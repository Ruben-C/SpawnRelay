package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// nftables inserts accept rules at the top of every base chain hooked on
// input, tagged with a rule comment. Accepting in a separate table would not
// help: a packet dropped by any input chain is dropped, so the rule has to
// live in the chain that would otherwise drop it.
type nftables struct {
	run runner
}

func (n *nftables) Name() string { return ModeNftables }

// ---- "nft -j list ruleset" parsing ---------------------------------------

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftRule struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Handle  int               `json:"handle"`
	Comment string            `json:"comment"`
	Expr    []json.RawMessage `json:"expr"`

	// derived
	proto  string
	port   int
	accept bool
	plain  bool // nothing but a dport match (and counters) before accept
}

type nftRuleset struct {
	chains []nftChain
	rules  []nftRule
}

func (rs *nftRuleset) inputChains() []nftChain {
	var out []nftChain
	for _, c := range rs.chains {
		if c.Hook == "input" && (c.Type == "filter" || c.Type == "") {
			out = append(out, c)
		}
	}
	return out
}

// allIptablesChains reports whether every input chain is one that iptables-nft
// created (table "filter", chain "INPUT", family ip/ip6). Those must be edited
// with iptables so that iptables keeps understanding the ruleset.
func allIptablesChains(chains []nftChain) bool {
	for _, c := range chains {
		if c.Name != "INPUT" || c.Table != "filter" || (c.Family != "ip" && c.Family != "ip6") {
			return false
		}
	}
	return len(chains) > 0
}

func parseNftRuleset(out string) (*nftRuleset, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("parse nft output: %w", err)
	}
	rs := &nftRuleset{}
	for _, item := range doc.Nftables {
		if raw, ok := item["chain"]; ok {
			var c nftChain
			if err := json.Unmarshal(raw, &c); err == nil {
				rs.chains = append(rs.chains, c)
			}
		}
		if raw, ok := item["rule"]; ok {
			var r nftRule
			if err := json.Unmarshal(raw, &r); err == nil {
				r.analyse()
				rs.rules = append(rs.rules, r)
			}
		}
	}
	return rs, nil
}

// analyse looks for "<proto> dport <port>" and "accept" in the expressions.
func (r *nftRule) analyse() {
	matches := 0
	other := 0
	for _, raw := range r.Expr {
		var e map[string]json.RawMessage
		if json.Unmarshal(raw, &e) != nil {
			other++
			continue
		}
		switch {
		case e["accept"] != nil:
			r.accept = true
		case e["counter"] != nil:
		case e["match"] != nil:
			matches++
			var m struct {
				Op   string `json:"op"`
				Left struct {
					Payload struct {
						Protocol string `json:"protocol"`
						Field    string `json:"field"`
					} `json:"payload"`
				} `json:"left"`
				Right json.RawMessage `json:"right"`
			}
			if json.Unmarshal(e["match"], &m) != nil {
				continue
			}
			var port int
			if (m.Op == "==" || m.Op == "") && m.Left.Payload.Field == "dport" &&
				(m.Left.Payload.Protocol == "tcp" || m.Left.Payload.Protocol == "udp") &&
				json.Unmarshal(m.Right, &port) == nil {
				r.proto = m.Left.Payload.Protocol
				r.port = port
			}
		default:
			other++
		}
	}
	r.plain = r.accept && r.port > 0 && matches == 1 && other == 0
}

func (r *nftRule) key() string { return fmt.Sprintf("%d/%s", r.port, r.proto) }

func (r *nftRule) chainRef() string { return r.Family + " " + r.Table + " " + r.Chain }

func (c nftChain) ref() string { return c.Family + " " + c.Table + " " + c.Name }

// ---- sync ----------------------------------------------------------------

func (n *nftables) Sync(ctx context.Context, want []Rule) (*Result, error) {
	out, err := n.run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	rs, err := parseNftRuleset(out)
	if err != nil {
		return nil, err
	}
	res := newResult(n.Name())
	chains := rs.inputChains()
	if len(chains) == 0 {
		res.Note = "nftables has no input chain; nothing is being filtered"
		for _, w := range want {
			res.set(w, StateOpen, nil)
		}
		return res, nil
	}
	res.Active = true

	// What is there now, per chain.
	type owned struct {
		rule nftRule
		id   string
	}
	tagged := map[string][]owned{}           // chain ref -> our rules
	existing := map[string]map[string]bool{} // chain ref -> "port/proto" allowed by an operator rule
	for _, r := range rs.rules {
		ref := r.chainRef()
		if id, ok := tagID(r.Comment); ok {
			tagged[ref] = append(tagged[ref], owned{rule: r, id: id})
		} else if r.plain {
			if existing[ref] == nil {
				existing[ref] = map[string]bool{}
			}
			existing[ref][r.key()] = true
		}
	}

	wanted := map[string]Rule{}
	for _, w := range want {
		wanted[w.Key()] = w
	}

	// Remove stale or mismatched tagged rules; remember the ones that stay.
	present := map[string]map[string]bool{} // chain ref -> "port/proto" with our rule in place
	for ref, list := range tagged {
		for _, o := range list {
			if w, keep := wanted[o.rule.key()]; keep && w.ID == o.id && o.rule.accept {
				if present[ref] == nil {
					present[ref] = map[string]bool{}
				}
				present[ref][o.rule.key()] = true
				continue
			}
			args := append([]string{"delete", "rule"}, strings.Fields(ref)...)
			args = append(args, "handle", portString(o.rule.Handle))
			if _, err := n.run(ctx, "nft", args...); err != nil {
				res.Note = strings.TrimSpace(res.Note + " " + err.Error())
			}
		}
	}

	for _, w := range sortedRules(want) {
		key := w.Key()
		state := StateOpen
		var firstErr error
		allExisting := true
		for _, c := range chains {
			ref := c.ref()
			if present[ref][key] {
				allExisting = false
				continue
			}
			if existing[ref][key] {
				continue
			}
			allExisting = false
			args := []string{"insert", "rule", c.Family, c.Table, c.Name, w.Proto, "dport", portString(w.Port), "accept", "comment", `"` + Tag + w.ID + `"`}
			if _, err := n.run(ctx, "nft", args...); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if allExisting {
			state = StateExisting
		}
		res.set(w, state, firstErr)
	}
	return res, nil
}
