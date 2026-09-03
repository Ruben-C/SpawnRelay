package firewall

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// iptables inserts tagged ACCEPT rules at the top of the INPUT chain with
// iptables and, when present, ip6tables. Rules are recognised by their
// "-m comment" match.
type iptables struct {
	run   runner
	tools []string // iptables and, when installed, ip6tables; nil = detect
}

func (i *iptables) Name() string { return ModeIptables }

type iptablesState struct {
	policy   string
	rules    int
	tagged   map[string]string // "port/proto" -> id
	untagged map[string]bool
}

func (s iptablesState) filtering() bool {
	return s.policy == "DROP" || s.policy == "REJECT" || s.rules > 0
}

var (
	iptPolicy   = regexp.MustCompile(`^-P INPUT (\S+)`)
	iptTagged   = regexp.MustCompile(`^-A INPUT -p (tcp|udp) (?:-m (?:tcp|udp) )?--dport (\d+) -m comment --comment "?(` + Tag + `[a-z0-9_-]+)"? -j ACCEPT$`)
	iptUntagged = regexp.MustCompile(`^-A INPUT -p (tcp|udp) (?:-m (?:tcp|udp) )?--dport (\d+) -j ACCEPT$`)
)

func parseIptables(out string) iptablesState {
	st := iptablesState{tagged: map[string]string{}, untagged: map[string]bool{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if m := iptPolicy.FindStringSubmatch(line); m != nil {
			st.policy = m[1]
			continue
		}
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		st.rules++
		if m := iptTagged.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[2])
			if id, ok := tagID(m[3]); ok {
				st.tagged[fmt.Sprintf("%d/%s", port, m[1])] = id
			}
			continue
		}
		if m := iptUntagged.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[2])
			st.untagged[fmt.Sprintf("%d/%s", port, m[1])] = true
		}
	}
	return st
}

func ruleArgs(op string, r Rule, id string) []string {
	return []string{op, "INPUT", "-p", r.Proto, "--dport", portString(r.Port), "-m", "comment", "--comment", Tag + id, "-j", "ACCEPT"}
}

func (i *iptables) Sync(ctx context.Context, want []Rule) (*Result, error) {
	tools := i.tools
	if tools == nil {
		tools = []string{"iptables"}
		if hasBinary("ip6tables") {
			tools = append(tools, "ip6tables")
		}
	}
	res := newResult(i.Name())
	wanted := map[string]Rule{}
	for _, w := range want {
		wanted[w.Key()] = w
		res.set(w, StateExisting, nil) // downgraded below when we add something
	}
	for _, tool := range tools {
		out, err := i.run(ctx, tool, "-S", "INPUT")
		if err != nil {
			if tool == "iptables" {
				return nil, err
			}
			res.Note = strings.TrimSpace(res.Note + " " + err.Error())
			continue
		}
		st := parseIptables(out)
		if st.filtering() {
			res.Active = true
		}
		for key, id := range st.tagged {
			if w, keep := wanted[key]; keep && w.ID == id {
				continue
			}
			port, proto, _ := strings.Cut(key, "/")
			p, _ := strconv.Atoi(port)
			if _, err := i.run(ctx, tool, ruleArgs("-D", Rule{Port: p, Proto: proto}, id)...); err != nil {
				res.Note = strings.TrimSpace(res.Note + " " + err.Error())
			}
		}
		for _, w := range sortedRules(want) {
			key := w.Key()
			cur := res.Rules[key]
			switch {
			case st.tagged[key] == w.ID:
				if cur.State == StateExisting {
					res.set(w, StateOpen, nil)
				}
			case st.untagged[key]:
				// leave the operator's rule alone
			default:
				if _, err := i.run(ctx, tool, ruleArgs("-I", w, w.ID)...); err != nil {
					res.set(w, StateError, err)
				} else if cur.State != StateError {
					res.set(w, StateOpen, nil)
				}
			}
		}
	}
	return res, nil
}
