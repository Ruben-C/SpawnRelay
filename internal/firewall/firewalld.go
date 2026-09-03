package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// firewalld manages ports in the default zone with firewall-cmd. firewalld
// has no place to attach a comment to a port, so the agent keeps a ledger
// file listing the ports it opened; ports that are open but not in the
// ledger belong to the operator and are never removed.
type firewalld struct {
	run    runner
	ledger string // path of the ledger file
}

func (f *firewalld) Name() string { return ModeFirewalld }

type ledgerFile struct {
	Firewalld map[string]string `json:"firewalld"` // "port/proto" -> id
}

func (f *firewalld) loadLedger() (ledgerFile, error) {
	var l ledgerFile
	b, err := os.ReadFile(f.ledger)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			l.Firewalld = map[string]string{}
			return l, nil
		}
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, fmt.Errorf("parse %s: %w", f.ledger, err)
	}
	if l.Firewalld == nil {
		l.Firewalld = map[string]string{}
	}
	return l, nil
}

func (f *firewalld) saveLedger(l ledgerFile) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.ledger + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.ledger)
}

func parseFirewalldPorts(out string) map[string]bool {
	open := map[string]bool{}
	for _, field := range strings.Fields(out) {
		open[field] = true
	}
	return open
}

// port applies add or remove to both the runtime and the permanent config.
func (f *firewalld) port(ctx context.Context, op, key string) error {
	if _, err := f.run(ctx, "firewall-cmd", "--"+op+"-port="+key); err != nil {
		return err
	}
	_, err := f.run(ctx, "firewall-cmd", "--permanent", "--"+op+"-port="+key)
	return err
}

func (f *firewalld) Sync(ctx context.Context, want []Rule) (*Result, error) {
	if _, err := f.run(ctx, "firewall-cmd", "--state"); err != nil {
		return nil, fmt.Errorf("firewalld is not running: %w", err)
	}
	out, err := f.run(ctx, "firewall-cmd", "--list-ports")
	if err != nil {
		return nil, err
	}
	open := parseFirewalldPorts(out)
	ledger, err := f.loadLedger()
	if err != nil {
		return nil, err
	}
	res := newResult(f.Name())
	res.Active = true

	wanted := map[string]bool{}
	for _, w := range sortedRules(want) {
		key := w.Key()
		wanted[key] = true
		_, ours := ledger.Firewalld[key]
		switch {
		case open[key] && !ours:
			res.set(w, StateExisting, nil)
		case open[key] && ours:
			ledger.Firewalld[key] = w.ID
			res.set(w, StateOpen, nil)
		default:
			err := f.port(ctx, "add", key)
			if err == nil {
				ledger.Firewalld[key] = w.ID
			}
			res.set(w, StateOpen, err)
		}
	}
	for key := range ledger.Firewalld {
		if wanted[key] {
			continue
		}
		if err := f.port(ctx, "remove", key); err != nil {
			res.Note = strings.TrimSpace(res.Note + " " + fmt.Sprintf("could not remove %s: %v", key, err))
			continue
		}
		delete(ledger.Firewalld, key)
	}
	if err := f.saveLedger(ledger); err != nil {
		return res, fmt.Errorf("save ledger: %w", err)
	}
	return res, nil
}
