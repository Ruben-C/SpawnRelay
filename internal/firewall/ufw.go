package firewall

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ufw manages rules through the ufw command line. Rules carry a comment so
// they can be recognised again; ufw prints it after "#" in "ufw status".
type ufw struct {
	run runner
}

func (u *ufw) Name() string { return ModeUFW }

// ufwStatus is what we learn from "ufw status".
type ufwStatus struct {
	active   bool
	tagged   map[string]string // "port/proto" -> id
	untagged map[string]bool   // "port/proto" allowed from anywhere by a rule that is not ours
}

// Lines look like:
//
//	25565/tcp                  ALLOW       Anywhere                   # spawnrelay:abc123
//	25565/tcp (v6)             ALLOW       Anywhere (v6)              # spawnrelay:abc123
//	25565                      ALLOW       Anywhere
var ufwLine = regexp.MustCompile(`^(\d+)(?:/(tcp|udp))?(?: \(v6\))?\s+ALLOW(?: IN)?\s+Anywhere(?: \(v6\))?\s*(?:#\s*(.*?))?\s*$`)

func parseUfwStatus(out string) ufwStatus {
	st := ufwStatus{tagged: map[string]string{}, untagged: map[string]bool{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "Status:") {
			st.active = strings.Contains(line, "active") && !strings.Contains(line, "inactive")
			continue
		}
		m := ufwLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		port, _ := strconv.Atoi(m[1])
		protos := []string{m[2]}
		if m[2] == "" {
			protos = []string{"tcp", "udp"}
		}
		id, ours := tagID(m[3])
		for _, proto := range protos {
			key := fmt.Sprintf("%d/%s", port, proto)
			if ours && m[2] != "" {
				st.tagged[key] = id
			} else {
				st.untagged[key] = true
			}
		}
	}
	return st
}

func (u *ufw) Sync(ctx context.Context, want []Rule) (*Result, error) {
	out, err := u.run(ctx, "ufw", "status")
	if err != nil {
		return nil, err
	}
	st := parseUfwStatus(out)
	res := newResult(u.Name())
	res.Active = st.active
	if !st.active {
		res.Note = "ufw is installed but inactive; rules are staged for when it is enabled"
	}

	wanted := map[string]Rule{}
	for _, w := range sortedRules(want) {
		key := w.Key()
		wanted[key] = w
		switch {
		case st.untagged[key]:
			res.set(w, StateExisting, nil)
		case st.tagged[key] == w.ID:
			res.set(w, StateOpen, nil)
		default:
			if old := st.tagged[key]; old != "" { // same port, different owner: retag
				_, _ = u.run(ctx, "ufw", "delete", "allow", key, "comment", Tag+old)
			}
			_, err := u.run(ctx, "ufw", "allow", key, "comment", Tag+w.ID)
			res.set(w, StateOpen, err)
		}
	}
	for key, id := range st.tagged {
		if _, keep := wanted[key]; keep {
			continue
		}
		if _, err := u.run(ctx, "ufw", "delete", "allow", key, "comment", Tag+id); err != nil {
			res.Note = strings.TrimSpace(res.Note + " " + fmt.Sprintf("could not remove %s: %v", key, err))
		}
	}
	return res, nil
}
