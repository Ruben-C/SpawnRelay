// Package firewall keeps the relay host's firewall in step with the forwards
// configured in SpawnRelay.
//
// The relay server runs unprivileged and must not be able to rewrite the host
// firewall, so the work is split in two: a small root-only agent
// (spawnrelay agent, see internal/agent) listens on a unix socket in the data directory
// and accepts exactly one kind of request, "make the set of ports SpawnRelay
// has opened equal to this list". The server (see the Client in this package)
// sends that list whenever a forward changes and periodically thereafter.
//
// Every rule the agent creates is tagged "spawnrelay:<id>" (a rule comment
// where the backend supports one, a private ledger otherwise). The agent only
// ever adds or removes tagged rules; rules the operator created by hand,
// including one that happens to allow the same port, are left untouched.
package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tag prefixes every rule the agent owns.
const Tag = "spawnrelay:"

// Mode values accepted in the server settings and in requests to the agent.
const (
	ModeOff       = "off"
	ModeAuto      = "auto"
	ModeUFW       = "ufw"
	ModeFirewalld = "firewalld"
	ModeNftables  = "nftables"
	ModeIptables  = "iptables"
)

// Modes lists every valid mode, in display order.
var Modes = []string{ModeAuto, ModeOff, ModeUFW, ModeFirewalld, ModeNftables, ModeIptables}

// ValidMode reports whether m is a known mode.
func ValidMode(m string) bool {
	for _, x := range Modes {
		if x == m {
			return true
		}
	}
	return false
}

// Rule is one port the agent should keep open.
type Rule struct {
	ID    string `json:"id"`    // owner tag, e.g. the forward id
	Port  int    `json:"port"`  // 1-65535
	Proto string `json:"proto"` // tcp | udp
}

// Key returns the "port/proto" string that identifies a rule in results.
func (r Rule) Key() string { return fmt.Sprintf("%d/%s", r.Port, r.Proto) }

var idPattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// Validate checks that a rule is well formed.
func (r Rule) Validate() error {
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("invalid rule id %q", r.ID)
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("invalid port %d", r.Port)
	}
	if r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("invalid protocol %q", r.Proto)
	}
	return nil
}

// Rule states reported for every requested rule.
const (
	StateOpen     = "open"     // a tagged rule is in place
	StateExisting = "existing" // the operator already allows this port; nothing was added
	StateError    = "error"    // the backend refused; see Error
)

// RuleState is the outcome for one requested rule.
type RuleState struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// Result is what a backend reports after a sync.
type Result struct {
	Backend string               `json:"backend"`
	Active  bool                 `json:"active"`         // the firewall is actually filtering traffic
	Note    string               `json:"note,omitempty"` // human readable detail, e.g. "ufw is inactive"
	Rules   map[string]RuleState `json:"rules"`          // keyed by Rule.Key()
}

func newResult(name string) *Result {
	return &Result{Backend: name, Rules: map[string]RuleState{}}
}

func (r *Result) set(rule Rule, state string, err error) {
	rs := RuleState{State: state}
	if err != nil {
		rs.State = StateError
		rs.Error = err.Error()
	}
	r.Rules[rule.Key()] = rs
}

// Backend manipulates one kind of firewall.
type Backend interface {
	Name() string
	// Sync adds tagged rules for every entry of want that is missing and
	// removes tagged rules that are no longer wanted. It returns a state for
	// every wanted rule; a non-nil error means the backend could not even
	// inspect the firewall.
	Sync(ctx context.Context, want []Rule) (*Result, error)
}

// ---- command execution ---------------------------------------------------

// runner executes an external command and returns its stdout. Tests
// substitute a fake.
type runner func(ctx context.Context, name string, args ...string) (string, error)

// exitError is returned by run when the command ran but failed.
type exitError struct {
	code   int
	stderr string
	cmd    string
}

func (e *exitError) Error() string {
	msg := strings.TrimSpace(e.stderr)
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", e.code)
	}
	return fmt.Sprintf("%s: %s", e.cmd, msg)
}

var extraPath = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// lookPath finds a binary in PATH or in the usual system directories, which
// matters when the agent runs from a minimal systemd environment.
func lookPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range extraPath {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found", name)
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	path, err := lookPath(name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.Stdin = nil
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out.String(), &exitError{code: ee.ExitCode(), stderr: stderr.String() + out.String(), cmd: name + " " + strings.Join(args, " ")}
		}
		return out.String(), fmt.Errorf("%s: %w", name, err)
	}
	return out.String(), nil
}

// ---- helpers shared by backends -----------------------------------------

func hasBinary(name string) bool {
	_, err := lookPath(name)
	return err == nil
}

// tagID extracts the id from a "spawnrelay:<id>" comment; ok is false for
// comments that are not ours.
func tagID(comment string) (id string, ok bool) {
	comment = strings.TrimSpace(comment)
	if !strings.HasPrefix(comment, Tag) {
		return "", false
	}
	id = strings.TrimPrefix(comment, Tag)
	return id, idPattern.MatchString(id)
}

// sortedRules returns a copy sorted by port then protocol for stable output.
func sortedRules(rules []Rule) []Rule {
	out := append([]Rule(nil), rules...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func portString(p int) string { return strconv.Itoa(p) }

// ---- detection -----------------------------------------------------------

// New returns the backend for mode, detecting the installed firewall when
// mode is "auto". ledgerDir is where backends without rule comments keep
// track of what they created.
func New(ctx context.Context, mode, ledgerDir string) (Backend, error) {
	return newWith(ctx, mode, ledgerDir, run)
}

func newWith(ctx context.Context, mode, ledgerDir string, r runner) (Backend, error) {
	switch mode {
	case ModeUFW:
		return &ufw{run: r}, nil
	case ModeFirewalld:
		return &firewalld{run: r, ledger: filepath.Join(ledgerDir, "firewall-ledger.json")}, nil
	case ModeNftables:
		return &nftables{run: r}, nil
	case ModeIptables:
		return &iptables{run: r}, nil
	case ModeAuto, "":
		return detect(ctx, ledgerDir, r), nil
	case ModeOff:
		return nil, errors.New("firewall management is off")
	}
	return nil, fmt.Errorf("unknown firewall mode %q", mode)
}

// detect picks the backend that is actually filtering traffic on this host.
// Order matters: ufw and firewalld are front ends over nftables/iptables, so
// they must win over the raw tools, and iptables-nft tables must be managed
// with iptables rather than nft so that iptables keeps understanding them.
func detect(ctx context.Context, ledgerDir string, r runner) Backend {
	if hasBinary("firewall-cmd") {
		if _, err := r(ctx, "firewall-cmd", "--state"); err == nil {
			return &firewalld{run: r, ledger: filepath.Join(ledgerDir, "firewall-ledger.json")}
		}
	}
	if hasBinary("ufw") {
		if out, err := r(ctx, "ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
			return &ufw{run: r}
		}
	}
	if hasBinary("nft") {
		if out, err := r(ctx, "nft", "-j", "list", "ruleset"); err == nil {
			if rs, err := parseNftRuleset(out); err == nil {
				chains := rs.inputChains()
				if len(chains) > 0 {
					if allIptablesChains(chains) && hasBinary("iptables") {
						return &iptables{run: r}
					}
					return &nftables{run: r}
				}
			}
		}
	}
	if hasBinary("iptables") {
		if out, err := r(ctx, "iptables", "-S", "INPUT"); err == nil {
			if st := parseIptables(out); st.filtering() {
				return &iptables{run: r}
			}
		}
	}
	return &none{}
}

// none is the backend used when no firewall is installed or active.
type none struct{}

func (none) Name() string { return "none" }

func (none) Sync(ctx context.Context, want []Rule) (*Result, error) {
	res := newResult("none")
	res.Note = "no active host firewall detected"
	for _, w := range want {
		res.set(w, StateOpen, nil)
	}
	return res, nil
}
