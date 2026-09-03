package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/firewall"
	"github.com/Ruben-C/SpawnRelay/internal/store"
)

// Agent states reported in FirewallStatus.Agent.
const (
	agentOff          = "off"           // management disabled in settings
	agentNotInstalled = "not installed" // no agent socket in the data directory
	agentUnreachable  = "unreachable"   // socket exists but the agent did not answer
	agentConnected    = "connected"
)

// FirewallStatus is the server-wide view exposed by the API.
type FirewallStatus struct {
	Mode     string     `json:"mode"`
	Managed  bool       `json:"managed"` // rules are being applied by the agent
	Agent    string     `json:"agent"`
	Backend  string     `json:"backend,omitempty"`
	Active   bool       `json:"active"`
	Note     string     `json:"note,omitempty"`
	Error    string     `json:"error,omitempty"`
	LastSync *time.Time `json:"last_sync,omitempty"`
	Socket   string     `json:"socket"`
}

// Per-forward states in addition to the ones the firewall package reports.
const (
	fwUnmanaged = "unmanaged" // management off or agent unavailable
	fwClosed    = "closed"    // forward disabled; no rule wanted
	fwNone      = "none"      // no host firewall detected
)

// ForwardFirewall is the per-forward view.
type ForwardFirewall struct {
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// Rule ids for the relay's own ports.
const (
	ruleTunnel = "tunnel"
	ruleAdmin  = "admin"
)

// fwManager keeps the host firewall in step with the store through the
// firewall agent. Syncs are serialised; the last outcome is cached so API
// reads never block on the agent.
type fwManager struct {
	socket     string
	tunnelPort int
	adminPort  int
	store      *store.Store
	log        *slog.Logger

	syncMu sync.Mutex // one sync at a time
	kick   chan struct{}

	mu     sync.RWMutex
	status FirewallStatus
	rules  map[string]firewall.RuleState // key "port/proto" -> last state
	failed bool
}

func newFwManager(st *store.Store, socket string, tunnelPort, adminPort int, log *slog.Logger) *fwManager {
	return &fwManager{
		socket: socket, tunnelPort: tunnelPort, adminPort: adminPort, store: st, log: log,
		kick:   make(chan struct{}, 1),
		status: FirewallStatus{Mode: firewall.ModeAuto, Agent: agentNotInstalled, Socket: socket},
		rules:  map[string]firewall.RuleState{},
	}
}

// desired computes the rule set from the store plus the relay's own ports.
func (m *fwManager) desired() (mode string, rules []firewall.Rule) {
	rules = []firewall.Rule{
		{ID: ruleTunnel, Port: m.tunnelPort, Proto: "tcp"},
		{ID: ruleAdmin, Port: m.adminPort, Proto: "tcp"},
	}
	m.store.View(func(st *store.State) {
		mode = st.Settings.Firewall
		for _, f := range st.Forwards {
			if !f.Enabled {
				continue
			}
			if f.HasTCP() {
				rules = append(rules, firewall.Rule{ID: f.ID, Port: f.PublicPort, Proto: "tcp"})
			}
			if f.HasUDP() {
				rules = append(rules, firewall.Rule{ID: f.ID, Port: f.PublicPort, Proto: "udp"})
			}
		}
	})
	if mode == "" {
		mode = firewall.ModeAuto
	}
	return mode, rules
}

// Sync talks to the agent once and records the outcome. It never returns an
// error: a failing firewall must not block forward management, it is
// surfaced through Status and ForwardState instead.
func (m *fwManager) Sync(ctx context.Context) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	mode, rules := m.desired()
	st := FirewallStatus{Mode: mode, Socket: m.socket}
	states := map[string]firewall.RuleState{}
	failed := false

	switch {
	case mode == firewall.ModeOff:
		st.Agent = agentOff
	case !firewall.Available(m.socket):
		st.Agent = agentNotInstalled
	default:
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		resp, err := firewall.Sync(ctx, m.socket, mode, rules)
		cancel()
		now := time.Now()
		st.LastSync = &now
		if resp != nil {
			st.Backend = resp.Backend
		}
		if err != nil {
			failed = true
			st.Agent = agentUnreachable
			if resp != nil && resp.Backend != "" {
				st.Agent = agentConnected // it answered, the backend failed
			}
			st.Error = err.Error()
			m.log.Warn("firewall sync failed", "error", err)
			for _, r := range rules {
				states[r.Key()] = firewall.RuleState{State: firewall.StateError, Error: err.Error()}
			}
		} else {
			st.Agent = agentConnected
			st.Managed = true
			st.Active = resp.Active
			st.Note = resp.Note
			for k, v := range resp.Rules {
				states[k] = v
				if v.State == firewall.StateError {
					failed = true
				}
			}
			if resp.Backend == "none" {
				st.Managed = false
			}
		}
	}

	m.mu.Lock()
	m.status = st
	m.rules = states
	m.failed = failed
	m.mu.Unlock()
}

// Kick schedules a background sync.
func (m *fwManager) Kick() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Run re-syncs periodically, sooner after failures, until ctx is done.
func (m *fwManager) Run(ctx context.Context) {
	const (
		normal = 5 * time.Minute
		retry  = 20 * time.Second
	)
	timer := time.NewTimer(normal)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
		case <-timer.C:
		}
		m.Sync(ctx)
		m.mu.RLock()
		failed := m.failed
		agent := m.status.Agent
		m.mu.RUnlock()
		next := normal
		if failed || agent == agentNotInstalled {
			next = retry
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(next)
	}
}

// Status returns the last known server-wide state.
func (m *fwManager) Status() FirewallStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// ForwardState derives the per-forward state from the last sync.
func (m *fwManager) ForwardState(f *store.Forward) ForwardFirewall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	switch {
	case m.status.Agent == agentOff || m.status.Agent == agentNotInstalled:
		return ForwardFirewall{State: fwUnmanaged}
	case m.status.Agent == agentUnreachable:
		return ForwardFirewall{State: firewall.StateError, Error: m.status.Error}
	case m.status.Backend == "none":
		return ForwardFirewall{State: fwNone}
	case !f.Enabled:
		return ForwardFirewall{State: fwClosed}
	}
	out := ForwardFirewall{State: firewall.StateOpen}
	check := func(proto string) {
		rs, ok := m.rules[firewall.Rule{Port: f.PublicPort, Proto: proto}.Key()]
		switch {
		case !ok:
			// not synced yet (e.g. created a moment ago); report the global error if any
			if m.status.Error != "" {
				out = ForwardFirewall{State: firewall.StateError, Error: m.status.Error}
			}
		case rs.State == firewall.StateError:
			out = ForwardFirewall{State: firewall.StateError, Error: rs.Error}
		case rs.State == firewall.StateExisting && out.State == firewall.StateOpen:
			out.State = firewall.StateExisting
		}
	}
	if f.HasTCP() {
		check("tcp")
	}
	if f.HasUDP() && out.State != firewall.StateError {
		check("udp")
	}
	return out
}
