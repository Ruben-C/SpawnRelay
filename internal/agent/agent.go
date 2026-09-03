// Package agent is the root-only helper that runs next to the relay server.
// The server itself runs unprivileged, so everything that needs root goes
// through this agent over a unix socket: keeping host firewall rules in step
// with the configured forwards, and installing server updates.
//
// The protocol is one JSON request line per connection, answered by one JSON
// response line. The agent never accepts file contents, paths or URLs from
// the server: an update request carries only a release tag, and the agent
// downloads and verifies the release on its own.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/firewall"
)

// Operations.
const (
	OpSync   = "sync"   // reconcile firewall rules
	OpUpdate = "update" // install a release (asynchronous)
	OpStatus = "status" // agent version and last update record
)

// Request is what the server sends to the agent.
type Request struct {
	Op string `json:"op"`

	// sync
	Mode  string          `json:"mode,omitempty"` // auto | ufw | firewalld | nftables | iptables
	Rules []firewall.Rule `json:"rules,omitempty"`

	// update
	Version string `json:"version,omitempty"` // release tag, e.g. v1.2.3
}

// Response is the agent's answer.
type Response struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Version string `json:"version,omitempty"` // agent version

	// sync
	Backend string                        `json:"backend,omitempty"`
	Active  bool                          `json:"active"`
	Note    string                        `json:"note,omitempty"`
	Rules   map[string]firewall.RuleState `json:"rules,omitempty"`

	// update / status
	Update *UpdateRecord `json:"update,omitempty"`
	// CanUpdate reports whether this agent can install server updates.
	CanUpdate bool `json:"can_update"`
}

const (
	maxRequestBytes = 1 << 20
	maxRules        = 2000
)

// Config configures Serve.
type Config struct {
	Socket  string // unix socket path, e.g. /var/lib/spawnrelay/agent.sock
	DataDir string // server state directory: firewall ledger and update record live here
	Version string
	Logger  *slog.Logger
	// Updater installs server releases; nil disables the update operation.
	Updater *Updater

	factory func(ctx context.Context, mode string) (firewall.Backend, error) // tests
}

// Serve runs the agent until ctx is cancelled. It must run as root (or with
// the capabilities the chosen firewall tool needs).
func Serve(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Socket == "" {
		return errors.New("socket path is required")
	}
	if len(cfg.Socket) > 100 {
		return fmt.Errorf("socket path %q is too long for a unix socket (max ~100 bytes); pass a shorter --socket", cfg.Socket)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Dir(cfg.Socket)
	}
	if cfg.factory == nil {
		cfg.factory = func(ctx context.Context, mode string) (firewall.Backend, error) {
			return firewall.New(ctx, mode, cfg.DataDir)
		}
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0o700); err != nil {
		return err
	}
	_ = os.Remove(cfg.Socket)
	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Socket, err)
	}
	defer os.Remove(cfg.Socket)
	if err := restrictSocket(cfg.Socket, cfg.DataDir); err != nil {
		ln.Close()
		return err
	}
	a := &agent{cfg: cfg}
	if cfg.Updater != nil {
		cfg.Updater.init(cfg)
	}
	cfg.Logger.Info("agent listening", "socket", cfg.Socket, "updates", cfg.Updater != nil)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go a.handle(ctx, conn)
	}
}

// restrictSocket makes the socket usable only by root and the owner of the
// data directory (the spawnrelay service user).
func restrictSocket(path, dataDir string) error {
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	uid, gid, ok := ownerOf(dataDir)
	if !ok || os.Geteuid() != 0 {
		return nil
	}
	return os.Chown(path, uid, gid)
}

type agent struct {
	cfg Config
	mu  sync.Mutex // one sync at a time
}

func (a *agent) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	var req Request
	line, err := bufio.NewReaderSize(io.LimitReader(conn, maxRequestBytes), 64*1024).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		a.reply(conn, Response{Error: "read request: " + err.Error()})
		return
	}
	if err := json.Unmarshal(line, &req); err != nil {
		a.reply(conn, Response{Error: "invalid request: " + err.Error()})
		return
	}
	var resp Response
	switch req.Op {
	case OpSync:
		resp = a.sync(ctx, req)
	case OpStatus:
		resp = Response{OK: true}
		if a.cfg.Updater != nil {
			resp.Update = a.cfg.Updater.Last()
		}
	case OpUpdate:
		resp = a.update(ctx, req)
	default:
		resp = Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
	a.reply(conn, resp)
}

func (a *agent) reply(conn net.Conn, resp Response) {
	resp.Version = a.cfg.Version
	resp.CanUpdate = a.cfg.Updater != nil
	b, _ := json.Marshal(resp)
	_, _ = conn.Write(append(b, '\n'))
}

func (a *agent) update(ctx context.Context, req Request) Response {
	if a.cfg.Updater == nil {
		return Response{Error: "this agent cannot install updates"}
	}
	rec, err := a.cfg.Updater.Start(ctx, req.Version)
	if err != nil {
		return Response{Error: err.Error(), Update: a.cfg.Updater.Last()}
	}
	return Response{OK: true, Update: rec}
}

func (a *agent) sync(ctx context.Context, req Request) Response {
	if req.Mode == "" {
		req.Mode = firewall.ModeAuto
	}
	if !firewall.ValidMode(req.Mode) || req.Mode == firewall.ModeOff {
		return Response{Error: fmt.Sprintf("invalid mode %q", req.Mode)}
	}
	if len(req.Rules) > maxRules {
		return Response{Error: "too many rules"}
	}
	seen := map[string]bool{}
	for _, r := range req.Rules {
		if err := r.Validate(); err != nil {
			return Response{Error: err.Error()}
		}
		if seen[r.Key()] {
			return Response{Error: "duplicate rule " + r.Key()}
		}
		seen[r.Key()] = true
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	be, err := a.cfg.factory(ctx, req.Mode)
	if err != nil {
		return Response{Error: err.Error()}
	}
	res, err := be.Sync(ctx, req.Rules)
	if err != nil {
		a.cfg.Logger.Error("firewall sync failed", "backend", be.Name(), "error", err)
		return Response{Backend: be.Name(), Error: err.Error()}
	}
	opened, errs := 0, 0
	for _, st := range res.Rules {
		switch st.State {
		case firewall.StateOpen:
			opened++
		case firewall.StateError:
			errs++
		}
	}
	a.cfg.Logger.Info("firewall synced", "backend", res.Backend, "active", res.Active, "rules", len(req.Rules), "open", opened, "errors", errs, "note", res.Note)
	return Response{OK: true, Backend: res.Backend, Active: res.Active, Note: res.Note, Rules: res.Rules}
}

// ---- client side ---------------------------------------------------------

// Available reports whether an agent socket exists at path.
func Available(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// Call sends one request to the agent at socket and returns its response.
// A response with OK false is returned together with an error carrying its
// message, so callers can still read the fields it filled in.
func Call(ctx context.Context, socket string, req Request) (*Response, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Minute)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequestBytes)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("agent: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("agent: bad response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown error"
		}
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}

// Sync asks the agent to make the tagged firewall rules equal to rules.
func Sync(ctx context.Context, socket, mode string, rules []firewall.Rule) (*Response, error) {
	if rules == nil {
		rules = []firewall.Rule{}
	}
	return Call(ctx, socket, Request{Op: OpSync, Mode: mode, Rules: rules})
}

// Status asks the agent for its version and last update record.
func Status(ctx context.Context, socket string) (*Response, error) {
	return Call(ctx, socket, Request{Op: OpStatus})
}

// Update asks the agent to install release version. The agent answers as
// soon as it has accepted the request; progress is in the update record.
func Update(ctx context.Context, socket, version string) (*Response, error) {
	return Call(ctx, socket, Request{Op: OpUpdate, Version: version})
}
