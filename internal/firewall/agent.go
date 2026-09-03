package firewall

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
)

// Request is what the server sends to the agent: one line of JSON per
// connection. The only operation is a full sync of the wanted rule set.
type Request struct {
	Op    string `json:"op"`   // "sync"
	Mode  string `json:"mode"` // auto | ufw | firewalld | nftables | iptables
	Rules []Rule `json:"rules"`
}

// Response is the agent's answer.
type Response struct {
	OK      bool                 `json:"ok"`
	Error   string               `json:"error,omitempty"`
	Version string               `json:"version,omitempty"`
	Backend string               `json:"backend,omitempty"`
	Active  bool                 `json:"active"`
	Note    string               `json:"note,omitempty"`
	Rules   map[string]RuleState `json:"rules,omitempty"`
}

const (
	maxRequestBytes = 1 << 20
	maxRules        = 2000
)

// AgentConfig configures Serve.
type AgentConfig struct {
	Socket    string // unix socket path, e.g. /var/lib/spawnrelay/firewall.sock
	LedgerDir string // where backends without comments keep their ledger
	Version   string
	Logger    *slog.Logger

	factory func(ctx context.Context, mode string) (Backend, error) // tests
}

// Serve runs the agent until ctx is cancelled. It must run as root (or with
// the capabilities the chosen firewall tool needs).
func Serve(ctx context.Context, cfg AgentConfig) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Socket == "" {
		return errors.New("socket path is required")
	}
	if len(cfg.Socket) > 100 {
		return fmt.Errorf("socket path %q is too long for a unix socket (max ~100 bytes); pass a shorter --socket", cfg.Socket)
	}
	if cfg.LedgerDir == "" {
		cfg.LedgerDir = filepath.Dir(cfg.Socket)
	}
	if cfg.factory == nil {
		cfg.factory = func(ctx context.Context, mode string) (Backend, error) { return New(ctx, mode, cfg.LedgerDir) }
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
	if err := restrictSocket(cfg.Socket, cfg.LedgerDir); err != nil {
		ln.Close()
		return err
	}
	a := &agent{cfg: cfg}
	cfg.Logger.Info("firewall agent listening", "socket", cfg.Socket)

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
	cfg AgentConfig
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
	resp := a.sync(ctx, req)
	a.reply(conn, resp)
}

func (a *agent) reply(conn net.Conn, resp Response) {
	resp.Version = a.cfg.Version
	b, _ := json.Marshal(resp)
	_, _ = conn.Write(append(b, '\n'))
}

func (a *agent) sync(ctx context.Context, req Request) Response {
	if req.Op != "sync" {
		return Response{Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
	if req.Mode == "" {
		req.Mode = ModeAuto
	}
	if !ValidMode(req.Mode) || req.Mode == ModeOff {
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
		case StateOpen:
			opened++
		case StateError:
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

// Sync asks the agent at socket to make the tagged rules equal to rules.
func Sync(ctx context.Context, socket, mode string, rules []Rule) (*Response, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("firewall agent: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Minute)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if rules == nil {
		rules = []Rule{}
	}
	b, err := json.Marshal(Request{Op: "sync", Mode: mode, Rules: rules})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("firewall agent: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxRequestBytes)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("firewall agent: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("firewall agent: bad response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unknown error"
		}
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}
