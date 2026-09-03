package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/protocol"
	"github.com/Ruben-C/SpawnRelay/internal/relay"
	"github.com/Ruben-C/SpawnRelay/internal/store"
	"github.com/hashicorp/yamux"
)

// Tunnel accepts client connections on the tunnel port, keeps track of live
// client sessions, and runs the public TCP/UDP listeners for every forward.
type Tunnel struct {
	store   *store.Store
	log     *slog.Logger
	version string
	tlsCfg  *tls.Config
	udpIdle time.Duration

	mu       sync.Mutex
	sessions map[string]*Session       // by client id
	runners  map[string]*forwardRunner // by forward id
	updates  map[string]*ClientUpdate  // by client id; see update.go

	// binary resolves a client binary asset name to a file path (set by Server).
	binary func(name string) (string, error)
	// autoUpdate reports whether clients should be updated on connect.
	autoUpdate func() bool
	binaries   binaryCache
}

// Session is a connected client.
type Session struct {
	ClientID    string
	Remote      string
	ConnectedAt time.Time
	Hello       protocol.Hello

	sess   *yamux.Session
	ctrl   *yamux.Stream
	ctrlMu sync.Mutex
}

// ClientStatus is the live view of a client.
type ClientStatus struct {
	Online      bool       `json:"online"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	RemoteAddr  string     `json:"remote_addr,omitempty"`
}

// ForwardStats are live counters for a forward.
type ForwardStats struct {
	Listening        bool   `json:"listening"`
	ActiveTCP        int64  `json:"active_tcp"`
	ActiveUDP        int64  `json:"active_udp"`
	TotalConnections int64  `json:"total_connections"`
	BytesIn          int64  `json:"bytes_in"`  // from the public side into the tunnel
	BytesOut         int64  `json:"bytes_out"` // from the tunnel back to the public side
	Error            string `json:"error,omitempty"`
}

// NewTunnel creates a tunnel manager.
func NewTunnel(st *store.Store, tlsCfg *tls.Config, version string, log *slog.Logger) *Tunnel {
	return &Tunnel{
		store: st, log: log, version: version, tlsCfg: tlsCfg, udpIdle: 90 * time.Second,
		sessions: map[string]*Session{}, runners: map[string]*forwardRunner{}, updates: map[string]*ClientUpdate{},
	}
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	c.StreamOpenTimeout = 10 * time.Second
	return c
}

// Serve accepts tunnel connections until ctx is done or ln fails.
func (t *Tunnel) Serve(ctx context.Context, ln net.Listener) error {
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
		go t.handleConn(conn)
	}
}

// Shutdown closes all sessions and listeners.
func (t *Tunnel) Shutdown() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, s := range t.sessions {
		s.sendControl(protocol.ControlMessage{Type: "shutdown", Message: "server shutting down"})
		s.sess.Close()
		delete(t.sessions, id)
	}
	for id, r := range t.runners {
		r.stop()
		delete(t.runners, id)
	}
}

func (t *Tunnel) handleConn(raw net.Conn) {
	remote := raw.RemoteAddr().String()
	tlsConn := tls.Server(raw, t.tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.log.Debug("tunnel tls handshake failed", "remote", remote, "error", err)
		tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	sess, err := yamux.Server(tlsConn, yamuxConfig())
	if err != nil {
		tlsConn.Close()
		return
	}

	// Wait for the control stream with a timeout.
	type acceptResult struct {
		s   *yamux.Stream
		err error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		s, err := sess.AcceptStream()
		ch <- acceptResult{s, err}
	}()
	var ctrl *yamux.Stream
	select {
	case r := <-ch:
		if r.err != nil {
			sess.Close()
			return
		}
		ctrl = r.s
	case <-time.After(15 * time.Second):
		t.log.Debug("tunnel client never opened control stream", "remote", remote)
		sess.Close()
		return
	}

	_ = ctrl.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := protocol.NewReader(ctrl)
	var hello protocol.Hello
	if err := protocol.ReadJSONLine(br, &hello); err != nil {
		t.log.Debug("bad hello", "remote", remote, "error", err)
		sess.Close()
		return
	}
	_ = ctrl.SetReadDeadline(time.Time{})

	reject := func(msg string) {
		t.log.Warn("tunnel client rejected", "remote", remote, "reason", msg)
		_ = protocol.WriteJSONLine(ctrl, protocol.HelloResponse{OK: false, Error: msg})
		time.Sleep(100 * time.Millisecond)
		sess.Close()
	}
	if hello.Version != protocol.Version {
		reject(fmt.Sprintf("unsupported protocol version %d (server speaks %d)", hello.Version, protocol.Version))
		return
	}
	var clientID, clientName string
	now := time.Now()
	err = t.store.Update(func(st *store.State) error {
		c := st.ClientByToken(hello.Token)
		if c == nil {
			return store.ErrNotFound
		}
		clientID, clientName = c.ID, c.Name
		c.LastSeenAt = &now
		c.LastAddr = remote
		c.Hostname = hello.Hostname
		c.OS = hello.OS
		c.Arch = hello.Arch
		c.ClientVersion = hello.ClientVersion
		return nil
	})
	if err != nil {
		reject("invalid token")
		return
	}

	s := &Session{ClientID: clientID, Remote: remote, ConnectedAt: now, Hello: hello, sess: sess, ctrl: ctrl}
	t.mu.Lock()
	if old := t.sessions[clientID]; old != nil {
		t.log.Info("replacing existing session for client", "client", clientName, "old_remote", old.Remote)
		old.sendControl(protocol.ControlMessage{Type: "shutdown", Message: "replaced by a new connection"})
		old.sess.Close()
	}
	t.sessions[clientID] = s
	t.mu.Unlock()

	if err := protocol.WriteJSONLine(ctrl, protocol.HelloResponse{OK: true, ClientID: clientID, ClientName: clientName, ServerVersion: t.version}); err != nil {
		t.dropSession(s)
		return
	}
	t.log.Info("client connected", "client", clientName, "client_id", clientID, "remote", remote, "hostname", hello.Hostname, "os", hello.OS+"/"+hello.Arch, "version", hello.ClientVersion)
	t.NotifyForwards(clientID)

	t.noteReconnect(s)

	// Streams the client opens towards us (binary downloads for self-update).
	go func() {
		for {
			st, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go t.handleClientStream(s, st)
		}
	}()

	// Messages from the client (update progress). Old clients never write, so
	// this simply blocks until the stream or session goes away.
	for {
		var msg protocol.ControlMessage
		if err := protocol.ReadJSONLine(br, &msg); err != nil {
			break
		}
		t.handleClientMessage(s, msg)
	}
	t.dropSession(s)
	t.log.Info("client disconnected", "client", clientName, "client_id", clientID, "remote", remote)
}

func (t *Tunnel) dropSession(s *Session) {
	t.mu.Lock()
	if t.sessions[s.ClientID] == s {
		delete(t.sessions, s.ClientID)
	}
	t.mu.Unlock()
	s.sess.Close()
	seen := time.Now()
	_ = t.store.Update(func(st *store.State) error {
		if c := st.ClientByID(s.ClientID); c != nil {
			c.LastSeenAt = &seen
		}
		return nil
	})
}

func (s *Session) sendControl(msg protocol.ControlMessage) {
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	_ = s.ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = protocol.WriteJSONLine(s.ctrl, msg)
	_ = s.ctrl.SetWriteDeadline(time.Time{})
}

func (t *Tunnel) session(clientID string) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[clientID]
}

// ClientStatus returns the live status of a client.
func (t *Tunnel) ClientStatus(clientID string) ClientStatus {
	s := t.session(clientID)
	if s == nil {
		return ClientStatus{}
	}
	at := s.ConnectedAt
	return ClientStatus{Online: true, ConnectedAt: &at, RemoteAddr: s.Remote}
}

// DisconnectClient closes a client's session (e.g. after deletion or token rotation).
func (t *Tunnel) DisconnectClient(clientID, reason string) {
	t.mu.Lock()
	s := t.sessions[clientID]
	delete(t.sessions, clientID)
	t.mu.Unlock()
	if s != nil {
		s.sendControl(protocol.ControlMessage{Type: "shutdown", Message: reason})
		s.sess.Close()
	}
}

// NotifyForwards pushes the current forward list to a connected client.
func (t *Tunnel) NotifyForwards(clientID string) {
	s := t.session(clientID)
	if s == nil {
		return
	}
	var infos []protocol.ForwardInfo
	t.store.View(func(st *store.State) {
		for _, f := range st.ForwardsForClient(clientID) {
			if f.Enabled {
				infos = append(infos, protocol.ForwardInfo{Name: f.Name, Protocol: f.Protocol, PublicPort: f.PublicPort, Target: f.Target()})
			}
		}
	})
	go s.sendControl(protocol.ControlMessage{Type: "forwards", Forwards: infos})
}

// ---- forward listeners ---------------------------------------------------

// Apply (re)starts the listeners for f, returning a bind error if the public
// port cannot be opened. On failure any previous listener for f is restored.
func (t *Tunnel) Apply(f *store.Forward) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.runners[f.ID]
	if old != nil && old.f.Same(f) {
		return nil
	}
	if old != nil {
		old.stop()
		delete(t.runners, f.ID)
	}
	if !f.Enabled {
		return nil
	}
	r := newRunner(t, *f)
	if err := r.start(); err != nil {
		if old != nil {
			restored := newRunner(t, old.f)
			if rerr := restored.start(); rerr == nil {
				t.runners[f.ID] = restored
			} else {
				t.log.Error("could not restore previous listener", "forward", old.f.Name, "error", rerr)
			}
		}
		return err
	}
	t.runners[f.ID] = r
	return nil
}

// Remove stops the listeners for a forward id.
func (t *Tunnel) Remove(forwardID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if r := t.runners[forwardID]; r != nil {
		r.stop()
		delete(t.runners, forwardID)
	}
}

// SyncAll reconciles listeners with the store; returns per-forward errors.
func (t *Tunnel) SyncAll() map[string]error {
	errs := map[string]error{}
	var forwards []store.Forward
	t.store.View(func(st *store.State) {
		for _, f := range st.Forwards {
			forwards = append(forwards, *f)
		}
	})
	live := map[string]bool{}
	for i := range forwards {
		f := &forwards[i]
		live[f.ID] = true
		if err := t.Apply(f); err != nil {
			errs[f.ID] = err
			t.log.Error("cannot start forward", "forward", f.Name, "port", f.PublicPort, "error", err)
		}
	}
	t.mu.Lock()
	for id, r := range t.runners {
		if !live[id] {
			r.stop()
			delete(t.runners, id)
		}
	}
	t.mu.Unlock()
	return errs
}

// ForwardStats returns live counters for a forward.
func (t *Tunnel) ForwardStats(forwardID string) ForwardStats {
	t.mu.Lock()
	r := t.runners[forwardID]
	t.mu.Unlock()
	if r == nil {
		return ForwardStats{}
	}
	r.udpMu.Lock()
	activeUDP := int64(len(r.peers))
	r.udpMu.Unlock()
	return ForwardStats{
		Listening:        true,
		ActiveTCP:        r.activeTCP.Load(),
		ActiveUDP:        activeUDP,
		TotalConnections: r.totalConns.Load(),
		BytesIn:          r.bytesIn.Load(),
		BytesOut:         r.bytesOut.Load(),
	}
}

type forwardRunner struct {
	t *Tunnel
	f store.Forward

	tcpLn net.Listener
	udpPC net.PacketConn
	done  chan struct{}

	activeTCP, totalConns, bytesIn, bytesOut atomic.Int64

	udpMu sync.Mutex
	peers map[string]*udpPeer
}

type udpPeer struct {
	addr   net.Addr
	stream *yamux.Stream
	last   atomic.Int64 // unix nanos
	wmu    sync.Mutex
}

func newRunner(t *Tunnel, f store.Forward) *forwardRunner {
	return &forwardRunner{t: t, f: f, done: make(chan struct{}), peers: map[string]*udpPeer{}}
}

func (r *forwardRunner) start() error {
	addr := fmt.Sprintf(":%d", r.f.PublicPort)
	if r.f.HasTCP() {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("tcp port %d: %w", r.f.PublicPort, unwrapBind(err))
		}
		r.tcpLn = ln
	}
	if r.f.HasUDP() {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			if r.tcpLn != nil {
				r.tcpLn.Close()
			}
			return fmt.Errorf("udp port %d: %w", r.f.PublicPort, unwrapBind(err))
		}
		r.udpPC = pc
	}
	if r.tcpLn != nil {
		go r.acceptLoop()
	}
	if r.udpPC != nil {
		go r.udpLoop()
		go r.udpReaper()
	}
	r.t.log.Info("forward listening", "forward", r.f.Name, "protocol", r.f.Protocol, "public_port", r.f.PublicPort, "target", r.f.Target())
	return nil
}

func unwrapBind(err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err
	}
	return err
}

func (r *forwardRunner) stop() {
	close(r.done)
	if r.tcpLn != nil {
		r.tcpLn.Close()
	}
	if r.udpPC != nil {
		r.udpPC.Close()
	}
	r.udpMu.Lock()
	for k, p := range r.peers {
		p.stream.Close()
		delete(r.peers, k)
	}
	r.udpMu.Unlock()
	r.t.log.Info("forward stopped", "forward", r.f.Name, "public_port", r.f.PublicPort)
}

func (r *forwardRunner) openStream(kind, remote string) (*yamux.Stream, error) {
	s := r.t.session(r.f.ClientID)
	if s == nil {
		return nil, errors.New("client offline")
	}
	stream, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err = protocol.WriteJSONLine(stream, protocol.StreamHeader{Type: kind, ForwardID: r.f.ID, Target: r.f.Target(), Remote: remote})
	_ = stream.SetWriteDeadline(time.Time{})
	if err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (r *forwardRunner) acceptLoop() {
	for {
		conn, err := r.tcpLn.Accept()
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		go r.handleTCP(conn)
	}
}

func (r *forwardRunner) handleTCP(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	stream, err := r.openStream("tcp", remote)
	if err != nil {
		r.t.log.Debug("dropping tcp connection", "forward", r.f.Name, "remote", remote, "error", err)
		conn.Close()
		return
	}
	r.activeTCP.Add(1)
	r.totalConns.Add(1)
	defer r.activeTCP.Add(-1)
	relay.PipeCounted(conn, stream, &r.bytesIn, &r.bytesOut)
}

func (r *forwardRunner) udpLoop() {
	buf := make([]byte, protocol.MaxDatagram)
	for {
		n, addr, err := r.udpPC.ReadFrom(buf)
		if err != nil {
			select {
			case <-r.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		p := r.peer(addr)
		if p == nil {
			continue // client offline: drop
		}
		p.wmu.Lock()
		err = protocol.WriteFrame(p.stream, buf[:n])
		p.wmu.Unlock()
		if err != nil {
			r.removePeer(addr.String(), p)
			continue
		}
		r.bytesIn.Add(int64(n))
	}
}

func (r *forwardRunner) peer(addr net.Addr) *udpPeer {
	key := addr.String()
	r.udpMu.Lock()
	defer r.udpMu.Unlock()
	if p := r.peers[key]; p != nil {
		p.last.Store(time.Now().UnixNano())
		return p
	}
	stream, err := r.openStream("udp", key)
	if err != nil {
		return nil
	}
	p := &udpPeer{addr: addr, stream: stream}
	p.last.Store(time.Now().UnixNano())
	r.peers[key] = p
	r.totalConns.Add(1)
	go r.peerReadLoop(key, p)
	return p
}

func (r *forwardRunner) removePeer(key string, p *udpPeer) {
	r.udpMu.Lock()
	if r.peers[key] == p {
		delete(r.peers, key)
	}
	r.udpMu.Unlock()
	p.stream.Close()
}

func (r *forwardRunner) peerReadLoop(key string, p *udpPeer) {
	defer r.removePeer(key, p)
	buf := make([]byte, protocol.MaxDatagram)
	for {
		payload, err := protocol.ReadFrame(p.stream, buf)
		if err != nil {
			return
		}
		if _, err := r.udpPC.WriteTo(payload, p.addr); err != nil {
			return
		}
		p.last.Store(time.Now().UnixNano())
		r.bytesOut.Add(int64(len(payload)))
	}
}

func (r *forwardRunner) udpReaper() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-r.t.udpIdle).UnixNano()
			var stale []*udpPeer
			var keys []string
			r.udpMu.Lock()
			for k, p := range r.peers {
				if p.last.Load() < cutoff {
					stale = append(stale, p)
					keys = append(keys, k)
				}
			}
			r.udpMu.Unlock()
			for i, p := range stale {
				r.removePeer(keys[i], p)
			}
		}
	}
}
