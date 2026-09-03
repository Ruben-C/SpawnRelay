// Package server implements the SpawnRelay relay server: the tunnel listener
// clients connect to, the public forward listeners, and the HTTPS management
// interface and API.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/store"
	"github.com/Ruben-C/SpawnRelay/internal/tlsutil"
)

// Config configures the server.
type Config struct {
	DataDir    string // state, certificates, downloadable binaries
	TunnelAddr string // listen address for clients, e.g. ":7443"
	AdminAddr  string // listen address for the management UI/API, e.g. ":8443"
	PublicHost string // hostname/IP players use; overrides the stored setting when set
	AdminCert  string // optional PEM certificate for the admin listener
	AdminKey   string // optional PEM key for the admin listener

	ResetAdminPassword bool
	Version            string
	Logger             *slog.Logger
}

// Server is a running relay.
type Server struct {
	cfg    Config
	log    *slog.Logger
	store  *store.Store
	tunnel *Tunnel

	tunnelFingerprint string
	adminTLS          *tls.Config
	adminSelfSigned   bool
	detectedHost      string
	tunnelPort        int
	adminPort         int
	startedAt         time.Time

	sessions *sessionStore
	limiter  *loginLimiter

	hostMu     sync.RWMutex
	publicHost string // configured value, cached so lookups never touch the store lock
}

// New prepares a server: loads state, certificates and the admin password.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.DataDir == "" {
		return nil, errors.New("data directory is required")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.json"))
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: cfg.Logger, store: st, sessions: newSessionStore(), limiter: newLoginLimiter(), startedAt: time.Now()}

	// Ports (for the UI and generated install commands).
	if s.tunnelPort, err = portOf(cfg.TunnelAddr); err != nil {
		return nil, fmt.Errorf("tunnel address: %w", err)
	}
	if s.adminPort, err = portOf(cfg.AdminAddr); err != nil {
		return nil, fmt.Errorf("admin address: %w", err)
	}
	s.detectedHost = detectOutboundIP()

	// Persist an explicit public host, then cache whatever is configured.
	if cfg.PublicHost != "" {
		if err := st.Update(func(state *store.State) error {
			state.Settings.PublicHost = cfg.PublicHost
			return nil
		}); err != nil {
			return nil, err
		}
	}
	st.View(func(state *store.State) { s.publicHost = state.Settings.PublicHost })

	// Tunnel certificate: long-lived and self-signed; clients pin its fingerprint.
	tunnelCert, fp, created, err := tlsutil.LoadOrCreate(
		filepath.Join(cfg.DataDir, "tunnel.crt"), filepath.Join(cfg.DataDir, "tunnel.key"),
		"SpawnRelay Tunnel", []string{s.PublicHost()}, 20*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	if created {
		s.log.Info("generated tunnel certificate", "fingerprint", fp)
	}
	s.tunnelFingerprint = fp
	tunnelTLS := &tls.Config{
		Certificates: []tls.Certificate{tunnelCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"spawnrelay/1"},
	}
	s.tunnel = NewTunnel(st, tunnelTLS, cfg.Version, s.log)

	// Admin certificate: user-supplied, or self-signed and regenerated yearly.
	if cfg.AdminCert != "" || cfg.AdminKey != "" {
		if cfg.AdminCert == "" || cfg.AdminKey == "" {
			return nil, errors.New("both admin certificate and key must be set")
		}
		cert, err := tls.LoadX509KeyPair(cfg.AdminCert, cfg.AdminKey)
		if err != nil {
			return nil, fmt.Errorf("admin certificate: %w", err)
		}
		s.adminTLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	} else {
		cert, _, created, err := tlsutil.LoadOrCreate(
			filepath.Join(cfg.DataDir, "admin.crt"), filepath.Join(cfg.DataDir, "admin.key"),
			"SpawnRelay Admin", []string{s.PublicHost(), "localhost", "127.0.0.1"}, 5*365*24*time.Hour)
		if err != nil {
			return nil, err
		}
		if created {
			s.log.Info("generated self-signed admin certificate")
		}
		s.adminTLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		s.adminSelfSigned = true
	}

	if err := s.bootstrapAdmin(); err != nil {
		return nil, err
	}
	return s, nil
}

// bootstrapAdmin creates the admin account on first run (or when a reset was
// requested) and writes the generated password to a file the installer prints.
func (s *Server) bootstrapAdmin() error {
	var needs bool
	s.store.View(func(st *store.State) { needs = st.Admin.PasswordHash == "" })
	if !needs && !s.cfg.ResetAdminPassword {
		return nil
	}
	password := store.RandomPassword()
	if err := s.store.Update(func(st *store.State) error {
		st.Admin.Username = "admin"
		return st.Admin.SetPassword(password)
	}); err != nil {
		return err
	}
	path := filepath.Join(s.cfg.DataDir, "initial-admin-password")
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		return err
	}
	s.log.Warn("admin password generated", "username", "admin", "password_file", path)
	return nil
}

// PublicHost returns the configured public host, falling back to the detected
// outbound IP address.
func (s *Server) PublicHost() string {
	s.hostMu.RLock()
	host := s.publicHost
	s.hostMu.RUnlock()
	if host == "" {
		host = s.detectedHost
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host
}

// setPublicHost updates the cached configured host.
func (s *Server) setPublicHost(h string) {
	s.hostMu.Lock()
	s.publicHost = h
	s.hostMu.Unlock()
}

// AdminURL is the base URL of the management interface.
func (s *Server) AdminURL() string {
	return fmt.Sprintf("https://%s", net.JoinHostPort(s.PublicHost(), strconv.Itoa(s.adminPort)))
}

// TunnelAddr is the host:port clients connect to.
func (s *Server) TunnelAddr() string {
	return net.JoinHostPort(s.PublicHost(), strconv.Itoa(s.tunnelPort))
}

// Run starts the listeners and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tunnelLn, err := net.Listen("tcp", s.cfg.TunnelAddr)
	if err != nil {
		return fmt.Errorf("tunnel listener: %w", err)
	}
	adminLn, err := tls.Listen("tcp", s.cfg.AdminAddr, s.adminTLS)
	if err != nil {
		tunnelLn.Close()
		return fmt.Errorf("admin listener: %w", err)
	}

	for id, err := range s.tunnel.SyncAll() {
		s.log.Error("forward could not be started", "forward_id", id, "error", err)
	}

	httpSrv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 2)
	go func() { errCh <- s.tunnel.Serve(ctx, tunnelLn) }()
	go func() {
		if err := httpSrv.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	s.log.Info("SpawnRelay server started",
		"version", s.cfg.Version,
		"tunnel", s.TunnelAddr(),
		"admin", s.AdminURL(),
		"tunnel_fingerprint", s.tunnelFingerprint)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
		cancel()
	}
	shutdownCtx, c2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer c2()
	_ = httpSrv.Shutdown(shutdownCtx)
	s.tunnel.Shutdown()
	return runErr
}

func portOf(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(p)
}

// detectOutboundIP finds the IP of the interface that routes to the internet.
// On most VPSes that is the public address; cloud NAT setups should set the
// public host explicitly.
func detectOutboundIP() string {
	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	return ""
}
