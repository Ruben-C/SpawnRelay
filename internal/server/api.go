package server

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/firewall"
	"github.com/Ruben-C/SpawnRelay/internal/store"
)

//go:embed web
var webFS embed.FS

//go:embed scripts/install-client.sh scripts/install-client.ps1
var scriptFS embed.FS

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.cfg.Version})
	})
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /install/client.sh", s.handleInstallScript("scripts/install-client.sh", "text/x-shellscript"))
	mux.HandleFunc("GET /install/client.ps1", s.handleInstallScript("scripts/install-client.ps1", "text/plain"))
	mux.HandleFunc("GET /dl/{name}", s.handleDownload)

	// Authenticated (session or API token)
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("GET /api/v1/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("GET /api/v1/settings", s.requireAuth(s.handleGetSettings))
	mux.HandleFunc("GET /api/v1/clients", s.requireAuth(s.handleListClients))
	mux.HandleFunc("POST /api/v1/clients", s.requireAuth(s.handleCreateClient))
	mux.HandleFunc("GET /api/v1/clients/{id}", s.requireAuth(s.handleGetClient))
	mux.HandleFunc("PATCH /api/v1/clients/{id}", s.requireAuth(s.handleUpdateClient))
	mux.HandleFunc("DELETE /api/v1/clients/{id}", s.requireAuth(s.handleDeleteClient))
	mux.HandleFunc("POST /api/v1/clients/{id}/rotate-token", s.requireAuth(s.handleRotateClientToken))
	mux.HandleFunc("GET /api/v1/forwards", s.requireAuth(s.handleListForwards))
	mux.HandleFunc("POST /api/v1/forwards", s.requireAuth(s.handleCreateForward))
	mux.HandleFunc("GET /api/v1/forwards/{id}", s.requireAuth(s.handleGetForward))
	mux.HandleFunc("PATCH /api/v1/forwards/{id}", s.requireAuth(s.handleUpdateForward))
	mux.HandleFunc("DELETE /api/v1/forwards/{id}", s.requireAuth(s.handleDeleteForward))

	// Interactive session only
	mux.HandleFunc("PUT /api/v1/settings", s.requireSession(s.handlePutSettings))
	mux.HandleFunc("POST /api/v1/auth/password", s.requireSession(s.handleChangePassword))
	mux.HandleFunc("GET /api/v1/tokens", s.requireSession(s.handleListTokens))
	mux.HandleFunc("POST /api/v1/tokens", s.requireSession(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.requireSession(s.handleDeleteToken))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "unknown endpoint")
	})

	// Web UI
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if !strings.HasPrefix(r.URL.Path, "/install/") && !strings.HasPrefix(r.URL.Path, "/dl/") {
			h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- helpers -------------------------------------------------------------

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func writeStoreError(w http.ResponseWriter, err error) {
	msg := err.Error()
	for _, p := range []string{"validation: ", "conflict: ", "not found: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, msg)
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, msg)
	case errors.Is(err, store.ErrValidation):
		writeError(w, http.StatusBadRequest, msg)
	default:
		writeError(w, http.StatusInternalServerError, msg)
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "request body is required")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// ---- auth ----------------------------------------------------------------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	if s.limiter.blocked(ip) {
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}
	var ok bool
	var username string
	s.store.View(func(st *store.State) {
		username = st.Admin.Username
		ok = strings.EqualFold(in.Username, st.Admin.Username) && st.Admin.CheckPassword(in.Password)
	})
	if !ok {
		s.limiter.fail(ip)
		time.Sleep(300 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.limiter.reset(ip)
	id := s.sessions.create(username)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, principalFrom(r))
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.NewPassword) < 10 {
		writeError(w, http.StatusBadRequest, "new password must be at least 10 characters")
		return
	}
	err := s.store.Update(func(st *store.State) error {
		if !st.Admin.CheckPassword(in.CurrentPassword) {
			return fmt.Errorf("%w: current password is incorrect", store.ErrValidation)
		}
		return st.Admin.SetPassword(in.NewPassword)
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "initial-admin-password"))
	s.sessions.clear()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "password changed; please sign in again"})
}

// ---- status & settings ---------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var total, forwards int
	var clientIDs []string
	s.store.View(func(st *store.State) {
		total = len(st.Clients)
		forwards = len(st.Forwards)
		for _, c := range st.Clients {
			clientIDs = append(clientIDs, c.ID)
		}
	})
	online := 0
	for _, id := range clientIDs {
		if s.tunnel.ClientStatus(id).Online {
			online++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":            s.cfg.Version,
		"server_time":        time.Now().UTC(),
		"uptime_seconds":     int(time.Since(s.startedAt).Seconds()),
		"public_host":        s.PublicHost(),
		"tunnel_port":        s.tunnelPort,
		"tunnel_addr":        s.TunnelAddr(),
		"tunnel_fingerprint": s.tunnelFingerprint,
		"admin_url":          s.AdminURL(),
		"admin_self_signed":  s.adminSelfSigned,
		"clients_total":      total,
		"clients_online":     online,
		"forwards_total":     forwards,
		"os":                 runtime.GOOS,
		"arch":               runtime.GOARCH,
	})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	var out store.Settings
	s.store.View(func(st *store.State) { out = st.Settings })
	mode := out.Firewall
	if mode == "" {
		mode = firewall.ModeAuto
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"public_host":           out.PublicHost,
		"detected_public_host":  s.detectedHost,
		"effective_public_host": s.PublicHost(),
		"firewall":              mode,
		"firewall_modes":        firewall.Modes,
		"firewall_status":       s.firewall.Status(),
	})
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PublicHost *string `json:"public_host"`
		Firewall   *string `json:"firewall"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var newHost string
	firewallChanged := false
	err := s.store.Update(func(st *store.State) error {
		if in.PublicHost != nil {
			h := strings.TrimSpace(*in.PublicHost)
			if h != "" && (strings.ContainsAny(h, " /:\\") || len(h) > 253) {
				return fmt.Errorf("%w: public_host must be a hostname or IP address", store.ErrValidation)
			}
			st.Settings.PublicHost = h
		}
		if in.Firewall != nil {
			m := strings.ToLower(strings.TrimSpace(*in.Firewall))
			if m == "" {
				m = firewall.ModeAuto
			}
			if !firewall.ValidMode(m) {
				return fmt.Errorf("%w: firewall must be one of %s", store.ErrValidation, strings.Join(firewall.Modes, ", "))
			}
			firewallChanged = st.Settings.Firewall != m
			st.Settings.Firewall = m
		}
		newHost = st.Settings.PublicHost
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.setPublicHost(newHost)
	if firewallChanged {
		s.log.Info("firewall mode changed", "by", principalFrom(r).Name)
		s.firewall.Sync(r.Context())
	}
	s.handleGetSettings(w, r)
}

// ---- clients -------------------------------------------------------------

type clientOut struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Token         string       `json:"token"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
	LastSeenAt    *time.Time   `json:"last_seen_at,omitempty"`
	LastAddr      string       `json:"last_addr,omitempty"`
	Hostname      string       `json:"hostname,omitempty"`
	OS            string       `json:"os,omitempty"`
	Arch          string       `json:"arch,omitempty"`
	ClientVersion string       `json:"client_version,omitempty"`
	Status        ClientStatus `json:"status"`
	ForwardCount  int          `json:"forward_count"`
	Install       installInfo  `json:"install"`
}

type installInfo struct {
	Linux   string `json:"linux"`
	Windows string `json:"windows"`
	Manual  string `json:"manual"`
}

func (s *Server) installInfo(token string) installInfo {
	base := s.AdminURL()
	curlFlags := ""
	if s.adminSelfSigned {
		curlFlags = "-k "
	}
	psSkip := ""
	if s.adminSelfSigned {
		psSkip = " -SkipCertificateCheck"
	}
	return installInfo{
		Linux:   fmt.Sprintf("curl -fsSL %s%s/install/client.sh?token=%s | sudo bash", curlFlags, base, token),
		Windows: fmt.Sprintf("irm%s '%s/install/client.ps1?token=%s' | iex", psSkip, base, token),
		Manual:  fmt.Sprintf("spawnrelay client --server %s --token %s --fingerprint %s", s.TunnelAddr(), token, s.tunnelFingerprint),
	}
}

func (s *Server) clientOut(c *store.Client, forwardCount int) clientOut {
	return clientOut{
		ID: c.ID, Name: c.Name, Token: c.Token, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
		LastSeenAt: c.LastSeenAt, LastAddr: c.LastAddr, Hostname: c.Hostname, OS: c.OS, Arch: c.Arch,
		ClientVersion: c.ClientVersion, Status: s.tunnel.ClientStatus(c.ID), ForwardCount: forwardCount,
		Install: s.installInfo(c.Token),
	}
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	out := []clientOut{}
	s.store.View(func(st *store.State) {
		for _, c := range st.Clients {
			out = append(out, s.clientOut(c, len(st.ForwardsForClient(c.ID))))
		}
	})
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if err := store.ValidateName(in.Name); err != nil {
		writeStoreError(w, err)
		return
	}
	now := time.Now()
	c := &store.Client{ID: store.NewID(), Name: in.Name, Token: store.NewClientToken(), CreatedAt: now, UpdatedAt: now}
	err := s.store.Update(func(st *store.State) error {
		for _, o := range st.Clients {
			if strings.EqualFold(o.Name, in.Name) {
				return fmt.Errorf("%w: a client named %q already exists", store.ErrConflict, in.Name)
			}
		}
		st.Clients = append(st.Clients, c)
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.log.Info("client created", "client", c.Name, "client_id", c.ID, "by", principalFrom(r).Name)
	writeJSON(w, http.StatusCreated, s.clientOut(c, 0))
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var out *clientOut
	s.store.View(func(st *store.State) {
		if c := st.ClientByID(id); c != nil {
			o := s.clientOut(c, len(st.ForwardsForClient(c.ID)))
			out = &o
		}
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "client not found")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name *string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	var out clientOut
	err := s.store.Update(func(st *store.State) error {
		c := st.ClientByID(id)
		if c == nil {
			return fmt.Errorf("%w: client not found", store.ErrNotFound)
		}
		if in.Name != nil {
			name := strings.TrimSpace(*in.Name)
			if err := store.ValidateName(name); err != nil {
				return err
			}
			for _, o := range st.Clients {
				if o.ID != c.ID && strings.EqualFold(o.Name, name) {
					return fmt.Errorf("%w: a client named %q already exists", store.ErrConflict, name)
				}
			}
			c.Name = name
		}
		c.UpdatedAt = time.Now()
		out = s.clientOut(c, len(st.ForwardsForClient(c.ID)))
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var removedForwards []string
	var name string
	err := s.store.Update(func(st *store.State) error {
		c := st.ClientByID(id)
		if c == nil {
			return fmt.Errorf("%w: client not found", store.ErrNotFound)
		}
		name = c.Name
		kept := st.Forwards[:0]
		for _, f := range st.Forwards {
			if f.ClientID == id {
				removedForwards = append(removedForwards, f.ID)
			} else {
				kept = append(kept, f)
			}
		}
		st.Forwards = kept
		clients := st.Clients[:0]
		for _, o := range st.Clients {
			if o.ID != id {
				clients = append(clients, o)
			}
		}
		st.Clients = clients
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for _, fid := range removedForwards {
		s.tunnel.Remove(fid)
	}
	s.tunnel.DisconnectClient(id, "client deleted")
	if len(removedForwards) > 0 {
		s.firewall.Sync(r.Context())
	}
	s.log.Info("client deleted", "client", name, "client_id", id, "forwards_removed", len(removedForwards), "by", principalFrom(r).Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "forwards_removed": len(removedForwards)})
}

func (s *Server) handleRotateClientToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var out clientOut
	err := s.store.Update(func(st *store.State) error {
		c := st.ClientByID(id)
		if c == nil {
			return fmt.Errorf("%w: client not found", store.ErrNotFound)
		}
		c.Token = store.NewClientToken()
		c.UpdatedAt = time.Now()
		out = s.clientOut(c, len(st.ForwardsForClient(c.ID)))
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.tunnel.DisconnectClient(id, "token rotated; reinstall the client with the new token")
	out.Status = ClientStatus{}
	s.log.Info("client token rotated", "client", out.Name, "client_id", id, "by", principalFrom(r).Name)
	writeJSON(w, http.StatusOK, out)
}

// ---- forwards ------------------------------------------------------------

type forwardOut struct {
	ID         string          `json:"id"`
	ClientID   string          `json:"client_id"`
	ClientName string          `json:"client_name"`
	Name       string          `json:"name"`
	Protocol   string          `json:"protocol"`
	PublicPort int             `json:"public_port"`
	PublicAddr string          `json:"public_addr"`
	TargetHost string          `json:"target_host"`
	TargetPort int             `json:"target_port"`
	Enabled    bool            `json:"enabled"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Stats      ForwardStats    `json:"stats"`
	Firewall   ForwardFirewall `json:"firewall"`
}

func (s *Server) forwardOut(st *store.State, f *store.Forward) forwardOut {
	name := ""
	if c := st.ClientByID(f.ClientID); c != nil {
		name = c.Name
	}
	return forwardOut{
		ID: f.ID, ClientID: f.ClientID, ClientName: name, Name: f.Name, Protocol: f.Protocol,
		PublicPort: f.PublicPort, PublicAddr: net.JoinHostPort(s.PublicHost(), strconv.Itoa(f.PublicPort)),
		TargetHost: f.TargetHost, TargetPort: f.TargetPort, Enabled: f.Enabled,
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt, Stats: s.tunnel.ForwardStats(f.ID),
		Firewall: s.firewall.ForwardState(f),
	}
}

func (s *Server) handleListForwards(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("client_id")
	out := []forwardOut{}
	s.store.View(func(st *store.State) {
		for _, f := range st.Forwards {
			if filter != "" && f.ClientID != filter {
				continue
			}
			out = append(out, s.forwardOut(st, f))
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].PublicPort < out[j].PublicPort })
	writeJSON(w, http.StatusOK, out)
}

type forwardInput struct {
	ClientID   *string `json:"client_id"`
	Name       *string `json:"name"`
	Protocol   *string `json:"protocol"`
	PublicPort *int    `json:"public_port"`
	TargetHost *string `json:"target_host"`
	TargetPort *int    `json:"target_port"`
	Enabled    *bool   `json:"enabled"`
}

func (in *forwardInput) applyTo(f *store.Forward) {
	if in.ClientID != nil {
		f.ClientID = strings.TrimSpace(*in.ClientID)
	}
	if in.Name != nil {
		f.Name = strings.TrimSpace(*in.Name)
	}
	if in.Protocol != nil {
		f.Protocol = strings.ToLower(strings.TrimSpace(*in.Protocol))
	}
	if in.PublicPort != nil {
		f.PublicPort = *in.PublicPort
	}
	if in.TargetHost != nil {
		f.TargetHost = strings.TrimSpace(*in.TargetHost)
	}
	if in.TargetPort != nil {
		f.TargetPort = *in.TargetPort
	}
	if in.Enabled != nil {
		f.Enabled = *in.Enabled
	}
}

func (s *Server) reservedPort(port int) error {
	if port == s.tunnelPort {
		return fmt.Errorf("%w: port %d is the tunnel port", store.ErrConflict, port)
	}
	if port == s.adminPort {
		return fmt.Errorf("%w: port %d is the management interface port", store.ErrConflict, port)
	}
	return nil
}

func (s *Server) handleCreateForward(w http.ResponseWriter, r *http.Request) {
	var in forwardInput
	if !readJSON(w, r, &in) {
		return
	}
	now := time.Now()
	f := &store.Forward{ID: store.NewID(), Protocol: store.ProtoTCP, TargetHost: "127.0.0.1", Enabled: true, CreatedAt: now, UpdatedAt: now}
	in.applyTo(f)
	if in.PublicPort == nil && in.TargetPort != nil {
		f.PublicPort = f.TargetPort // convenient default: same port on both ends
	}
	if in.TargetPort == nil && in.PublicPort != nil {
		f.TargetPort = f.PublicPort
	}
	if f.Name == "" {
		f.Name = fmt.Sprintf("%s-%d", f.Protocol, f.PublicPort)
	}
	if err := f.Validate(); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.reservedPort(f.PublicPort); err != nil {
		writeStoreError(w, err)
		return
	}
	var out forwardOut
	err := s.store.Update(func(st *store.State) error {
		if st.ClientByID(f.ClientID) == nil {
			return fmt.Errorf("%w: client_id does not refer to an existing client", store.ErrValidation)
		}
		if o := st.PortConflict(f); o != nil {
			return fmt.Errorf("%w: port %d is already used by forward %q", store.ErrConflict, f.PublicPort, o.Name)
		}
		if err := s.tunnel.Apply(f); err != nil {
			return fmt.Errorf("%w: cannot listen on %v", store.ErrConflict, err)
		}
		st.Forwards = append(st.Forwards, f)
		out = s.forwardOut(st, f)
		return nil
	})
	if err != nil {
		s.tunnel.Remove(f.ID)
		writeStoreError(w, err)
		return
	}
	s.tunnel.NotifyForwards(f.ClientID)
	s.firewall.Sync(r.Context())
	out.Firewall = s.firewall.ForwardState(f)
	s.log.Info("forward created", "forward", f.Name, "protocol", f.Protocol, "public_port", f.PublicPort, "target", f.Target(), "by", principalFrom(r).Name)
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleGetForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var out *forwardOut
	s.store.View(func(st *store.State) {
		if f := st.ForwardByID(id); f != nil {
			o := s.forwardOut(st, f)
			out = &o
		}
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "forward not found")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpdateForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in forwardInput
	if !readJSON(w, r, &in) {
		return
	}
	var out forwardOut
	var oldClient string
	var updated store.Forward
	err := s.store.Update(func(st *store.State) error {
		f := st.ForwardByID(id)
		if f == nil {
			return fmt.Errorf("%w: forward not found", store.ErrNotFound)
		}
		next := *f
		in.applyTo(&next)
		next.UpdatedAt = time.Now()
		if err := next.Validate(); err != nil {
			return err
		}
		if err := s.reservedPort(next.PublicPort); err != nil {
			return err
		}
		if st.ClientByID(next.ClientID) == nil {
			return fmt.Errorf("%w: client_id does not refer to an existing client", store.ErrValidation)
		}
		if o := st.PortConflict(&next); o != nil {
			return fmt.Errorf("%w: port %d is already used by forward %q", store.ErrConflict, next.PublicPort, o.Name)
		}
		if err := s.tunnel.Apply(&next); err != nil {
			return fmt.Errorf("%w: cannot listen on %v", store.ErrConflict, err)
		}
		oldClient = f.ClientID
		*f = next
		updated = next
		out = s.forwardOut(st, f)
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.tunnel.NotifyForwards(updated.ClientID)
	if oldClient != updated.ClientID {
		s.tunnel.NotifyForwards(oldClient)
	}
	s.firewall.Sync(r.Context())
	out.Firewall = s.firewall.ForwardState(&updated)
	s.log.Info("forward updated", "forward", updated.Name, "protocol", updated.Protocol, "public_port", updated.PublicPort, "target", updated.Target(), "enabled", updated.Enabled, "by", principalFrom(r).Name)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeleteForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var removed store.Forward
	err := s.store.Update(func(st *store.State) error {
		f := st.ForwardByID(id)
		if f == nil {
			return fmt.Errorf("%w: forward not found", store.ErrNotFound)
		}
		removed = *f
		kept := st.Forwards[:0]
		for _, o := range st.Forwards {
			if o.ID != id {
				kept = append(kept, o)
			}
		}
		st.Forwards = kept
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.tunnel.Remove(id)
	s.tunnel.NotifyForwards(removed.ClientID)
	s.firewall.Sync(r.Context())
	s.log.Info("forward deleted", "forward", removed.Name, "public_port", removed.PublicPort, "by", principalFrom(r).Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- API tokens ----------------------------------------------------------

type tokenOut struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Token      string     `json:"token,omitempty"` // only on creation
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	out := []tokenOut{}
	s.store.View(func(st *store.State) {
		for _, t := range st.Tokens {
			out = append(out, tokenOut{ID: t.ID, Name: t.Name, Prefix: t.Prefix, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt})
		}
	})
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if err := store.ValidateName(in.Name); err != nil {
		writeStoreError(w, err)
		return
	}
	secret := store.NewAPIToken()
	t := &store.APIToken{ID: store.NewID(), Name: in.Name, Prefix: secret[:len(store.APITokenPrefix)+6], TokenHash: store.HashToken(secret), CreatedAt: time.Now()}
	err := s.store.Update(func(st *store.State) error {
		st.Tokens = append(st.Tokens, t)
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.log.Info("api token created", "token", t.Name, "token_id", t.ID)
	writeJSON(w, http.StatusCreated, tokenOut{ID: t.ID, Name: t.Name, Prefix: t.Prefix, CreatedAt: t.CreatedAt, Token: secret})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.Update(func(st *store.State) error {
		kept := st.Tokens[:0]
		found := false
		for _, t := range st.Tokens {
			if t.ID == id {
				found = true
				continue
			}
			kept = append(kept, t)
		}
		if !found {
			return fmt.Errorf("%w: token not found", store.ErrNotFound)
		}
		st.Tokens = kept
		return nil
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.log.Info("api token deleted", "token_id", id)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- installers & downloads ---------------------------------------------

type installParams struct {
	Server      string
	Token       string
	Fingerprint string
	AdminURL    string
	CurlFlags   string
	SkipCert    bool
	Version     string
	ClientName  string
}

func (s *Server) handleInstallScript(name, contentType string) http.HandlerFunc {
	tmpl := template.Must(template.ParseFS(scriptFS, name))
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		var clientName string
		s.store.View(func(st *store.State) {
			if c := st.ClientByToken(token); c != nil {
				clientName = c.Name
			}
		})
		if clientName == "" {
			http.Error(w, "echo 'SpawnRelay: unknown or missing client token'; exit 1", http.StatusUnauthorized)
			return
		}
		curl := ""
		if s.adminSelfSigned {
			curl = "-k"
		}
		p := installParams{
			Server: s.TunnelAddr(), Token: token, Fingerprint: s.tunnelFingerprint, AdminURL: s.AdminURL(),
			CurlFlags: curl, SkipCert: s.adminSelfSigned, Version: s.cfg.Version, ClientName: clientName,
		}
		w.Header().Set("Content-Type", contentType+"; charset=utf-8")
		_ = tmpl.Execute(w, p)
	}
}

var downloadName = regexp.MustCompile(`^spawnrelay_(linux|darwin|windows|freebsd)_(amd64|arm64|arm|386)(\.exe)?$`)

// handleDownload serves client binaries from <data-dir>/bin, falling back to
// the running executable when the requested platform matches the server's.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	m := downloadName.FindStringSubmatch(name)
	if m == nil {
		http.Error(w, "unknown binary name; expected spawnrelay_<os>_<arch>", http.StatusNotFound)
		return
	}
	goos, goarch := m[1], m[2]
	path := filepath.Join(s.cfg.DataDir, "bin", name)
	if _, err := os.Stat(path); err == nil {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+name)
		http.ServeFile(w, r, path)
		return
	}
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		if exe, err := os.Executable(); err == nil {
			if real, err := filepath.EvalSymlinks(exe); err == nil {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", "attachment; filename="+name)
				http.ServeFile(w, r, real)
				return
			}
		}
	}
	http.Error(w, fmt.Sprintf("no binary for %s/%s on this server; place a build at %s", goos, goarch, path), http.StatusNotFound)
}
