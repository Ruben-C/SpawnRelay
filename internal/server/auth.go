package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/store"
)

const sessionCookie = "spawnrelay_session"
const sessionTTL = 7 * 24 * time.Hour

// principal identifies who is making an API request.
type principal struct {
	Kind      string `json:"kind"` // "session" | "token"
	Name      string `json:"name"`
	TokenID   string `json:"token_id,omitempty"`
	expiresAt time.Time
}

type ctxKey struct{}

func principalFrom(r *http.Request) *principal {
	p, _ := r.Context().Value(ctxKey{}).(*principal)
	return p
}

// ---- browser sessions ----------------------------------------------------

type sessionStore struct {
	mu   sync.Mutex
	byID map[string]*principal
}

func newSessionStore() *sessionStore { return &sessionStore{byID: map[string]*principal{}} }

func (ss *sessionStore) create(name string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	ss.mu.Lock()
	ss.byID[id] = &principal{Kind: "session", Name: name, expiresAt: time.Now().Add(sessionTTL)}
	ss.mu.Unlock()
	return id
}

func (ss *sessionStore) get(id string) *principal {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	p := ss.byID[id]
	if p == nil {
		return nil
	}
	if time.Now().After(p.expiresAt) {
		delete(ss.byID, id)
		return nil
	}
	p.expiresAt = time.Now().Add(sessionTTL) // sliding expiry
	return p
}

func (ss *sessionStore) delete(id string) {
	ss.mu.Lock()
	delete(ss.byID, id)
	ss.mu.Unlock()
}

func (ss *sessionStore) clear() {
	ss.mu.Lock()
	ss.byID = map[string]*principal{}
	ss.mu.Unlock()
}

// ---- login rate limiting -------------------------------------------------

type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	loginMaxFailures = 5
	loginWindow      = 15 * time.Minute
)

func newLoginLimiter() *loginLimiter { return &loginLimiter{failures: map[string][]time.Time{}} }

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip)) >= loginMaxFailures
}

func (l *loginLimiter) recent(ip string) []time.Time {
	cutoff := time.Now().Add(-loginWindow)
	var keep []time.Time
	for _, t := range l.failures[ip] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.failures, ip)
	} else {
		l.failures[ip] = keep
	}
	return keep
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	l.failures[ip] = append(l.recent(ip), time.Now())
	l.mu.Unlock()
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.failures, ip)
	l.mu.Unlock()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- middleware ----------------------------------------------------------

// authenticate resolves the principal from a bearer token or session cookie.
func (s *Server) authenticate(r *http.Request) *principal {
	if h := r.Header.Get("Authorization"); h != "" {
		if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
			return nil
		}
		tok := strings.TrimSpace(h[7:])
		if !strings.HasPrefix(tok, store.APITokenPrefix) {
			return nil
		}
		hash := store.HashToken(tok)
		var p *principal
		var touch bool
		s.store.View(func(st *store.State) {
			t := st.TokenByHash(hash)
			if t == nil {
				return
			}
			p = &principal{Kind: "token", Name: t.Name, TokenID: t.ID}
			touch = t.LastUsedAt == nil || time.Since(*t.LastUsedAt) > time.Minute
		})
		if p != nil && touch {
			now := time.Now()
			_ = s.store.Update(func(st *store.State) error {
				if t := st.TokenByID(p.TokenID); t != nil {
					t.LastUsedAt = &now
				}
				return nil
			})
		}
		return p
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	return s.sessions.get(c.Value)
}

// requireAuth admits sessions and API tokens; requireSession admits only
// browser sessions (used for credential management).
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.guard(next, false)
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return s.guard(next, true)
}

func (s *Server) guard(next http.HandlerFunc, sessionOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := s.authenticate(r)
		if p == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if sessionOnly && p.Kind != "session" {
			writeError(w, http.StatusForbidden, "this endpoint requires an interactive admin session")
			return
		}
		// Cross-site request protection for cookie-authenticated mutations.
		if p.Kind == "session" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				writeError(w, http.StatusForbidden, "cross-origin request rejected")
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	}
}

func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	origin = strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return strings.EqualFold(origin, r.Host)
}
