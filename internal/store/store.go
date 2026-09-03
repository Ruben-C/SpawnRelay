// Package store persists SpawnRelay's configuration (clients, port forwards,
// API tokens, admin credentials and settings) in a single JSON file.
//
// The data set is small (a handful of clients and forwards) so a whole-file
// atomic rewrite on every change is simpler and more robust than a database.
package store

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Token prefixes make it obvious what kind of secret a string is.
const (
	ClientTokenPrefix = "sr_c_"
	APITokenPrefix    = "sr_api_"
)

// Protocol values accepted for a forward.
const (
	ProtoTCP  = "tcp"
	ProtoUDP  = "udp"
	ProtoBoth = "both"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
	ErrValidation = errors.New("validation")
)

// Client is a machine that connects to the relay and hosts game servers.
type Client struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Token is stored in clear so the install command can be shown again in
	// the management interface. The state file is only readable by root.
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Details learned from the last successful connection.
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	LastAddr      string     `json:"last_addr,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
	OS            string     `json:"os,omitempty"`
	Arch          string     `json:"arch,omitempty"`
	ClientVersion string     `json:"client_version,omitempty"`
}

// Forward exposes a public port on the relay that is relayed to a target
// host:port reachable from the client.
type Forward struct {
	ID         string    `json:"id"`
	ClientID   string    `json:"client_id"`
	Name       string    `json:"name"`
	Protocol   string    `json:"protocol"` // tcp | udp | both
	PublicPort int       `json:"public_port"`
	TargetHost string    `json:"target_host"`
	TargetPort int       `json:"target_port"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Target returns the client-side dial address.
func (f *Forward) Target() string {
	return fmt.Sprintf("%s:%d", f.TargetHost, f.TargetPort)
}

// HasTCP / HasUDP report which listeners a forward needs.
func (f *Forward) HasTCP() bool { return f.Protocol == ProtoTCP || f.Protocol == ProtoBoth }
func (f *Forward) HasUDP() bool { return f.Protocol == ProtoUDP || f.Protocol == ProtoBoth }

// Same reports whether two forwards would produce identical listeners.
func (f *Forward) Same(o *Forward) bool {
	return f.ClientID == o.ClientID && f.Protocol == o.Protocol && f.PublicPort == o.PublicPort &&
		f.TargetHost == o.TargetHost && f.TargetPort == o.TargetPort && f.Enabled == o.Enabled
}

// APIToken is a bearer token for automation.
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"` // first characters shown in the UI
	TokenHash  string     `json:"token_hash"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Admin holds the management interface credentials.
type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // hex(pbkdf2-sha256)
	Salt         string `json:"salt"`          // hex
	Iterations   int    `json:"iterations"`
}

// Settings are user-editable server settings.
type Settings struct {
	// PublicHost is the hostname or IP players and clients use to reach the relay.
	PublicHost string `json:"public_host"`
}

// State is the on-disk document.
type State struct {
	Admin    Admin       `json:"admin"`
	Settings Settings    `json:"settings"`
	Clients  []*Client   `json:"clients"`
	Forwards []*Forward  `json:"forwards"`
	Tokens   []*APIToken `json:"tokens"`
}

// Store is a mutex-guarded State persisted to a JSON file.
type Store struct {
	path  string
	mu    sync.RWMutex
	state State
}

// Open loads the store at path, creating an empty one when it doesn't exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.state); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	return s, nil
}

// Path returns the backing file path.
func (s *Store) Path() string { return s.path }

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// View runs fn with read access to the state.
func (s *Store) View(fn func(st *State)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.state)
}

// Update runs fn with write access and persists the result if fn succeeds.
func (s *Store) Update(fn func(st *State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.state); err != nil {
		return err
	}
	return s.saveLocked()
}

// ---- secrets -------------------------------------------------------------

// NewID returns a random 12-hex-char identifier.
func NewID() string { return randomHex(6) }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewClientToken / NewAPIToken return fresh secrets. Only the hash is stored.
func NewClientToken() string { return ClientTokenPrefix + randomHex(24) }
func NewAPIToken() string    { return APITokenPrefix + randomHex(24) }

// HashToken returns the hex SHA-256 of a token.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// RandomPassword returns a human-typeable random password.
func RandomPassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

const pbkdfIterations = 210_000

// SetAdminPassword hashes and stores password for the admin user.
func (a *Admin) SetPassword(password string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdfIterations, 32)
	if err != nil {
		return err
	}
	a.Salt = hex.EncodeToString(salt)
	a.PasswordHash = hex.EncodeToString(key)
	a.Iterations = pbkdfIterations
	return nil
}

// CheckPassword verifies password against the stored hash in constant time.
func (a *Admin) CheckPassword(password string) bool {
	if a.PasswordHash == "" || a.Salt == "" {
		return false
	}
	salt, err := hex.DecodeString(a.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(a.PasswordHash)
	if err != nil {
		return false
	}
	iters := a.Iterations
	if iters <= 0 {
		iters = pbkdfIterations
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iters, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- lookups (callers hold the lock via View/Update) ---------------------

func (st *State) ClientByID(id string) *Client {
	for _, c := range st.Clients {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (st *State) ClientByToken(tok string) *Client {
	if tok == "" {
		return nil
	}
	for _, c := range st.Clients {
		if subtle.ConstantTimeCompare([]byte(c.Token), []byte(tok)) == 1 {
			return c
		}
	}
	return nil
}

func (st *State) ForwardByID(id string) *Forward {
	for _, f := range st.Forwards {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func (st *State) TokenByHash(h string) *APIToken {
	for _, t := range st.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(h)) == 1 {
			return t
		}
	}
	return nil
}

func (st *State) TokenByID(id string) *APIToken {
	for _, t := range st.Tokens {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// ForwardsForClient returns forwards belonging to client id, sorted by port.
func (st *State) ForwardsForClient(id string) []*Forward {
	var out []*Forward
	for _, f := range st.Forwards {
		if f.ClientID == id {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicPort < out[j].PublicPort })
	return out
}

// ---- validation ----------------------------------------------------------

// ValidateName checks a human-facing name.
func ValidateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrValidation)
	}
	if len(name) > 64 {
		return fmt.Errorf("%w: name must be 64 characters or fewer", ErrValidation)
	}
	return nil
}

// Validate checks a forward's fields (not port availability).
func (f *Forward) Validate() error {
	if err := ValidateName(f.Name); err != nil {
		return err
	}
	switch f.Protocol {
	case ProtoTCP, ProtoUDP, ProtoBoth:
	default:
		return fmt.Errorf("%w: protocol must be tcp, udp or both", ErrValidation)
	}
	if f.PublicPort < 1 || f.PublicPort > 65535 {
		return fmt.Errorf("%w: public_port must be between 1 and 65535", ErrValidation)
	}
	if f.TargetPort < 1 || f.TargetPort > 65535 {
		return fmt.Errorf("%w: target_port must be between 1 and 65535", ErrValidation)
	}
	if strings.TrimSpace(f.TargetHost) == "" {
		return fmt.Errorf("%w: target_host is required", ErrValidation)
	}
	if strings.ContainsAny(f.TargetHost, " /\\\t\n") {
		return fmt.Errorf("%w: target_host is not a valid host", ErrValidation)
	}
	return nil
}

// PortConflict returns the forward that already uses f's public port with an
// overlapping protocol, ignoring f itself.
func (st *State) PortConflict(f *Forward) *Forward {
	for _, o := range st.Forwards {
		if o.ID == f.ID || o.PublicPort != f.PublicPort {
			continue
		}
		if (f.HasTCP() && o.HasTCP()) || (f.HasUDP() && o.HasUDP()) {
			return o
		}
	}
	return nil
}
