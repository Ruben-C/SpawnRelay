package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/protocol"
	"github.com/hashicorp/yamux"
)

// Client updates: the server knows every client's version from its Hello and
// serves client binaries for all platforms. PushUpdate sends an "update"
// control message; the client fetches the binary over a stream of the same
// tunnel (handleClientStream), verifies it, swaps it in and restarts, and
// reports progress with "update_status" messages. The outcome is tracked per
// client in memory so the UI can show it, and confirmed when the client
// reconnects with the new version.

// Update states.
const (
	updatePending = "pending"
	updateDone    = "done"
	updateFailed  = "failed"
)

const (
	updateTimeout   = 3 * time.Minute // no reconnect or status within this = failed
	autoRetryAfter  = time.Hour       // automatic pushes are not retried sooner after a failure
	updateKeepDone  = 24 * time.Hour  // how long a "done" record is shown
	devVersion      = "dev"
	downloadTimeout = 10 * time.Minute
)

// ClientUpdate is the last update attempt for a client.
type ClientUpdate struct {
	State         string    `json:"state"` // pending | done | failed
	TargetVersion string    `json:"target_version"`
	Detail        string    `json:"detail,omitempty"`
	RequestedAt   time.Time `json:"requested_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Automatic     bool      `json:"automatic,omitempty"`
}

// binaryInfo is the cached size and hash of one client binary.
type binaryInfo struct {
	path    string
	size    int64
	modTime time.Time
	sha256  string
}

type binaryCache struct {
	mu    sync.Mutex
	cache map[string]binaryInfo // by asset name
}

// info returns the size and hash of the binary at path, recomputing when the
// file changed.
func (b *binaryCache) info(name, path string) (binaryInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return binaryInfo{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cache == nil {
		b.cache = map[string]binaryInfo{}
	}
	if c, ok := b.cache[name]; ok && c.path == path && c.size == st.Size() && c.modTime.Equal(st.ModTime()) {
		return c, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return binaryInfo{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return binaryInfo{}, err
	}
	info := binaryInfo{path: path, size: st.Size(), modTime: st.ModTime(), sha256: hex.EncodeToString(h.Sum(nil))}
	b.cache[name] = info
	return info, nil
}

// assetName is the download name for a client platform.
func assetName(goos, goarch string) string {
	name := "spawnrelay_" + goos + "_" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// UpdateAvailability reports whether an update can be pushed to a client
// right now, and why not otherwise.
func (t *Tunnel) UpdateAvailability(clientID string) (ok bool, reason string) {
	s := t.session(clientID)
	if s == nil {
		return false, "client is offline"
	}
	if s.Hello.ClientVersion == t.version {
		return false, "already on " + t.version
	}
	if !s.Hello.AllowUpdate {
		return false, "updates are disabled on the client (SPAWNRELAY_ALLOW_UPDATE=0) or it predates v0.3.0 and must be reinstalled once"
	}
	if t.binary == nil {
		return false, "no binaries available"
	}
	name := assetName(s.Hello.OS, s.Hello.Arch)
	if _, err := t.binary(name); err != nil {
		return false, fmt.Sprintf("no %s/%s binary on the server (%s)", s.Hello.OS, s.Hello.Arch, name)
	}
	if u := t.UpdateStatus(clientID); u != nil && u.State == updatePending {
		return false, "an update is already in progress"
	}
	return true, ""
}

// PushUpdate asks a connected client to update itself to the server's version.
func (t *Tunnel) PushUpdate(clientID string, automatic bool) error {
	if ok, reason := t.UpdateAvailability(clientID); !ok {
		return errors.New(reason)
	}
	s := t.session(clientID)
	if s == nil {
		return errors.New("client is offline")
	}
	name := assetName(s.Hello.OS, s.Hello.Arch)
	path, err := t.binary(name)
	if err != nil {
		return err
	}
	info, err := t.binaries.info(name, path)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	now := time.Now()
	t.mu.Lock()
	t.updates[clientID] = &ClientUpdate{State: updatePending, TargetVersion: t.version, Detail: "update requested", RequestedAt: now, UpdatedAt: now, Automatic: automatic}
	t.mu.Unlock()
	t.log.Info("pushing update to client", "client_id", clientID, "from", s.Hello.ClientVersion, "to", t.version, "asset", name, "automatic", automatic)
	go s.sendControl(protocol.ControlMessage{Type: "update", Update: &protocol.UpdateInfo{Version: t.version, Name: name, Size: info.size, SHA256: info.sha256}})
	return nil
}

// UpdateStatus returns the last update record for a client, expiring stale
// ones. nil means nothing to show.
func (t *Tunnel) UpdateStatus(clientID string) *ClientUpdate {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := t.updates[clientID]
	if u == nil {
		return nil
	}
	now := time.Now()
	switch u.State {
	case updatePending:
		if now.Sub(u.UpdatedAt) > updateTimeout {
			u.State = updateFailed
			u.Detail = "no response from the client within " + updateTimeout.String()
			u.UpdatedAt = now
		}
	case updateDone:
		if now.Sub(u.UpdatedAt) > updateKeepDone {
			delete(t.updates, clientID)
			return nil
		}
	}
	cp := *u
	return &cp
}

// handleClientMessage processes a message the client sent on the control stream.
func (t *Tunnel) handleClientMessage(s *Session, msg protocol.ControlMessage) {
	switch msg.Type {
	case "update_status":
		t.mu.Lock()
		u := t.updates[s.ClientID]
		if u != nil && u.State == updatePending {
			u.UpdatedAt = time.Now()
			u.Detail = msg.Message
			if msg.Status == "failed" {
				u.State = updateFailed
			}
		}
		t.mu.Unlock()
		lvl := t.log.Info
		if msg.Status == "failed" {
			lvl = t.log.Warn
		}
		lvl("client update status", "client_id", s.ClientID, "status", msg.Status, "message", msg.Message)
	}
}

// noteReconnect settles a pending update when the client comes back, and
// starts an automatic update when configured.
func (t *Tunnel) noteReconnect(s *Session) {
	now := time.Now()
	t.mu.Lock()
	if u := t.updates[s.ClientID]; u != nil && u.State == updatePending {
		u.UpdatedAt = now
		if s.Hello.ClientVersion == u.TargetVersion {
			u.State = updateDone
			u.Detail = "updated to " + s.Hello.ClientVersion
		} else {
			u.State = updateFailed
			u.Detail = "client reconnected still running " + s.Hello.ClientVersion
		}
	}
	t.mu.Unlock()

	if t.autoUpdate == nil || !t.autoUpdate() || t.version == devVersion {
		return
	}
	if u := t.UpdateStatus(s.ClientID); u != nil && u.State == updateFailed && now.Sub(u.UpdatedAt) < autoRetryAfter {
		return
	}
	if ok, _ := t.UpdateAvailability(s.ClientID); ok {
		if err := t.PushUpdate(s.ClientID, true); err != nil {
			t.log.Warn("automatic update not started", "client_id", s.ClientID, "error", err)
		}
	}
}

// handleClientStream serves a stream the client opened towards the server.
func (t *Tunnel) handleClientStream(s *Session, stream *yamux.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(downloadTimeout))
	br := protocol.NewReader(stream)
	var req protocol.ClientRequest
	if err := protocol.ReadJSONLine(br, &req); err != nil {
		return
	}
	if req.Type != "download" {
		_ = protocol.WriteJSONLine(stream, protocol.DownloadResponse{Error: "unknown request type " + req.Type})
		return
	}
	refuse := func(msg string) {
		t.log.Warn("client download refused", "client_id", s.ClientID, "name", req.Name, "reason", msg)
		_ = protocol.WriteJSONLine(stream, protocol.DownloadResponse{Error: msg})
	}
	if !downloadName.MatchString(req.Name) {
		refuse("invalid binary name")
		return
	}
	if t.binary == nil {
		refuse("downloads not available")
		return
	}
	path, err := t.binary(req.Name)
	if err != nil {
		refuse(err.Error())
		return
	}
	info, err := t.binaries.info(req.Name, path)
	if err != nil {
		refuse(err.Error())
		return
	}
	f, err := os.Open(path)
	if err != nil {
		refuse(err.Error())
		return
	}
	defer f.Close()
	if err := protocol.WriteJSONLine(stream, protocol.DownloadResponse{OK: true, Size: info.size, SHA256: info.sha256}); err != nil {
		return
	}
	n, err := io.Copy(stream, io.LimitReader(f, info.size))
	if err != nil {
		t.log.Warn("client download interrupted", "client_id", s.ClientID, "name", req.Name, "sent", n, "error", err)
		return
	}
	t.log.Info("client downloaded binary", "client_id", s.ClientID, "name", req.Name, "bytes", n)
}
