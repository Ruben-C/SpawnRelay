package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/protocol"
	"github.com/hashicorp/yamux"
)

// Self-update: the server pushes an "update" control message naming a binary
// it serves, its size and SHA-256. The client fetches it over a stream of
// the same pinned tunnel, verifies size and hash, checks that the file runs
// and reports the expected version, swaps it into place and restarts itself
// (exec on unix, a detached child on Windows). Progress goes back to the
// server as "update_status" messages so the UI can show it.

const maxBinarySize = 256 << 20

// updateState guards against overlapping updates within one process.
var updating atomic.Bool

func (c *conn) sendStatus(status, message string) {
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()
	_ = c.ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = protocol.WriteJSONLine(c.ctrl, protocol.ControlMessage{Type: "update_status", Status: status, Message: message})
	_ = c.ctrl.SetWriteDeadline(time.Time{})
}

// runUpdate is started in its own goroutine when an update message arrives.
func (c *conn) runUpdate(ctx context.Context, info protocol.UpdateInfo) {
	log := c.log
	if !c.cfg.AllowUpdate {
		log.Warn("server pushed an update but updates are disabled on this client", "version", info.Version)
		c.sendStatus("failed", "updates are disabled on this client")
		return
	}
	if !updating.CompareAndSwap(false, true) {
		c.sendStatus("failed", "an update is already in progress")
		return
	}
	defer updating.Store(false)

	err := c.doUpdate(ctx, info)
	if err != nil {
		log.Error("update failed", "version", info.Version, "error", err)
		c.sendStatus("failed", err.Error())
	}
}

func (c *conn) doUpdate(ctx context.Context, info protocol.UpdateInfo) error {
	log := c.log
	if info.Version != "" && info.Version == c.cfg.Version {
		return fmt.Errorf("already running %s", info.Version)
	}
	exe, err := currentExecutable()
	if err != nil {
		return err
	}
	log.Info("update requested", "version", info.Version, "asset", info.Name, "size", info.Size, "current", c.cfg.Version, "executable", exe)

	c.sendStatus("downloading", fmt.Sprintf("downloading %s (%d bytes)", info.Name, info.Size))
	tmp := filepath.Join(filepath.Dir(exe), fmt.Sprintf(".spawnrelay.new-%d", os.Getpid()))
	if err := c.download(ctx, info, tmp); err != nil {
		os.Remove(tmp)
		return err
	}

	c.sendStatus("installing", "verifying the new binary")
	if err := verifyBinary(ctx, tmp, info.Version); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := installBinary(tmp, exe); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install: %w", err)
	}
	log.Info("update installed; restarting", "version", info.Version, "executable", exe)
	c.sendStatus("restarting", "installed "+info.Version+", restarting")
	time.Sleep(300 * time.Millisecond) // let the status message leave the socket
	return restart(exe, os.Args)
}

// download fetches info.Name over a new tunnel stream into path, checking
// size and hash against both the update message and the stream header.
func (c *conn) download(ctx context.Context, info protocol.UpdateInfo, path string) error {
	if info.Size <= 0 || info.Size > maxBinarySize {
		return fmt.Errorf("refusing update with size %d", info.Size)
	}
	stream, err := c.sess.OpenStream()
	if err != nil {
		return fmt.Errorf("open download stream: %w", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Minute))
	if err := protocol.WriteJSONLine(stream, protocol.ClientRequest{Type: "download", Name: info.Name}); err != nil {
		return fmt.Errorf("request download: %w", err)
	}
	br := protocol.NewReader(stream)
	var resp protocol.DownloadResponse
	if err := protocol.ReadJSONLine(br, &resp); err != nil {
		return fmt.Errorf("read download response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("server refused download: %s", resp.Error)
	}
	if resp.Size != info.Size || !strings.EqualFold(resp.SHA256, info.SHA256) {
		return errors.New("server's download header does not match the update announcement")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(br, info.Size))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n != info.Size {
		return fmt.Errorf("download truncated: got %d of %d bytes", n, info.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, info.SHA256) {
		return fmt.Errorf("sha256 mismatch: got %s, expected %s", got, info.SHA256)
	}
	return nil
}

// verifyBinary runs "<path> version" and checks the output.
func verifyBinary(ctx context.Context, path, expected string) error {
	if err := os.Chmod(path, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("new binary does not run: %v: %s", err, strings.TrimSpace(out.String()))
	}
	got := strings.TrimSpace(out.String())
	if got == "" {
		return errors.New("new binary printed no version")
	}
	if expected != "" && got != expected {
		return fmt.Errorf("new binary reports version %q, expected %q", got, expected)
	}
	return nil
}

// installBinary moves the verified file over the running executable.
func installBinary(tmp, exe string) error {
	if runtime.GOOS == "windows" {
		// A running executable can be renamed but not overwritten.
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return err
		}
		if err := os.Rename(tmp, exe); err != nil {
			_ = os.Rename(old, exe)
			return err
		}
		return nil
	}
	return os.Rename(tmp, exe) // atomic; the running process keeps its old inode
}

func currentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot determine own executable: %w", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, nil
}

// cleanupUpdateLeftovers removes files a previous update left behind.
func cleanupUpdateLeftovers(log *slog.Logger) {
	exe, err := currentExecutable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	if runtime.GOOS == "windows" {
		if err := os.Remove(exe + ".old"); err == nil {
			log.Debug("removed previous binary", "path", exe+".old")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".spawnrelay.new-") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// conn is the live state of one tunnel session, shared with the update code.
type conn struct {
	cfg    Config
	log    *slog.Logger
	sess   *yamux.Session
	ctrl   *yamux.Stream
	ctrlMu sync.Mutex // serialises writes on the control stream
}
