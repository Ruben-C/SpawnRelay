package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Update states.
const (
	UpdatePending    = "pending"
	UpdateDone       = "done"
	UpdateFailed     = "failed"
	UpdateRolledBack = "rolled_back"
)

// RecordFile is the name of the update record inside the data directory.
const RecordFile = "server-update.json"

// UpdateRecord is the last server update attempt, persisted in the data
// directory so the server can show it after it has been restarted.
type UpdateRecord struct {
	State      string    `json:"state"` // pending | done | failed | rolled_back
	From       string    `json:"from"`
	To         string    `json:"to"`
	Detail     string    `json:"detail,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
}

// ReadRecord loads the update record from dataDir; nil when there is none.
func ReadRecord(dataDir string) *UpdateRecord {
	b, err := os.ReadFile(filepath.Join(dataDir, RecordFile))
	if err != nil {
		return nil
	}
	var rec UpdateRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.State == "" {
		return nil
	}
	return &rec
}

// ValidTag matches the release tags the agent will install.
var ValidTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// Updater installs server releases. Exported fields are configuration; the
// function fields are hooks that tests replace.
type Updater struct {
	Repo       string // GitHub repository, owner/name
	BinPath    string // the installed binary, e.g. /usr/local/bin/spawnrelay
	DataDir    string // where the record file goes
	ServerUnit string // systemd unit of the relay server
	AgentUnit  string // systemd unit of this agent
	AdminAddr  string // the server's admin listen address, for the health probe
	Arch       string // GOARCH of the binary to install; defaults to runtime.GOARCH
	Version    string // running agent version (the "from" of an update)
	Timeout    time.Duration
	Logger     *slog.Logger

	// Download fetches url; defaults to an HTTP GET with a 10 minute timeout.
	Download func(ctx context.Context, url string) ([]byte, error)
	// Run executes a command; defaults to exec.CommandContext.
	Run func(ctx context.Context, name string, args ...string) error
	// Probe returns the version the server reports at its health endpoint.
	Probe func(ctx context.Context) (string, error)
	// VerifyBinary checks that the file at path prints version when asked.
	VerifyBinary func(ctx context.Context, path, version string) error

	mu   sync.Mutex
	busy bool
	last *UpdateRecord
}

func (u *Updater) init(cfg Config) {
	if u.Logger == nil {
		u.Logger = cfg.Logger
	}
	if u.DataDir == "" {
		u.DataDir = cfg.DataDir
	}
	if u.Version == "" {
		u.Version = cfg.Version
	}
	if u.Arch == "" {
		u.Arch = runtime.GOARCH
	}
	if u.Timeout == 0 {
		u.Timeout = 60 * time.Second
	}
	if u.Download == nil {
		u.Download = httpDownload
	}
	if u.Run == nil {
		u.Run = func(ctx context.Context, name string, args ...string) error {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}
	if u.Probe == nil {
		u.Probe = u.httpProbe
	}
	if u.VerifyBinary == nil {
		u.VerifyBinary = verifyBinary
	}
	u.last = ReadRecord(u.DataDir)
}

// Last returns the most recent update record.
func (u *Updater) Last() *UpdateRecord {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.last == nil {
		return nil
	}
	rec := *u.last
	return &rec
}

// Start validates version and begins installing it in the background. It
// returns the pending record, or an error when the request is refused.
func (u *Updater) Start(ctx context.Context, version string) (*UpdateRecord, error) {
	if !ValidTag.MatchString(version) {
		return nil, fmt.Errorf("invalid release tag %q", version)
	}
	if u.Repo == "" || u.BinPath == "" || u.ServerUnit == "" {
		return nil, errors.New("agent is not configured for updates")
	}
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return nil, errors.New("an update is already in progress")
	}
	u.busy = true
	rec := &UpdateRecord{State: UpdatePending, From: u.Version, To: version, Detail: "downloading", StartedAt: time.Now()}
	u.last = rec
	u.mu.Unlock()
	u.persist()
	// Detach from the request context: the connection closes right after
	// the reply, and the server that asked is about to be restarted.
	go u.run(context.WithoutCancel(ctx), version)
	out := *rec
	return &out, nil
}

func (u *Updater) set(state, detail string) {
	u.mu.Lock()
	u.last.State = state
	u.last.Detail = detail
	if state != UpdatePending {
		u.last.FinishedAt = time.Now()
	}
	u.mu.Unlock()
	u.persist()
}

func (u *Updater) persist() {
	u.mu.Lock()
	rec := *u.last
	u.mu.Unlock()
	b, _ := json.MarshalIndent(rec, "", "  ")
	path := filepath.Join(u.DataDir, RecordFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		u.Logger.Error("cannot write update record", "path", path, "error", err)
		return
	}
	_ = os.Rename(tmp, path)
}

func (u *Updater) run(ctx context.Context, version string) {
	defer func() {
		u.mu.Lock()
		u.busy = false
		u.mu.Unlock()
	}()
	log := u.Logger.With("version", version)
	fail := func(state, detail string, err error) {
		if err != nil {
			detail = detail + ": " + err.Error()
		}
		log.Error("server update failed", "state", state, "detail", detail)
		u.set(state, detail)
	}

	// 1. Download and verify.
	binary, err := u.fetchBinary(ctx, version)
	if err != nil {
		fail(UpdateFailed, "download", err)
		return
	}
	u.set(UpdatePending, "installing")
	newPath := u.BinPath + ".new"
	if err := os.WriteFile(newPath, binary, 0o755); err != nil {
		fail(UpdateFailed, "write binary", err)
		return
	}
	if err := u.VerifyBinary(ctx, newPath, version); err != nil {
		_ = os.Remove(newPath)
		fail(UpdateFailed, "verify binary", err)
		return
	}

	// 2. Swap: exactly one previous binary is kept.
	prev := u.BinPath + ".previous"
	_ = os.Remove(prev)
	if err := os.Rename(u.BinPath, prev); err != nil {
		_ = os.Remove(newPath)
		fail(UpdateFailed, "keep previous binary", err)
		return
	}
	if err := os.Rename(newPath, u.BinPath); err != nil {
		_ = os.Rename(prev, u.BinPath)
		fail(UpdateFailed, "install binary", err)
		return
	}

	// 3. Restart the server and wait for it to come back on the new version.
	u.set(UpdatePending, "restarting")
	log.Info("binary installed; restarting server", "unit", u.ServerUnit)
	if err := u.Run(ctx, "systemctl", "restart", u.ServerUnit); err != nil {
		u.rollback(ctx, "restart failed", err)
		return
	}
	if err := u.waitHealthy(ctx, version); err != nil {
		u.rollback(ctx, "new server did not become healthy", err)
		return
	}
	u.set(UpdateDone, "updated to "+version)
	log.Info("server updated", "from", u.Version)

	// 4. Restart ourselves, after the record is written, so the agent runs
	// the new version too. The transient unit outlives this process.
	if u.AgentUnit != "" {
		if err := u.Run(ctx, "systemd-run", "--quiet", "--on-active=2", "systemctl", "restart", u.AgentUnit); err != nil {
			log.Warn("could not schedule agent restart; restart it by hand", "unit", u.AgentUnit, "error", err)
		}
	}
}

func (u *Updater) rollback(ctx context.Context, why string, cause error) {
	u.Logger.Error("rolling back server update", "reason", why, "error", cause)
	prev := u.BinPath + ".previous"
	detail := why + ": " + cause.Error()
	if err := os.Rename(prev, u.BinPath); err != nil {
		u.set(UpdateFailed, detail+" (and the previous binary could not be restored: "+err.Error()+")")
		return
	}
	if err := u.Run(ctx, "systemctl", "restart", u.ServerUnit); err != nil {
		u.set(UpdateFailed, detail+" (previous binary restored, but restarting it failed: "+err.Error()+")")
		return
	}
	u.set(UpdateRolledBack, detail+"; previous version restored")
}

// waitHealthy polls the server until it reports version or the timeout passes.
func (u *Updater) waitHealthy(ctx context.Context, version string) error {
	deadline := time.Now().Add(u.Timeout)
	var last error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		got, err := u.Probe(ctx)
		switch {
		case err != nil:
			last = err
		case got == version:
			return nil
		default:
			last = fmt.Errorf("server reports version %q", got)
		}
	}
	if last == nil {
		last = errors.New("no answer")
	}
	return fmt.Errorf("after %s: %w", u.Timeout, last)
}

// ReleaseURL is the download URL of one asset of a release.
func ReleaseURL(repo, version, asset string) string {
	return "https://github.com/" + repo + "/releases/download/" + version + "/" + asset
}

// ParseSums parses a sha256sum-style checksum file into name -> hex hash.
func ParseSums(b []byte) map[string]string {
	sums := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		sums[strings.TrimPrefix(f[1], "*")] = strings.ToLower(f[0])
	}
	return sums
}

// VerifySum checks data against the entry for name in sums.
func VerifySum(sums map[string]string, name string, data []byte) error {
	want, ok := sums[name]
	if !ok {
		return fmt.Errorf("%s is not listed in SHA256SUMS", name)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	return nil
}

// fetchBinary downloads the release tarball for this platform, verifies it
// against the release's SHA256SUMS and returns the contained binary.
func (u *Updater) fetchBinary(ctx context.Context, version string) ([]byte, error) {
	sumsRaw, err := u.Download(ctx, ReleaseURL(u.Repo, version, "SHA256SUMS"))
	if err != nil {
		return nil, fmt.Errorf("SHA256SUMS: %w", err)
	}
	sums := ParseSums(sumsRaw)
	asset := "spawnrelay_linux_" + u.Arch + ".tar.gz"
	tarball, err := u.Download(ctx, ReleaseURL(u.Repo, version, asset))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", asset, err)
	}
	if err := VerifySum(sums, asset, tarball); err != nil {
		return nil, err
	}
	return extractBinary(tarball)
}

// extractBinary returns the "spawnrelay" file from a .tar.gz.
func extractBinary(tarball []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("tarball: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("tarball does not contain spawnrelay")
		}
		if err != nil {
			return nil, fmt.Errorf("tarball: %w", err)
		}
		if filepath.Base(h.Name) == "spawnrelay" && h.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 512<<20))
		}
	}
}

func httpDownload(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512<<20))
}

// httpProbe asks the server's health endpoint which version it runs.
func (u *Updater) httpProbe(ctx context.Context) (string, error) {
	addr := u.AdminAddr
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/api/v1/health", nil)
	if err != nil {
		return "", err
	}
	resp, err := insecureClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return "", err
	}
	return body.Version, nil
}

// verifyBinary runs "<path> version" and checks the output.
func verifyBinary(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}
	got := strings.TrimSpace(string(out))
	if got != version {
		return fmt.Errorf("new binary reports version %q, expected %q", got, version)
	}
	return nil
}

// insecureClient talks to the local admin listener, whose certificate is
// usually self-signed.
var insecureClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
