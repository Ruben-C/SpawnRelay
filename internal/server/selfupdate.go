package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/agent"
)

// Server self-update: the server watches GitHub releases, downloads and
// verifies the client binaries it will serve afterwards, and then asks the
// root agent to install the matching server binary and restart it. The agent
// downloads the server binary on its own from nothing but the tag, keeps the
// previous binary, and rolls back when the new server does not come up.

const (
	DefaultUpdateRepo = "Ruben-C/SpawnRelay"
	releaseCheckEvery = time.Hour
	stalePendingAfter = 15 * time.Minute // a pending record older than this is a crashed update
	stagingKeepFor    = 7 * 24 * time.Hour
	updatesDir        = "updates"
)

// clientPlatforms are the client binaries a release ships (see Makefile PLATFORMS).
var clientPlatforms = []string{
	"linux_amd64", "linux_arm64", "linux_arm", "darwin_amd64", "darwin_arm64",
	"windows_amd64.exe", "windows_arm64.exe", "freebsd_amd64",
}

type selfUpdater struct {
	version string
	repo    string
	dataDir string
	log     interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
		Error(msg string, args ...any)
	}
	agentSocket func() (path string, legacy bool)

	apiBase    string                             // GitHub API base (tests override)
	releaseURL func(version, asset string) string // asset download URL (tests override)
	client     *http.Client

	mu        sync.Mutex
	latest    string
	checkedAt time.Time
	checkErr  string
	local     *agent.UpdateRecord // the download stage, before the agent takes over
	busy      bool
}

func newSelfUpdater(s *Server, repo string) *selfUpdater {
	if repo == "" {
		repo = DefaultUpdateRepo
	}
	return &selfUpdater{
		version: s.cfg.Version, repo: repo, dataDir: s.cfg.DataDir, log: s.log,
		agentSocket: s.firewall.socketPath,
		apiBase:     "https://api.github.com",
		releaseURL:  func(version, asset string) string { return agent.ReleaseURL(repo, version, asset) },
		client:      &http.Client{Timeout: 10 * time.Minute},
	}
}

// ---- versions ------------------------------------------------------------

// parseVersion reads vMAJOR.MINOR.PATCH.
func parseVersion(v string) (parts [3]int, ok bool) {
	if !agent.ValidTag.MatchString(v) {
		return parts, false
	}
	for i, p := range strings.Split(strings.TrimPrefix(v, "v"), ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}

// newerVersion reports whether a is a release newer than b.
func newerVersion(a, b string) bool {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

// ---- release check --------------------------------------------------------

// check refreshes the latest release tag.
func (u *selfUpdater) check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tag, err := u.fetchLatest(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.checkedAt = time.Now()
	if err != nil {
		u.checkErr = err.Error()
		u.log.Warn("release check failed", "repo", u.repo, "error", err)
		return
	}
	u.checkErr = ""
	if tag != u.latest {
		u.log.Info("latest release", "repo", u.repo, "version", tag, "running", u.version)
	}
	u.latest = tag
}

func (u *selfUpdater) fetchLatest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.apiBase+"/repos/"+u.repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SpawnRelay/"+u.version)
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub answered HTTP %d", resp.StatusCode)
	}
	var body struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("bad release response: %w", err)
	}
	if !agent.ValidTag.MatchString(body.Tag) {
		return "", fmt.Errorf("latest release has an unexpected tag %q", body.Tag)
	}
	return body.Tag, nil
}

// run checks on start and then periodically until ctx is done.
func (u *selfUpdater) run(ctx context.Context) {
	u.check(ctx)
	t := time.NewTicker(releaseCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.check(ctx)
		}
	}
}

// availability reports whether a newer release is known, and why not.
func (u *selfUpdater) availability() (available bool, latest, reason string) {
	u.mu.Lock()
	latest, checkErr := u.latest, u.checkErr
	u.mu.Unlock()
	if _, ok := parseVersion(u.version); !ok {
		return false, latest, "this is a development build; updates are paused until it runs a release version"
	}
	if latest == "" {
		if checkErr != "" {
			return false, "", "could not check for releases: " + checkErr
		}
		return false, "", "no release information yet"
	}
	if !newerVersion(latest, u.version) {
		return false, latest, "already on the latest release"
	}
	return true, latest, ""
}

// supported reports whether an agent that can install updates is reachable.
func (u *selfUpdater) supported(ctx context.Context) (ok bool, reason string, socket string) {
	socket, legacy := u.agentSocket()
	switch {
	case !agent.Available(socket):
		return false, "the agent is not installed on this host (re-run the server installer)", socket
	case legacy:
		return false, "the agent is older than the server; re-run the server installer", socket
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := agent.Status(ctx, socket)
	if err != nil {
		return false, "the agent did not answer: " + err.Error(), socket
	}
	if !st.CanUpdate {
		return false, "the agent is not configured to install updates; re-run the server installer", socket
	}
	return true, "", socket
}

// last returns the most recent update record, from the agent's file or from
// the download stage this process is running.
func (u *selfUpdater) last() *agent.UpdateRecord {
	u.mu.Lock()
	local := u.local
	u.mu.Unlock()
	rec := agent.ReadRecord(u.dataDir)
	if local != nil && (rec == nil || !rec.StartedAt.After(local.StartedAt)) {
		cp := *local
		rec = &cp
	}
	if rec != nil && rec.State == agent.UpdatePending && time.Since(rec.StartedAt) > stalePendingAfter {
		rec.State = agent.UpdateFailed
		rec.Detail = "update did not finish: " + rec.Detail
	}
	return rec
}

// ---- API -------------------------------------------------------------------

type updateOutServer struct {
	RunningVersion string              `json:"running_version"`
	LatestVersion  string              `json:"latest_version,omitempty"`
	CheckedAt      *time.Time          `json:"checked_at,omitempty"`
	CheckError     string              `json:"check_error,omitempty"`
	Available      bool                `json:"available"`
	Reason         string              `json:"reason,omitempty"`
	Supported      bool                `json:"supported"`
	InstallCommand string              `json:"install_command"`
	Last           *agent.UpdateRecord `json:"last"`
}

func (u *selfUpdater) installCommand() string {
	return "curl -fsSL https://raw.githubusercontent.com/" + u.repo + "/main/scripts/install-server.sh | sudo bash"
}

func (u *selfUpdater) out(ctx context.Context) updateOutServer {
	available, latest, reason := u.availability()
	supported, why, _ := u.supported(ctx)
	if reason == "" && !supported {
		reason = why
	}
	u.mu.Lock()
	checkedAt, checkErr := u.checkedAt, u.checkErr
	u.mu.Unlock()
	out := updateOutServer{
		RunningVersion: u.version, LatestVersion: latest, CheckError: checkErr, Available: available, Reason: reason,
		Supported: supported, InstallCommand: u.installCommand(), Last: u.last(),
	}
	if !checkedAt.IsZero() {
		out.CheckedAt = &checkedAt
	}
	return out
}

// statusOut is the compact form embedded in GET /status.
func (u *selfUpdater) statusOut() map[string]any {
	available, latest, _ := u.availability()
	out := map[string]any{"available": available}
	if available {
		out["version"] = latest
	}
	return out
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.updater.out(r.Context()))
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	s.updater.check(r.Context())
	writeJSON(w, http.StatusOK, s.updater.out(r.Context()))
}

func (s *Server) handleUpdateStart(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version   string `json:"version"`
		Reinstall bool   `json:"reinstall"`
	}
	if r.ContentLength != 0 && !readJSON(w, r, &in) {
		return
	}
	code, err := s.updater.start(r.Context(), in.Version, in.Reinstall)
	if err != nil {
		writeError(w, code, err.Error())
		return
	}
	s.log.Warn("server update started", "target", in.Version, "by", principalFrom(r).Name)
	writeJSON(w, http.StatusAccepted, s.updater.out(r.Context()))
}

// start validates the request and begins the update; it returns the HTTP
// status to use on failure.
func (u *selfUpdater) start(ctx context.Context, version string, reinstall bool) (int, error) {
	available, latest, reason := u.availability()
	switch {
	case version == "":
		if !available {
			return http.StatusConflict, errors.New(reason)
		}
		version = latest
	case version == u.version && reinstall:
		if _, ok := parseVersion(version); !ok {
			return http.StatusBadRequest, errors.New("a development build cannot be reinstalled from a release")
		}
	case version == latest && available:
	case !agent.ValidTag.MatchString(version):
		return http.StatusBadRequest, fmt.Errorf("%q is not a release tag (expected vMAJOR.MINOR.PATCH)", version)
	case version == u.version:
		return http.StatusBadRequest, errors.New("already running " + version + "; pass reinstall to install it again")
	case !newerVersion(version, u.version):
		return http.StatusBadRequest, fmt.Errorf("%s is older than the running %s; downgrades are not installed", version, u.version)
	default:
		return http.StatusBadRequest, fmt.Errorf("%s is not the latest release (%s)", version, latest)
	}
	if ok, why, _ := u.supported(ctx); !ok {
		return http.StatusConflict, errors.New(why)
	}
	if rec := u.last(); rec != nil && rec.State == agent.UpdatePending {
		return http.StatusConflict, errors.New("an update is already in progress")
	}
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return http.StatusConflict, errors.New("an update is already in progress")
	}
	u.busy = true
	u.local = &agent.UpdateRecord{State: agent.UpdatePending, From: u.version, To: version, Detail: "downloading client binaries", StartedAt: time.Now()}
	u.mu.Unlock()
	go u.stageAndInstall(context.WithoutCancel(ctx), version)
	return 0, nil
}

func (u *selfUpdater) setLocal(state, detail string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.local != nil {
		u.local.State = state
		u.local.Detail = detail
		if state != agent.UpdatePending {
			u.local.FinishedAt = time.Now()
		}
	}
}

// stageAndInstall downloads the client binaries into the staging directory,
// then hands the tag to the agent.
func (u *selfUpdater) stageAndInstall(ctx context.Context, version string) {
	defer func() {
		u.mu.Lock()
		u.busy = false
		u.mu.Unlock()
	}()
	if err := u.stageClientBinaries(ctx, version); err != nil {
		u.log.Error("server update failed", "version", version, "error", err)
		u.setLocal(agent.UpdateFailed, err.Error())
		return
	}
	u.setLocal(agent.UpdatePending, "asking the agent to install "+version)
	_, socket := "", ""
	if ok, why, sock := u.supported(ctx); !ok {
		u.setLocal(agent.UpdateFailed, why)
		return
	} else {
		socket = sock
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := agent.Update(ctx, socket, version); err != nil {
		u.log.Error("agent refused the update", "version", version, "error", err)
		u.setLocal(agent.UpdateFailed, "agent: "+err.Error())
		return
	}
	// From here the agent's record file is the source of truth.
	u.mu.Lock()
	u.local = nil
	u.mu.Unlock()
	u.log.Info("update handed to the agent; the server will be restarted", "version", version)
}

// stageClientBinaries downloads every client binary of the release into
// <data-dir>/updates/<version>/, verified against SHA256SUMS. On any error
// the staging directory is removed.
func (u *selfUpdater) stageClientBinaries(ctx context.Context, version string) error {
	dir := filepath.Join(u.dataDir, updatesDir, version)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	err := func() error {
		sumsRaw, err := u.download(ctx, u.releaseURL(version, "SHA256SUMS"))
		if err != nil {
			return fmt.Errorf("SHA256SUMS: %w", err)
		}
		sums := agent.ParseSums(sumsRaw)
		for _, p := range clientPlatforms {
			name := "spawnrelay_" + p
			u.setLocal(agent.UpdatePending, "downloading "+name)
			b, err := u.download(ctx, u.releaseURL(version, name))
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if err := agent.VerifySum(sums, name, b); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, name), b, 0o755); err != nil {
				return err
			}
		}
		return nil
	}()
	if err != nil {
		_ = os.RemoveAll(dir)
	}
	return err
}

func (u *selfUpdater) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SpawnRelay/"+u.version)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512<<20))
}

// adoptStaged moves client binaries staged for the running version into the
// served bin directory and prunes old staging directories. Called at startup,
// so binaries only ever switch once the matching server version runs.
func (u *selfUpdater) adoptStaged() {
	root := filepath.Join(u.dataDir, updatesDir)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if e.Name() == u.version {
			binDir := filepath.Join(u.dataDir, "bin")
			if err := os.MkdirAll(binDir, 0o755); err != nil {
				u.log.Error("cannot create bin directory", "error", err)
				continue
			}
			files, _ := os.ReadDir(dir)
			moved := 0
			for _, f := range files {
				if !strings.HasPrefix(f.Name(), "spawnrelay_") {
					continue
				}
				if err := os.Rename(filepath.Join(dir, f.Name()), filepath.Join(binDir, f.Name())); err != nil {
					u.log.Error("cannot adopt client binary", "file", f.Name(), "error", err)
					continue
				}
				moved++
			}
			u.log.Info("adopted client binaries for this version", "version", u.version, "count", moved)
			_ = os.RemoveAll(dir)
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > stagingKeepFor {
			_ = os.RemoveAll(dir)
		}
	}
}
