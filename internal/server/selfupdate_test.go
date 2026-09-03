package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/agent"
	"github.com/Ruben-C/SpawnRelay/internal/store"
)

func TestVersionRules(t *testing.T) {
	if !newerVersion("v0.5.0", "v0.4.9") || !newerVersion("v1.0.0", "v0.99.99") || newerVersion("v0.4.0", "v0.4.0") || newerVersion("v0.3.9", "v0.4.0") {
		t.Fatal("version ordering")
	}
	if newerVersion("v0.5.0", "dev") || newerVersion("latest", "v0.1.0") || newerVersion("v0.5.0-rc1", "v0.4.0") {
		t.Fatal("unparseable versions must never compare as newer")
	}
}

// fakeRelease is a GitHub stand-in: the releases API plus asset downloads.
type fakeRelease struct {
	srv     *httptest.Server
	tag     string
	assets  map[string][]byte
	corrupt string // asset whose checksum is wrong
}

func newFakeRelease(t *testing.T, tag string) *fakeRelease {
	f := &fakeRelease{tag: tag, assets: map[string][]byte{}}
	for _, p := range clientPlatforms {
		f.assets["spawnrelay_"+p] = []byte("client " + p + " " + tag)
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/o/r/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": f.tag})
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
			var sb strings.Builder
			for name, b := range f.assets {
				sum := sha256.Sum256(b)
				hash := hex.EncodeToString(sum[:])
				if name == f.corrupt {
					hash = strings.Repeat("0", 64)
				}
				fmt.Fprintf(&sb, "%s  %s\n", hash, name)
			}
			_, _ = io.WriteString(w, sb.String())
		default:
			name := filepath.Base(r.URL.Path)
			if b, ok := f.assets[name]; ok {
				_, _ = w.Write(b)
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// sessionClient logs in through the real login endpoint and sends the cookie.
type sessionClient struct {
	t      *testing.T
	h      http.Handler
	cookie string
}

func newSessionClient(t *testing.T, s *Server) *sessionClient {
	t.Helper()
	pw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "initial-admin-password"))
	if err != nil {
		t.Fatal(err)
	}
	c := &sessionClient{t: t, h: s.routes()}
	body := fmt.Sprintf(`{"username":"admin","password":%q}`, strings.TrimSpace(string(pw)))
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	c.cookie = strings.Split(rec.Header().Get("Set-Cookie"), ";")[0]
	return c
}

func (c *sessionClient) do(method, path, body string, out any) (int, string) {
	c.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Cookie", c.cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+req.Host)
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: decode %v: %s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, rec.Body.String()
}

func newUpdateServer(t *testing.T, version string, rel *fakeRelease) *Server {
	t.Helper()
	// Relative data dir: the agent socket inside it must stay under the unix
	// socket path limit.
	t.Chdir(t.TempDir())
	s, err := New(Config{DataDir: "d", TunnelAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0", PublicHost: "relay.test",
		Version: version, UpdateRepo: "o/r", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.tunnel.Shutdown)
	s.updater.apiBase = rel.srv.URL
	s.updater.releaseURL = func(version, asset string) string { return rel.srv.URL + "/download/" + version + "/" + asset }
	return s
}

// startFakeAgent runs a real agent on the server's socket path with fake
// system hooks, so the whole request path is exercised.
func startFakeAgent(t *testing.T, s *Server, rel *fakeRelease, probeVersion string) *agent.Updater {
	t.Helper()
	dir := s.cfg.DataDir
	bin := filepath.Join(dir, "spawnrelay-bin")
	_ = os.WriteFile(bin, []byte("old"), 0o755)
	tarball := map[string][]byte{}
	u := &agent.Updater{
		Repo: "o/r", BinPath: bin, DataDir: dir, ServerUnit: "srv", AgentUnit: "", Arch: "amd64", Version: s.cfg.Version, Timeout: time.Second,
		Download: func(ctx context.Context, url string) ([]byte, error) {
			// The agent verifies its tarball against SHA256SUMS; give it a tarball whose hash is listed.
			if strings.HasSuffix(url, "SHA256SUMS") {
				sum := sha256.Sum256(tarball["tgz"])
				return []byte(hex.EncodeToString(sum[:]) + "  spawnrelay_linux_amd64.tar.gz\n"), nil
			}
			return tarball["tgz"], nil
		},
		Run:          func(ctx context.Context, name string, args ...string) error { return nil },
		Probe:        func(ctx context.Context) (string, error) { return probeVersion, nil },
		VerifyBinary: func(ctx context.Context, path, version string) error { return nil },
	}
	tarball["tgz"] = tgzWith(t, "spawnrelay", []byte("new"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.Serve(ctx, agent.Config{Socket: filepath.Join(dir, "agent.sock"), DataDir: dir, Version: s.cfg.Version,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Updater: u})
	}()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 50 && !agent.Available(filepath.Join(dir, "agent.sock")); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	return u
}

func TestServerUpdateFlow(t *testing.T) {
	if os.Getenv("CI_NO_UNIX_SOCKETS") != "" {
		t.Skip()
	}
	rel := newFakeRelease(t, "v0.5.0")
	s := newUpdateServer(t, "v0.4.0", rel)
	s.updater.check(context.Background())

	// Status carries the indicator.
	c := newSessionClient(t, s)
	var status map[string]any
	c.do("GET", "/api/v1/status", "", &status)
	su := status["server_update"].(map[string]any)
	if su["available"] != true || su["version"] != "v0.5.0" {
		t.Fatalf("status.server_update = %v", su)
	}

	// Tokens are refused; sessions are required.
	tok := store.NewAPIToken()
	_ = s.store.Update(func(st *store.State) error {
		st.Tokens = append(st.Tokens, &store.APIToken{ID: "t", Name: "t", TokenHash: store.HashToken(tok)})
		return nil
	})
	req := httptest.NewRequest("POST", "/api/v1/server/update", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token must be refused: %d", rec.Code)
	}

	// Without an agent: reported, not startable.
	var out updateOutServer
	c.do("GET", "/api/v1/server/update", "", &out)
	if !out.Available || out.Supported || out.LatestVersion != "v0.5.0" || !strings.Contains(out.InstallCommand, "install-server.sh") || out.Reason == "" {
		t.Fatalf("unsupported: %+v", out)
	}
	if code, body := c.do("POST", "/api/v1/server/update", "", nil); code != http.StatusConflict || !strings.Contains(body, "agent") {
		t.Fatalf("no agent: %d %s", code, body)
	}
	// Guards.
	for body, want := range map[string]string{
		`{"version":"v0.3.0"}`: "older", `{"version":"v0.4.0"}`: "reinstall", `{"version":"v0.4.5"}`: "not the latest", `{"version":"nope"}`: "not a release tag",
	} {
		if code, resp := c.do("POST", "/api/v1/server/update", body, nil); code != http.StatusBadRequest || !strings.Contains(resp, want) {
			t.Fatalf("%s: %d %s", body, code, resp)
		}
	}

	// With an agent: the update runs end to end.
	startFakeAgent(t, s, rel, "v0.5.0")
	c.do("GET", "/api/v1/server/update", "", &out)
	if !out.Supported {
		t.Fatalf("supported: %+v", out)
	}
	if code, body := c.do("POST", "/api/v1/server/update", "", &out); code != http.StatusAccepted || out.Last == nil || out.Last.State != agent.UpdatePending {
		t.Fatalf("start: %d %s", code, body)
	}
	if code, body := c.do("POST", "/api/v1/server/update", "", nil); code != http.StatusConflict {
		t.Fatalf("second start: %d %s", code, body)
	}
	var last *agent.UpdateRecord
	for i := 0; i < 200; i++ {
		last = s.updater.last()
		if last != nil && last.State != agent.UpdatePending {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if last == nil || last.State != agent.UpdateDone || last.To != "v0.5.0" {
		t.Fatalf("outcome: %+v", last)
	}
	staged := filepath.Join(s.cfg.DataDir, updatesDir, "v0.5.0")
	files, _ := os.ReadDir(staged)
	if len(files) != len(clientPlatforms) {
		t.Fatalf("staged %d client binaries, want %d", len(files), len(clientPlatforms))
	}

	// The new server adopts the staged client binaries on startup.
	s2 := &selfUpdater{version: "v0.5.0", dataDir: s.cfg.DataDir, log: s.log}
	s2.adoptStaged()
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatal("staging directory not removed")
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "bin", "spawnrelay_windows_amd64.exe"))
	if err != nil || string(b) != "client windows_amd64.exe v0.5.0" {
		t.Fatalf("adopted binary: %q %v", b, err)
	}
}

func TestServerUpdateRefusesCorruptClientBinary(t *testing.T) {
	if os.Getenv("CI_NO_UNIX_SOCKETS") != "" {
		t.Skip()
	}
	rel := newFakeRelease(t, "v0.5.0")
	rel.corrupt = "spawnrelay_linux_arm64"
	s := newUpdateServer(t, "v0.4.0", rel)
	s.updater.check(context.Background())
	u := startFakeAgent(t, s, rel, "v0.5.0")
	c := newSessionClient(t, s)
	if code, body := c.do("POST", "/api/v1/server/update", "", nil); code != http.StatusAccepted {
		t.Fatalf("start: %d %s", code, body)
	}
	var last *agent.UpdateRecord
	for i := 0; i < 200; i++ {
		if last = s.updater.last(); last != nil && last.State != agent.UpdatePending {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if last == nil || last.State != agent.UpdateFailed || !strings.Contains(last.Detail, "checksum mismatch") {
		t.Fatalf("outcome: %+v", last)
	}
	if u.Last() != nil {
		t.Fatal("agent must not be asked to install when client binaries fail verification")
	}
	if _, err := os.Stat(filepath.Join(s.cfg.DataDir, updatesDir, "v0.5.0")); !os.IsNotExist(err) {
		t.Fatal("staging directory must be removed after a failure")
	}
}

func TestDevBuildNeverUpdates(t *testing.T) {
	rel := newFakeRelease(t, "v0.5.0")
	s := newUpdateServer(t, "dev", rel)
	s.updater.check(context.Background())
	if ok, _, reason := s.updater.availability(); ok || !strings.Contains(reason, "development build") {
		t.Fatalf("dev availability: %v %q", ok, reason)
	}
	if code, err := s.updater.start(context.Background(), "", false); code != http.StatusConflict || err == nil {
		t.Fatalf("dev start: %d %v", code, err)
	}
}

// tgzWith builds a .tar.gz holding one file.
func tgzWith(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}
