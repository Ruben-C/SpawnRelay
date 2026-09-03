package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/firewall"
)

type fakeBackend struct{ got []firewall.Rule }

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) Sync(ctx context.Context, want []firewall.Rule) (*firewall.Result, error) {
	f.got = want
	res := &firewall.Result{Backend: "fake", Active: true, Rules: map[string]firewall.RuleState{}}
	for _, w := range want {
		res.Rules[w.Key()] = firewall.RuleState{State: firewall.StateOpen}
	}
	return res, nil
}

func startAgent(t *testing.T, cfg Config) (string, func()) {
	t.Helper()
	if os.Getenv("CI_NO_UNIX_SOCKETS") != "" {
		t.Skip()
	}
	// Unix socket paths are limited to ~100 bytes and t.TempDir() names are
	// long, so use a relative socket path from inside the temp directory.
	dir := t.TempDir()
	t.Chdir(dir)
	cfg.Socket = "a.sock"
	if cfg.DataDir == "" {
		cfg.DataDir = dir
	}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	if cfg.factory == nil {
		fb := &fakeBackend{}
		cfg.factory = func(ctx context.Context, mode string) (firewall.Backend, error) { return fb, nil }
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg) }()
	for i := 0; i < 50 && !Available(cfg.Socket); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !Available(cfg.Socket) {
		t.Fatal("agent did not start")
	}
	return cfg.Socket, func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		if Available(cfg.Socket) {
			t.Error("socket not cleaned up")
		}
	}
}

func TestAgentSyncAndStatus(t *testing.T) {
	fb := &fakeBackend{}
	sock, stop := startAgent(t, Config{Version: "test", factory: func(ctx context.Context, mode string) (firewall.Backend, error) { return fb, nil }})
	defer stop()
	ctx := context.Background()
	rules := []firewall.Rule{{ID: "tunnel", Port: 7443, Proto: "tcp"}, {ID: "abc", Port: 25565, Proto: "tcp"}}
	resp, err := Sync(ctx, sock, firewall.ModeAuto, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Backend != "fake" || resp.Rules["25565/tcp"].State != firewall.StateOpen || resp.Version != "test" || resp.CanUpdate {
		t.Fatalf("resp = %+v", resp)
	}
	if !reflect.DeepEqual(fb.got, rules) {
		t.Fatalf("backend got %v", fb.got)
	}
	if _, err := Sync(ctx, sock, firewall.ModeAuto, []firewall.Rule{{ID: "bad id!", Port: 1, Proto: "tcp"}}); err == nil || !strings.Contains(err.Error(), "invalid rule id") {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := Sync(ctx, sock, firewall.ModeOff, nil); err == nil {
		t.Fatal("mode off must be rejected by the agent")
	}
	st, err := Status(ctx, sock)
	if err != nil || st.Version != "test" || st.Update != nil || st.CanUpdate {
		t.Fatalf("status = %+v %v", st, err)
	}
	if _, err := Call(ctx, sock, Request{Op: "reboot"}); err == nil || !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("unknown op: %v", err)
	}
	if _, err := Update(ctx, sock, "v9.9.9"); err == nil || !strings.Contains(err.Error(), "cannot install updates") {
		t.Fatalf("update without updater: %v", err)
	}
}

// fakeRelease serves a release from memory through the Download hook.
type fakeRelease struct {
	files map[string][]byte
}

func newFakeRelease(version string, binary []byte, corruptSums bool) *fakeRelease {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "spawnrelay", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(binary)
	_ = tw.Close()
	_ = gz.Close()
	asset := "spawnrelay_linux_amd64.tar.gz"
	sum := sha256.Sum256(buf.Bytes())
	sums := hex.EncodeToString(sum[:])
	if corruptSums {
		sums = strings.Repeat("0", 64)
	}
	return &fakeRelease{files: map[string][]byte{
		ReleaseURL("o/r", version, asset):        buf.Bytes(),
		ReleaseURL("o/r", version, "SHA256SUMS"): []byte(sums + "  " + asset + "\n"),
	}}
}

func (f *fakeRelease) download(ctx context.Context, url string) ([]byte, error) {
	b, ok := f.files[url]
	if !ok {
		return nil, fmt.Errorf("HTTP 404")
	}
	return b, nil
}

type fakeSystem struct {
	mu       sync.Mutex
	calls    []string
	version  string // what the probe reports
	probeErr error
}

func (s *fakeSystem) run(ctx context.Context, name string, args ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	return nil
}

func (s *fakeSystem) probe(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, s.probeErr
}

func (s *fakeSystem) calledWith() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func newUpdater(t *testing.T, rel *fakeRelease, sys *fakeSystem, binVersion string) (*Updater, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "spawnrelay")
	if err := os.WriteFile(bin, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := &Updater{
		Repo: "o/r", BinPath: bin, DataDir: dir, ServerUnit: "srv.service", AgentUnit: "agent.service",
		Arch: "amd64", Version: "v0.4.0", Timeout: 2 * time.Second, Download: rel.download, Run: sys.run, Probe: sys.probe,
		VerifyBinary: func(ctx context.Context, path, version string) error {
			if binVersion != version {
				return fmt.Errorf("binary is %s", binVersion)
			}
			return nil
		},
	}
	return u, bin
}

func waitFinished(t *testing.T, u *Updater) *UpdateRecord {
	t.Helper()
	for i := 0; i < 200; i++ {
		if rec := u.Last(); rec != nil && rec.State != UpdatePending {
			return rec
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("update did not finish")
	return nil
}

func TestUpdaterInstallsAndRestarts(t *testing.T) {
	sys := &fakeSystem{version: "v0.5.0"}
	u, bin := newUpdater(t, newFakeRelease("v0.5.0", []byte("new-binary"), false), sys, "v0.5.0")
	sock, stop := startAgent(t, Config{Version: "v0.4.0", Updater: u, DataDir: u.DataDir})
	defer stop()
	// Leftover from an older update must be replaced, not accumulated.
	_ = os.WriteFile(bin+".previous", []byte("ancient"), 0o755)

	resp, err := Update(context.Background(), sock, "v0.5.0")
	if err != nil || resp.Update == nil || resp.Update.State != UpdatePending || !resp.CanUpdate {
		t.Fatalf("update accept: %+v %v", resp, err)
	}
	rec := waitFinished(t, u)
	if rec.State != UpdateDone || rec.From != "v0.4.0" || rec.To != "v0.5.0" {
		t.Fatalf("record: %+v", rec)
	}
	if b, _ := os.ReadFile(bin); string(b) != "new-binary" {
		t.Fatalf("binary not replaced: %q", b)
	}
	if b, _ := os.ReadFile(bin + ".previous"); string(b) != "old-binary" {
		t.Fatalf("previous not kept: %q", b)
	}
	calls := sys.calledWith()
	if len(calls) != 2 || calls[0] != "systemctl restart srv.service" || !strings.Contains(calls[1], "systemctl restart agent.service") {
		t.Fatalf("calls: %v", calls)
	}
	if got := ReadRecord(u.DataDir); got == nil || got.State != UpdateDone {
		t.Fatalf("record not persisted: %+v", got)
	}
	st, err := Status(context.Background(), sock)
	if err != nil || st.Update == nil || st.Update.State != UpdateDone {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestUpdaterRefusesBadChecksumAndTag(t *testing.T) {
	sys := &fakeSystem{version: "v0.5.0"}
	u, bin := newUpdater(t, newFakeRelease("v0.5.0", []byte("new-binary"), true), sys, "v0.5.0")
	sock, stop := startAgent(t, Config{Version: "v0.4.0", Updater: u, DataDir: u.DataDir})
	defer stop()
	for _, bad := range []string{"", "latest", "0.5.0", "v0.5.0; rm -rf /", "../v0.5.0"} {
		if _, err := Update(context.Background(), sock, bad); err == nil || !strings.Contains(err.Error(), "invalid release tag") {
			t.Fatalf("tag %q accepted: %v", bad, err)
		}
	}
	if _, err := Update(context.Background(), sock, "v0.5.0"); err != nil {
		t.Fatal(err)
	}
	rec := waitFinished(t, u)
	if rec.State != UpdateFailed || !strings.Contains(rec.Detail, "checksum mismatch") {
		t.Fatalf("record: %+v", rec)
	}
	if b, _ := os.ReadFile(bin); string(b) != "old-binary" {
		t.Fatal("binary touched despite checksum failure")
	}
	if len(sys.calledWith()) != 0 {
		t.Fatalf("nothing should have been restarted: %v", sys.calledWith())
	}
}

func TestUpdaterRollsBackWhenUnhealthy(t *testing.T) {
	sys := &fakeSystem{version: "v0.4.0", probeErr: errors.New("connection refused")}
	u, bin := newUpdater(t, newFakeRelease("v0.5.0", []byte("new-binary"), false), sys, "v0.5.0")
	sock, stop := startAgent(t, Config{Version: "v0.4.0", Updater: u, DataDir: u.DataDir})
	defer stop()
	if _, err := Update(context.Background(), sock, "v0.5.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(context.Background(), sock, "v0.5.0"); err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("concurrent update: %v", err)
	}
	rec := waitFinished(t, u)
	if rec.State != UpdateRolledBack || !strings.Contains(rec.Detail, "healthy") || !strings.Contains(rec.Detail, "connection refused") {
		t.Fatalf("record: %+v", rec)
	}
	if b, _ := os.ReadFile(bin); string(b) != "old-binary" {
		t.Fatalf("previous binary not restored: %q", b)
	}
	calls := sys.calledWith()
	if len(calls) != 2 || calls[0] != "systemctl restart srv.service" || calls[1] != "systemctl restart srv.service" {
		t.Fatalf("calls: %v", calls)
	}
}

func TestParseSumsAndVerify(t *testing.T) {
	data := []byte("hello")
	sum := sha256.Sum256(data)
	sums := ParseSums([]byte(hex.EncodeToString(sum[:]) + "  a.tar.gz\n" + strings.Repeat("0", 64) + " *b.exe\n\nnot a line\n"))
	if len(sums) != 2 || sums["b.exe"] != strings.Repeat("0", 64) {
		t.Fatalf("sums: %v", sums)
	}
	if err := VerifySum(sums, "a.tar.gz", data); err != nil {
		t.Fatal(err)
	}
	if err := VerifySum(sums, "b.exe", data); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("mismatch: %v", err)
	}
	if err := VerifySum(sums, "c", data); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("missing: %v", err)
	}
}
