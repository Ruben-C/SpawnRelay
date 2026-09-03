package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestServerInstallerCleanup runs the "previous versions" section of
// scripts/install-server.sh against a temp directory with a fake systemctl,
// fake unit files, stale sockets, leftovers and a stray "spawnrelay server"
// process, and checks that everything is stopped and cleaned up exactly once.
func TestServerInstallerCleanup(t *testing.T) {
	for _, tool := range []string{"bash", "pgrep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install-server.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(script)
	start := strings.Index(src, "# ---- previous versions")
	end := strings.Index(src, "\ncleanup_previous\n")
	if start < 0 || end < 0 {
		t.Fatal("cleanup section not found in install-server.sh")
	}
	section := src[start:end] + "\ncleanup_previous\n"

	// Relative paths keep the unix socket names short.
	t.Chdir(t.TempDir())
	for _, d := range []string{"units", "data", "bin", "fakebin"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Fake systemctl: logs every call; is-active/is-enabled succeed while a marker exists.
	// Each unit has its own "active" marker, like real units do.
	fake := "#!/usr/bin/env bash\necho \"$*\" >> systemctl.log\ncase \"$1\" in is-active|is-enabled) [ -f \"active.$3\" ] ;; disable) shift; for a in \"$@\"; do rm -f \"active.$a\"; done ;; esac\n"
	if err := os.WriteFile("fakebin/systemctl", []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	run := func() string {
		body := "log() { echo \"$*\"; }\nBIN=" + wd + "/bin/spawnrelay\nDATA_DIR=" + wd + "/data\nUNIT_DIR=" + wd + "/units\nSYSTEMCTL=" + wd + "/fakebin/systemctl\n" + section
		cmd := exec.Command("bash", "-euo", "pipefail", "-c", body)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cleanup failed: %v\n%s", err, out)
		}
		return string(out)
	}

	// An earlier version's state.
	for _, u := range []string{"spawnrelay-firewall.service", "spawnrelay-server.service"} {
		_ = os.WriteFile(filepath.Join("units", u), []byte("[Unit]\n"), 0o644)
	}
	for _, u := range []string{"spawnrelay-firewall.service", "spawnrelay-server.service"} {
		_ = os.WriteFile("active."+u, nil, 0o644)
	}
	for _, sock := range []string{"data/firewall.sock", "data/agent.sock"} {
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
	}
	_ = os.WriteFile("bin/spawnrelay", []byte("bin"), 0o755)
	_ = os.WriteFile("bin/spawnrelay.previous", []byte("prev"), 0o755)
	_ = os.WriteFile("data/server-update.json", []byte("{}"), 0o644)
	_ = os.MkdirAll("data/updates/v0.4.0", 0o755)
	_ = os.WriteFile("data/state.json", []byte("{}"), 0o600)
	// A stray server process outside systemd (argv[0] set with exec -a).
	stray := exec.Command("bash", "-c", `exec -a "spawnrelay server" sleep 60`)
	if err := stray.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stray.Process.Kill(); _, _ = stray.Process.Wait() }()
	time.Sleep(200 * time.Millisecond)

	out := run()
	for _, want := range []string{
		"stopping spawnrelay-firewall.service", "stopping spawnrelay-server.service", "removing spawnrelay-firewall.service",
		"stopping spawnrelay processes left running outside systemd", "removing leftover", "firewall.sock", "agent.sock", "spawnrelay.previous", "server-update.json", "data/updates",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	log, _ := os.ReadFile("systemctl.log")
	for _, want := range []string{"disable --now spawnrelay-firewall.service", "disable --now spawnrelay-server.service", "daemon-reload"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("systemctl was not asked to %q:\n%s", want, log)
		}
	}
	if _, err := os.Stat("units/spawnrelay-firewall.service"); !os.IsNotExist(err) {
		t.Error("old firewall unit file not removed")
	}
	if _, err := os.Stat("units/spawnrelay-server.service"); err != nil {
		t.Error("server unit file must stay (it is rewritten later)")
	}
	for _, gone := range []string{"data/firewall.sock", "data/agent.sock", "bin/spawnrelay.previous", "data/server-update.json", "data/updates"} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Errorf("%s still exists", gone)
		}
	}
	for _, kept := range []string{"data/state.json", "bin/spawnrelay"} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s must be kept", kept)
		}
	}
	// The stray process is gone.
	if err := stray.Process.Signal(syscall.Signal(0)); err == nil {
		_, _ = stray.Process.Wait()
		if err := stray.Process.Signal(syscall.Signal(0)); err == nil {
			t.Error("stray spawnrelay server process still alive")
		}
	}

	// Idempotent: a second run has nothing to do and says nothing.
	if out := run(); strings.TrimSpace(out) != "" {
		t.Errorf("second run should be silent, got:\n%s", out)
	}
}
