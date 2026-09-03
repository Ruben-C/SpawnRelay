//go:build !windows

package client

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyBinary(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	writeScript(t, good, `echo v2.0.0`)
	if err := verifyBinary(context.Background(), good, "v2.0.0"); err != nil {
		t.Fatalf("good binary rejected: %v", err)
	}
	if err := verifyBinary(context.Background(), good, "v3.0.0"); err == nil || !strings.Contains(err.Error(), "reports version") {
		t.Fatalf("version mismatch not detected: %v", err)
	}
	silent := filepath.Join(dir, "silent")
	writeScript(t, silent, `exit 0`)
	if err := verifyBinary(context.Background(), silent, ""); err == nil {
		t.Fatal("silent binary accepted")
	}
	broken := filepath.Join(dir, "broken")
	writeScript(t, broken, `echo boom >&2; exit 3`)
	if err := verifyBinary(context.Background(), broken, "v2.0.0"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("broken binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notexec"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyBinary(context.Background(), filepath.Join(dir, "notexec"), "v2.0.0"); err == nil {
		t.Fatal("garbage file accepted")
	}
}

func TestInstallBinaryAndCleanup(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "spawnrelay")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".spawnrelay.new-1")
	if err := os.WriteFile(tmp, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installBinary(tmp, exe); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(exe)
	if string(b) != "new" {
		t.Fatalf("exe content = %q", b)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("temp file still present after install")
	}
}
