package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/protocol"
	"github.com/Ruben-C/SpawnRelay/internal/store"
	"github.com/Ruben-C/SpawnRelay/internal/tlsutil"
	"github.com/hashicorp/yamux"
)

// connectRaw speaks the tunnel protocol directly so the test controls the
// Hello fields and sees every control message.
func connectRaw(t *testing.T, addr, fingerprint string, hello protocol.Hello) (*yamux.Session, *yamux.Stream, func(v any) error) {
	t.Helper()
	tlsCfg := &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: tlsutil.PinnedVerifier(fingerprint), NextProtos: []string{"spawnrelay/1"}}
	c, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := yamux.Client(c, yamuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctrl, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteJSONLine(ctrl, hello); err != nil {
		t.Fatal(err)
	}
	br := protocol.NewReader(ctrl)
	read := func(v any) error {
		_ = ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
		return protocol.ReadJSONLine(br, v)
	}
	var resp protocol.HelloResponse
	if err := read(&resp); err != nil || !resp.OK {
		t.Fatalf("hello: %v %+v", err, resp)
	}
	return sess, ctrl, read
}

func TestClientUpdateFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); time.Sleep(200 * time.Millisecond) })
	token := store.NewClientToken()
	if err := st.Update(func(s *store.State) error {
		s.Clients = append(s.Clients, &store.Client{ID: "c1", Name: "box", Token: token})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := tlsutil.GenerateSelfSigned("test", []string{"127.0.0.1"}, time.Hour)
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	fp := tlsutil.Fingerprint(cert.Certificate[0])
	tun := NewTunnel(st, &tls.Config{Certificates: []tls.Certificate{cert}}, "v9.9.9", log)
	t.Cleanup(tun.Shutdown)

	// A fake binary for this platform.
	payload := []byte(strings.Repeat("spawnrelay-binary-", 50000))
	name := assetName(runtime.GOOS, runtime.GOARCH)
	if err := os.WriteFile(filepath.Join(dir, name), payload, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	tun.binary = func(n string) (string, error) {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}
	autoOn := false
	tun.autoUpdate = func() bool { return autoOn }

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go tun.Serve(ctx, ln)
	hello := protocol.Hello{Version: protocol.Version, Token: token, OS: runtime.GOOS, Arch: runtime.GOARCH, ClientVersion: "v1.0.0"}

	// 1. A client that does not allow updates cannot be pushed to.
	sess, _, _ := connectRaw(t, ln.Addr().String(), fp, hello)
	if ok, reason := tun.UpdateAvailability("c1"); ok || !strings.Contains(reason, "disabled") {
		t.Fatalf("availability = %v %q", ok, reason)
	}
	sess.Close()
	waitOffline(t, tun)

	// 2. Allowed: push, read the update message, download, report progress.
	hello.AllowUpdate = true
	sess, ctrl, read := connectRaw(t, ln.Addr().String(), fp, hello)
	var fwd protocol.ControlMessage
	if err := read(&fwd); err != nil || fwd.Type != "forwards" {
		t.Fatalf("expected forwards message, got %+v %v", fwd, err)
	}
	if ok, reason := tun.UpdateAvailability("c1"); !ok {
		t.Fatalf("expected update to be available: %s", reason)
	}
	if err := tun.PushUpdate("c1", false); err != nil {
		t.Fatal(err)
	}
	var upd protocol.ControlMessage
	if err := read(&upd); err != nil || upd.Type != "update" || upd.Update == nil {
		t.Fatalf("expected update message, got %+v %v", upd, err)
	}
	if upd.Update.Version != "v9.9.9" || upd.Update.Name != name || upd.Update.Size != int64(len(payload)) || upd.Update.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("bad update info %+v", upd.Update)
	}
	if err := tun.PushUpdate("c1", false); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("second push should be refused, got %v", err)
	}

	dl, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = protocol.WriteJSONLine(dl, protocol.ClientRequest{Type: "download", Name: name})
	dbr := protocol.NewReader(dl)
	var dresp protocol.DownloadResponse
	if err := protocol.ReadJSONLine(dbr, &dresp); err != nil || !dresp.OK {
		t.Fatalf("download response %+v %v", dresp, err)
	}
	got, err := io.ReadAll(io.LimitReader(dbr, dresp.Size))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("download mismatch: %d bytes, %v", len(got), err)
	}
	dl.Close()

	// Invalid names are refused.
	bad, _ := sess.OpenStream()
	_ = protocol.WriteJSONLine(bad, protocol.ClientRequest{Type: "download", Name: "../../etc/passwd"})
	var bresp protocol.DownloadResponse
	if err := protocol.ReadJSONLine(protocol.NewReader(bad), &bresp); err != nil || bresp.OK {
		t.Fatalf("expected refusal, got %+v %v", bresp, err)
	}
	bad.Close()

	_ = protocol.WriteJSONLine(ctrl, protocol.ControlMessage{Type: "update_status", Status: "installing", Message: "verifying"})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if u := tun.UpdateStatus("c1"); u != nil && u.Detail == "verifying" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status not recorded: %+v", tun.UpdateStatus("c1"))
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 3. Reconnecting on the new version settles the update as done.
	sess.Close()
	waitOffline(t, tun)
	hello.ClientVersion = "v9.9.9"
	sess, _, _ = connectRaw(t, ln.Addr().String(), fp, hello)
	if u := tun.UpdateStatus("c1"); u == nil || u.State != updateDone {
		t.Fatalf("expected done, got %+v", u)
	}
	if ok, reason := tun.UpdateAvailability("c1"); ok || !strings.Contains(reason, "already on") {
		t.Fatalf("availability = %v %q", ok, reason)
	}
	sess.Close()
	waitOffline(t, tun)

	// 4. A failure report, then automatic update on reconnect with the flag on.
	hello.ClientVersion = "v1.0.0"
	sess, ctrl, read = connectRaw(t, ln.Addr().String(), fp, hello)
	_ = read(&fwd)
	if err := tun.PushUpdate("c1", false); err != nil {
		t.Fatal(err)
	}
	_ = read(&upd)
	_ = protocol.WriteJSONLine(ctrl, protocol.ControlMessage{Type: "update_status", Status: "failed", Message: "disk full"})
	deadline = time.Now().Add(3 * time.Second)
	for {
		if u := tun.UpdateStatus("c1"); u != nil && u.State == updateFailed {
			if u.Detail != "disk full" {
				t.Fatalf("detail = %q", u.Detail)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failure not recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	sess.Close()
	waitOffline(t, tun)

	autoOn = true
	// Recent failure: no automatic retry.
	sess, _, read = connectRaw(t, ln.Addr().String(), fp, hello)
	_ = read(&fwd)
	var none protocol.ControlMessage
	if err := read(&none); err == nil {
		t.Fatalf("unexpected message after recent failure: %+v", none)
	}
	sess.Close()
	waitOffline(t, tun)
	// Old failure: automatic push happens.
	tun.mu.Lock()
	tun.updates["c1"].UpdatedAt = time.Now().Add(-2 * time.Hour)
	tun.mu.Unlock()
	sess, _, read = connectRaw(t, ln.Addr().String(), fp, hello)
	_ = read(&fwd)
	if err := read(&upd); err != nil || upd.Type != "update" {
		t.Fatalf("expected automatic update, got %+v %v", upd, err)
	}
	if u := tun.UpdateStatus("c1"); u == nil || !u.Automatic || u.State != updatePending {
		t.Fatalf("expected pending automatic record, got %+v", u)
	}
	sess.Close()
}

func waitOffline(t *testing.T, tun *Tunnel) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for tun.ClientStatus("c1").Online {
		if time.Now().After(deadline) {
			t.Fatal("client never went offline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
