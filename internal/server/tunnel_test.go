package server

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/client"
	"github.com/Ruben-C/SpawnRelay/internal/store"
	"github.com/Ruben-C/SpawnRelay/internal/tlsutil"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startEcho runs TCP and UDP echo servers that upper-case what they receive.
func startEcho(t *testing.T) (tcpPort, udpPort int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); pc.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write([]byte(strings.ToUpper(string(buf[:n]))))
				}
			}()
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo([]byte(strings.ToUpper(string(buf[:n]))), addr)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, pc.LocalAddr().(*net.UDPAddr).Port
}

func TestTunnelRelaysTCPAndUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Runs before TempDir's cleanup: stop everything that may still write state.
	t.Cleanup(func() { cancel(); time.Sleep(300 * time.Millisecond) })
	token := store.NewClientToken()
	if err := st.Update(func(s *store.State) error {
		s.Clients = append(s.Clients, &store.Client{ID: "c1", Name: "box", Token: token})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := tlsutil.GenerateSelfSigned("test", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := tlsutil.Fingerprint(cert.Certificate[0])
	tun := NewTunnel(st, &tls.Config{Certificates: []tls.Certificate{cert}}, "test", log)
	t.Cleanup(tun.Shutdown)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go tun.Serve(ctx, ln)

	// A client with a bad token must be rejected; a good one must come online.
	badCtx, badCancel := context.WithTimeout(ctx, 2*time.Second)
	defer badCancel()
	_ = client.Run(badCtx, client.Config{Server: ln.Addr().String(), Token: "sr_c_bad", Fingerprint: fingerprint, Logger: log})
	if tun.ClientStatus("c1").Online {
		t.Fatal("client came online with a bad token")
	}
	go client.Run(ctx, client.Config{Server: ln.Addr().String(), Token: token, Fingerprint: fingerprint, Logger: log})
	deadline := time.Now().Add(5 * time.Second)
	for !tun.ClientStatus("c1").Online {
		if time.Now().After(deadline) {
			t.Fatal("client never came online")
		}
		time.Sleep(20 * time.Millisecond)
	}

	echoTCP, echoUDP := startEcho(t)
	tcpPub, udpPub := freePort(t), freePort(t)
	fwdTCP := &store.Forward{ID: "f1", ClientID: "c1", Name: "tcp", Protocol: store.ProtoTCP, PublicPort: tcpPub, TargetHost: "127.0.0.1", TargetPort: echoTCP, Enabled: true}
	fwdUDP := &store.Forward{ID: "f2", ClientID: "c1", Name: "udp", Protocol: store.ProtoUDP, PublicPort: udpPub, TargetHost: "127.0.0.1", TargetPort: echoUDP, Enabled: true}
	for _, f := range []*store.Forward{fwdTCP, fwdUDP} {
		if err := tun.Apply(f); err != nil {
			t.Fatalf("apply %s: %v", f.Name, err)
		}
	}

	// TCP: small message, then a payload larger than the yamux window.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(tcpPub)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "HELLO" {
		t.Fatalf("tcp echo: %q %v", buf, err)
	}
	big := []byte(strings.Repeat("a", 1<<20))
	go conn.Write(big)
	got := make([]byte, len(big))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("tcp big read: %v", err)
	}
	if string(got) != strings.ToUpper(string(big)) {
		t.Fatal("tcp big payload corrupted")
	}

	// UDP: two independent peers each get their own replies.
	for i := 0; i < 2; i++ {
		u, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(udpPub)))
		if err != nil {
			t.Fatal(err)
		}
		u.SetDeadline(time.Now().Add(5 * time.Second))
		msg := "ping" + itoa(i)
		u.Write([]byte(msg))
		rb := make([]byte, 100)
		n, err := u.Read(rb)
		if err != nil || string(rb[:n]) != strings.ToUpper(msg) {
			t.Fatalf("udp echo %d: %q %v", i, rb[:n], err)
		}
		u.Close()
	}
	if s := tun.ForwardStats("f2"); s.ActiveUDP != 2 || s.TotalConnections != 2 {
		t.Fatalf("unexpected udp stats %+v", s)
	}
	if s := tun.ForwardStats("f1"); s.TotalConnections != 1 || s.BytesIn < int64(len(big)) {
		t.Fatalf("unexpected tcp stats %+v", s)
	}

	// Disabling a forward closes its public port; a second Apply with the
	// same spec is a no-op.
	disabled := *fwdTCP
	disabled.Enabled = false
	if err := tun.Apply(&disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(tcpPub)), 500*time.Millisecond); err == nil {
		t.Fatal("port still open after disabling forward")
	}
	if err := tun.Apply(fwdTCP); err != nil {
		t.Fatal(err)
	}
	if err := tun.Apply(fwdTCP); err != nil {
		t.Fatal(err)
	}

	// Token rotation disconnects the client.
	tun.DisconnectClient("c1", "test")
	if tun.ClientStatus("c1").Online {
		t.Fatal("client still online after disconnect")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
