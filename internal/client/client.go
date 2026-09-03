// Package client implements the SpawnRelay client: it maintains an outbound
// TLS tunnel to the relay server and services the streams the server opens
// for each public connection.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/Ruben-C/SpawnRelay/internal/protocol"
	"github.com/Ruben-C/SpawnRelay/internal/relay"
	"github.com/Ruben-C/SpawnRelay/internal/tlsutil"
	"github.com/hashicorp/yamux"
)

// Config configures a client.
type Config struct {
	Server      string // host:port of the relay's tunnel listener
	Token       string // client token issued by the server
	Fingerprint string // pinned "sha256:..." of the tunnel certificate; empty = system CA verification
	AllowUpdate bool   // install updates pushed by the server (see update.go)
	Version     string
	Logger      *slog.Logger
}

// ErrAuth is returned when the server rejects the token.
var ErrAuth = errors.New("authentication rejected")

// Run connects to the server and reconnects with backoff until ctx ends.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Server == "" || cfg.Token == "" {
		return errors.New("server address and token are required")
	}
	if cfg.Fingerprint != "" {
		fp, err := tlsutil.NormalizeFingerprint(cfg.Fingerprint)
		if err != nil {
			return err
		}
		cfg.Fingerprint = fp
	} else {
		cfg.Logger.Warn("no fingerprint configured; verifying server certificate with system CAs")
	}
	cleanupUpdateLeftovers(cfg.Logger)

	backoff := time.Second
	for {
		connected := false
		err := runOnce(ctx, cfg, func() { connected = true })
		if ctx.Err() != nil {
			return nil
		}
		if connected {
			backoff = time.Second
		}
		if errors.Is(err, ErrAuth) {
			backoff = 30 * time.Second
		}
		cfg.Logger.Warn("tunnel disconnected", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	return c
}

func runOnce(ctx context.Context, cfg Config, onConnected func()) error {
	log := cfg.Logger
	host, _, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		return fmt.Errorf("invalid server address %q (expected host:port): %w", cfg.Server, err)
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"spawnrelay/1"}}
	if cfg.Fingerprint != "" {
		tlsCfg.InsecureSkipVerify = true // we verify via the pinned fingerprint instead
		tlsCfg.VerifyPeerCertificate = tlsutil.PinnedVerifier(cfg.Fingerprint)
	}

	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: tlsCfg}
	log.Info("connecting to relay", "server", cfg.Server)
	tlsConn, err := dialer.DialContext(ctx, "tcp", cfg.Server)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	sess, err := yamux.Client(tlsConn, yamuxConfig())
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("mux: %w", err)
	}
	defer sess.Close()

	ctrl, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	hostname, _ := os.Hostname()
	_ = ctrl.SetDeadline(time.Now().Add(15 * time.Second))
	if err := protocol.WriteJSONLine(ctrl, protocol.Hello{
		Version: protocol.Version, Token: cfg.Token, Hostname: hostname,
		OS: runtime.GOOS, Arch: runtime.GOARCH, ClientVersion: cfg.Version, AllowUpdate: cfg.AllowUpdate,
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}
	br := protocol.NewReader(ctrl)
	var resp protocol.HelloResponse
	if err := protocol.ReadJSONLine(br, &resp); err != nil {
		return fmt.Errorf("read hello response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("%w: %s", ErrAuth, resp.Error)
	}
	_ = ctrl.SetDeadline(time.Time{})
	onConnected()
	log.Info("connected to relay", "client_id", resp.ClientID, "client_name", resp.ClientName, "server_version", resp.ServerVersion)
	c := &conn{cfg: cfg, log: log, sess: sess, ctrl: ctrl}

	// Control reader: log forward announcements; any error ends the session.
	go func() {
		defer sess.Close()
		for {
			var msg protocol.ControlMessage
			if err := protocol.ReadJSONLine(br, &msg); err != nil {
				return
			}
			switch msg.Type {
			case "forwards":
				if len(msg.Forwards) == 0 {
					log.Info("no port forwards configured for this client yet")
				}
				for _, f := range msg.Forwards {
					log.Info("forward active", "name", f.Name, "protocol", f.Protocol, "public_port", f.PublicPort, "target", f.Target)
				}
			case "update":
				if msg.Update == nil {
					log.Warn("update message without details")
					continue
				}
				go c.runUpdate(ctx, *msg.Update)
			case "shutdown":
				log.Info("server asked us to disconnect", "message", msg.Message)
				return
			}
		}
	}()
	go func() {
		<-ctx.Done()
		sess.Close()
	}()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("session closed: %w", err)
		}
		go handleStream(log, stream)
	}
}

func handleStream(log *slog.Logger, stream *yamux.Stream) {
	br := protocol.NewReader(stream)
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var hdr protocol.StreamHeader
	if err := protocol.ReadJSONLine(br, &hdr); err != nil {
		log.Warn("bad stream header", "error", err)
		stream.Close()
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	switch hdr.Type {
	case "tcp":
		target, err := net.DialTimeout("tcp", hdr.Target, 10*time.Second)
		if err != nil {
			log.Warn("cannot reach local target", "target", hdr.Target, "remote", hdr.Remote, "error", err)
			stream.Close()
			return
		}
		log.Debug("tcp session open", "target", hdr.Target, "remote", hdr.Remote)
		in, out := relay.Pipe(&relay.BufferedConn{R: br, C: stream}, target)
		log.Debug("tcp session closed", "target", hdr.Target, "remote", hdr.Remote, "bytes_in", in, "bytes_out", out)
	case "udp":
		raddr, err := net.ResolveUDPAddr("udp", hdr.Target)
		if err != nil {
			log.Warn("bad udp target", "target", hdr.Target, "error", err)
			stream.Close()
			return
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			log.Warn("cannot open udp socket", "target", hdr.Target, "error", err)
			stream.Close()
			return
		}
		log.Debug("udp session open", "target", hdr.Target, "remote", hdr.Remote)
		done := make(chan struct{})
		go func() { // local target -> stream
			defer close(done)
			buf := make([]byte, protocol.MaxDatagram)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				if err := protocol.WriteFrame(stream, buf[:n]); err != nil {
					return
				}
			}
		}()
		buf := make([]byte, protocol.MaxDatagram) // stream -> local target
		for {
			payload, err := protocol.ReadFrame(br, buf)
			if err != nil {
				break
			}
			if _, err := conn.Write(payload); err != nil {
				break
			}
		}
		conn.Close()
		stream.Close()
		<-done
		log.Debug("udp session closed", "target", hdr.Target, "remote", hdr.Remote)
	default:
		log.Warn("unknown stream type", "type", hdr.Type)
		stream.Close()
	}
}
