// Command spawnrelay is the single binary for both the SpawnRelay relay server
// and the client that connects game servers to it.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/Ruben-C/SpawnRelay/internal/client"
	"github.com/Ruben-C/SpawnRelay/internal/firewall"
	"github.com/Ruben-C/SpawnRelay/internal/server"
)

// version is overridden at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usageText = `SpawnRelay %s - expose local game servers through a relay without opening ports.

Usage:
  spawnrelay server [flags]          run the relay server (tunnel + management UI/API)
  spawnrelay client [flags]          connect this machine to a relay server
  spawnrelay firewall-agent [flags]  root helper that opens/closes host firewall ports for the server
  spawnrelay version                 print the version

Run "spawnrelay <command> -h" for flags. Every flag can also be set through
the environment variable shown next to it.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usageText, version)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	case "firewall-agent":
		err = runFirewallAgent(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Printf(usageText, version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usageText, version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// envBoolDefault reads a boolean environment variable, returning def when unset.
func envBoolDefault(key string, def bool) bool {
	if os.Getenv(key) == "" {
		return def
	}
	return envBool(key)
}

func defaultDataDir() string {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return "/var/lib/spawnrelay"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "spawnrelay-data"
	}
	return filepath.Join(home, ".spawnrelay")
}

func newLogger(level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch format {
	case "json":
		h = slog.NewJSONHandler(os.Stdout, opts)
	case "text", "":
		h = slog.NewTextHandler(os.Stdout, opts)
	default:
		return nil, fmt.Errorf("invalid log format %q (text|json)", format)
	}
	return slog.New(h), nil
}

func signalContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx
}

// loadEnvFile sets KEY=VALUE lines from path into the process environment.
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if err := os.Setenv(strings.TrimSpace(k), v); err != nil {
			return err
		}
	}
	return sc.Err()
}

// preloadEnvFile applies --env-file before the flag set is defined so that
// flag defaults can be read from the environment.
func preloadEnvFile(args []string) error {
	for i, a := range args {
		switch {
		case a == "--env-file" || a == "-env-file":
			if i+1 < len(args) {
				return loadEnvFile(args[i+1])
			}
		case strings.HasPrefix(a, "--env-file=") || strings.HasPrefix(a, "-env-file="):
			return loadEnvFile(a[strings.Index(a, "=")+1:])
		}
	}
	return nil
}

func runServer(args []string) error {
	if err := preloadEnvFile(args); err != nil {
		return err
	}
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var cfg server.Config
	var logLevel, logFormat, envFile string
	fs.StringVar(&envFile, "env-file", "", "file with KEY=VALUE lines to load into the environment first")
	fs.StringVar(&cfg.DataDir, "data-dir", envOr("SPAWNRELAY_DATA_DIR", defaultDataDir()), "state directory [SPAWNRELAY_DATA_DIR]")
	fs.StringVar(&cfg.TunnelAddr, "tunnel-addr", envOr("SPAWNRELAY_TUNNEL_ADDR", ":7443"), "listen address for clients [SPAWNRELAY_TUNNEL_ADDR]")
	fs.StringVar(&cfg.AdminAddr, "admin-addr", envOr("SPAWNRELAY_ADMIN_ADDR", ":8443"), "listen address for the management UI/API (HTTPS) [SPAWNRELAY_ADMIN_ADDR]")
	fs.StringVar(&cfg.PublicHost, "public-host", envOr("SPAWNRELAY_PUBLIC_HOST", ""), "public hostname or IP of this server; saved to settings [SPAWNRELAY_PUBLIC_HOST]")
	fs.StringVar(&cfg.AdminCert, "admin-cert", envOr("SPAWNRELAY_ADMIN_CERT", ""), "PEM certificate for the management interface (default: self-signed) [SPAWNRELAY_ADMIN_CERT]")
	fs.StringVar(&cfg.AdminKey, "admin-key", envOr("SPAWNRELAY_ADMIN_KEY", ""), "PEM private key for the management interface [SPAWNRELAY_ADMIN_KEY]")
	fs.StringVar(&cfg.FirewallSocket, "firewall-socket", envOr("SPAWNRELAY_FIREWALL_SOCKET", ""), "unix socket of the firewall agent (default: <data-dir>/firewall.sock) [SPAWNRELAY_FIREWALL_SOCKET]")
	fs.BoolVar(&cfg.ResetAdminPassword, "reset-admin-password", envBool("SPAWNRELAY_RESET_ADMIN_PASSWORD"), "generate a new admin password at startup [SPAWNRELAY_RESET_ADMIN_PASSWORD]")
	fs.StringVar(&logLevel, "log-level", envOr("SPAWNRELAY_LOG_LEVEL", "info"), "debug|info|warn|error [SPAWNRELAY_LOG_LEVEL]")
	fs.StringVar(&logFormat, "log-format", envOr("SPAWNRELAY_LOG_FORMAT", "text"), "text|json [SPAWNRELAY_LOG_FORMAT]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log, err := newLogger(logLevel, logFormat)
	if err != nil {
		return err
	}
	cfg.Logger = log
	cfg.Version = version
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	return srv.Run(signalContext())
}

func runFirewallAgent(args []string) error {
	if err := preloadEnvFile(args); err != nil {
		return err
	}
	fs := flag.NewFlagSet("firewall-agent", flag.ExitOnError)
	var dataDir, socket, logLevel, logFormat, envFile string
	fs.StringVar(&envFile, "env-file", "", "file with KEY=VALUE lines to load into the environment first")
	fs.StringVar(&dataDir, "data-dir", envOr("SPAWNRELAY_DATA_DIR", defaultDataDir()), "server state directory; the socket is created there [SPAWNRELAY_DATA_DIR]")
	fs.StringVar(&socket, "socket", envOr("SPAWNRELAY_FIREWALL_SOCKET", ""), "unix socket path (default: <data-dir>/firewall.sock) [SPAWNRELAY_FIREWALL_SOCKET]")
	fs.StringVar(&logLevel, "log-level", envOr("SPAWNRELAY_LOG_LEVEL", "info"), "debug|info|warn|error [SPAWNRELAY_LOG_LEVEL]")
	fs.StringVar(&logFormat, "log-format", envOr("SPAWNRELAY_LOG_FORMAT", "text"), "text|json [SPAWNRELAY_LOG_FORMAT]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log, err := newLogger(logLevel, logFormat)
	if err != nil {
		return err
	}
	if socket == "" {
		socket = filepath.Join(dataDir, "firewall.sock")
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		log.Warn("firewall agent is not running as root; firewall changes will most likely fail")
	}
	log.Info("SpawnRelay firewall agent starting", "version", version, "socket", socket)
	return firewall.Serve(signalContext(), firewall.AgentConfig{Socket: socket, LedgerDir: dataDir, Version: version, Logger: log})
}

func runClient(args []string) error {
	if err := preloadEnvFile(args); err != nil {
		return err
	}
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	var cfg client.Config
	var logLevel, logFormat, envFile string
	fs.StringVar(&envFile, "env-file", "", "file with KEY=VALUE lines to load into the environment first")
	fs.StringVar(&cfg.Server, "server", envOr("SPAWNRELAY_SERVER", ""), "relay tunnel address host:port [SPAWNRELAY_SERVER]")
	fs.StringVar(&cfg.Token, "token", envOr("SPAWNRELAY_TOKEN", ""), "client token issued by the relay [SPAWNRELAY_TOKEN]")
	fs.StringVar(&cfg.Fingerprint, "fingerprint", envOr("SPAWNRELAY_FINGERPRINT", ""), "pinned sha256 fingerprint of the relay's tunnel certificate [SPAWNRELAY_FINGERPRINT]")
	fs.BoolVar(&cfg.AllowUpdate, "allow-update", envBoolDefault("SPAWNRELAY_ALLOW_UPDATE", true), "install updates pushed by the relay server [SPAWNRELAY_ALLOW_UPDATE]")
	fs.StringVar(&logLevel, "log-level", envOr("SPAWNRELAY_LOG_LEVEL", "info"), "debug|info|warn|error [SPAWNRELAY_LOG_LEVEL]")
	fs.StringVar(&logFormat, "log-format", envOr("SPAWNRELAY_LOG_FORMAT", "text"), "text|json [SPAWNRELAY_LOG_FORMAT]")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log, err := newLogger(logLevel, logFormat)
	if err != nil {
		return err
	}
	cfg.Logger = log
	cfg.Version = version
	log.Info("SpawnRelay client starting", "version", version)
	return client.Run(signalContext(), cfg)
}
