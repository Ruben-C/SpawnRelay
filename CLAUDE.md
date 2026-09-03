# SpawnRelay

Open-source game relay: a server on a VPS accepts one outbound TLS tunnel per
client, exposes public TCP/UDP ports and relays them to game servers on the
client's machine, so users never expose their home network directly. Includes a
web management interface, one-line installers and a token-authenticated REST
API (documented in docs/API.md).

## Layout

- `cmd/spawnrelay` – single binary: `spawnrelay server` and `spawnrelay client`
- `internal/protocol` – wire format (Hello handshake, stream headers, UDP framing)
- `internal/tlsutil` – self-signed certs and fingerprint pinning
- `internal/store` – JSON state file (clients, forwards, tokens, admin, settings)
- `internal/server` – tunnel manager (`tunnel.go`), HTTPS API (`api.go`, `auth.go`), embedded UI (`web/`), embedded client installers (`scripts/`)
- `internal/client` – outbound tunnel client
- `scripts/install-server.sh` – VPS installer (systemd)
- `docs/API.md` – API reference; keep it in sync with `internal/server/api.go`

## Commands

```bash
make build        # bin/spawnrelay
make build-all    # cross-compile into dist/
go test ./...
go vet ./...
make run-server   # dev server on https://127.0.0.1:8443 with ./dev-data
```

## Conventions

- Standard library only, plus `hashicorp/yamux`. No cgo (must cross-compile).
- Routing uses Go 1.22 `ServeMux` method patterns; JSON errors are `{"error": ...}`.
- Credential-management endpoints (tokens, password, settings) are session-only.
- The web UI is vanilla JS with a CSP that forbids inline scripts: no inline handlers.
- Any API change must be reflected in `docs/API.md` and, if user-facing, the web UI.
