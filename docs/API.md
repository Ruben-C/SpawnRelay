# SpawnRelay API

The management API is a JSON REST API served by the relay server on the
management port (default `8443`, HTTPS) under `/api/v1`. Everything the web
interface does goes through this API, so anything you can click you can script.

- Base URL: `https://<relay-host>:8443/api/v1`
- Content type: `application/json` for request and response bodies
- Errors: a non-2xx status with a body of `{"error": "human readable message"}`
- Timestamps: RFC 3339 / ISO 8601 in UTC

The management port uses a self-signed certificate by default, so add `-k`
(`--insecure`) to `curl`, or install your own certificate with
`SPAWNRELAY_ADMIN_CERT` / `SPAWNRELAY_ADMIN_KEY` in `/etc/spawnrelay/server.env`.

## Authentication

There are two ways to authenticate:

| Method | Who | How |
|---|---|---|
| API token | scripts, automation | `Authorization: Bearer sr_api_…` header |
| Browser session | the web interface | cookie set by `POST /auth/login` |

Create API tokens in the web interface (**API tokens → Create token**). The
token is shown once; only its hash is stored. Tokens never expire but can be
revoked at any time.

```bash
export SR="https://relay.example.com:8443/api/v1"
export SR_TOKEN="sr_api_…"
curl -k -H "Authorization: Bearer $SR_TOKEN" "$SR/status"
```

A few endpoints are limited to interactive sessions because they manage
credentials: token management, password change and settings. They return
`403` when called with an API token.

| Status | Meaning |
|---|---|
| `400` | invalid body or validation error |
| `401` | missing or invalid credentials |
| `403` | endpoint needs a browser session, or cross-origin request |
| `404` | unknown id |
| `409` | conflict: port already in use, duplicate name, port cannot be bound |
| `429` | too many failed logins from this address (15 minute window) |

## Endpoints

### Health and status

#### `GET /health` (no auth)

```json
{"ok": true, "version": "v1.0.0"}
```

#### `GET /status`

```json
{
  "version": "v1.0.0",
  "server_time": "2026-09-02T18:00:00Z",
  "uptime_seconds": 8642,
  "public_host": "relay.example.com",
  "tunnel_port": 7443,
  "tunnel_addr": "relay.example.com:7443",
  "tunnel_fingerprint": "sha256:3f9c…",
  "admin_url": "https://relay.example.com:8443",
  "admin_self_signed": true,
  "clients_total": 2,
  "clients_online": 1,
  "forwards_total": 3,
  "os": "linux",
  "arch": "amd64"
}
```

### Session (used by the web UI)

| Method | Path | Body | Notes |
|---|---|---|---|
| `POST` | `/auth/login` | `{"username","password"}` | sets the session cookie |
| `POST` | `/auth/logout` | – | clears the cookie |
| `GET` | `/auth/me` | – | `{"kind":"session"|"token","name":…}` |
| `POST` | `/auth/password` | `{"current_password","new_password"}` | session only; invalidates all sessions |

### Settings

#### `GET /settings`

```json
{"public_host": "relay.example.com", "detected_public_host": "203.0.113.5", "effective_public_host": "relay.example.com"}
```

#### `PUT /settings` (session only)

Body: `{"public_host": "relay.example.com"}`. An empty string reverts to the
detected address. The public host is used in generated install commands and
in the `public_addr` of every forward.

### Clients

A client is a machine that runs the SpawnRelay client and hosts game servers.

Client object:

```json
{
  "id": "a1b2c3d4e5f6",
  "name": "basement-pc",
  "token": "sr_c_…",
  "created_at": "…", "updated_at": "…",
  "last_seen_at": "…",
  "last_addr": "198.51.100.7:51234",
  "hostname": "gamebox", "os": "linux", "arch": "amd64", "client_version": "v1.0.0",
  "status": {"online": true, "connected_at": "…", "remote_addr": "198.51.100.7:51234"},
  "forward_count": 2,
  "install": {
    "linux":   "curl -fsSL -k https://relay.example.com:8443/install/client.sh?token=sr_c_… | sudo bash",
    "windows": "irm -SkipCertificateCheck 'https://relay.example.com:8443/install/client.ps1?token=sr_c_…' | iex",
    "manual":  "spawnrelay client --server relay.example.com:7443 --token sr_c_… --fingerprint sha256:…"
  }
}
```

| Method | Path | Body | Result |
|---|---|---|---|
| `GET` | `/clients` | – | array of clients, sorted by name |
| `POST` | `/clients` | `{"name"}` | `201` new client including its token and install commands |
| `GET` | `/clients/{id}` | – | one client |
| `PATCH` | `/clients/{id}` | `{"name"}` | rename |
| `DELETE` | `/clients/{id}` | – | deletes the client and all its forwards, disconnects it |
| `POST` | `/clients/{id}/rotate-token` | – | issues a new token; the old one stops working and the client is disconnected |

Example:

```bash
curl -k -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"basement-pc"}' "$SR/clients"
```

### Forwards

A forward opens a public port on the relay and relays everything that arrives
there through the tunnel to `target_host:target_port` as seen from the client
machine. `target_host` defaults to `127.0.0.1`; use another LAN address to
expose a server on a different machine in the client's network.

Forward object:

```json
{
  "id": "0f1e2d3c4b5a",
  "client_id": "a1b2c3d4e5f6",
  "client_name": "basement-pc",
  "name": "Minecraft survival",
  "protocol": "tcp",
  "public_port": 25565,
  "public_addr": "relay.example.com:25565",
  "target_host": "127.0.0.1",
  "target_port": 25565,
  "enabled": true,
  "created_at": "…", "updated_at": "…",
  "stats": {
    "listening": true,
    "active_tcp": 3, "active_udp": 0,
    "total_connections": 41,
    "bytes_in": 128000, "bytes_out": 5400000
  }
}
```

`protocol` is `tcp`, `udp` or `both`. `bytes_in` counts bytes received on the
public port; `bytes_out` counts bytes sent back to players.

| Method | Path | Body | Result |
|---|---|---|---|
| `GET` | `/forwards` | – | all forwards, sorted by public port. Filter with `?client_id=…` |
| `POST` | `/forwards` | see below | `201` created forward; the public port is bound immediately |
| `GET` | `/forwards/{id}` | – | one forward |
| `PATCH` | `/forwards/{id}` | any subset of the create fields | listeners are restarted if needed |
| `DELETE` | `/forwards/{id}` | – | closes the public port |

Create body fields:

| Field | Required | Default | Notes |
|---|---|---|---|
| `client_id` | yes | – | id of an existing client |
| `public_port` | one of the two | `target_port` | 1–65535, not the tunnel or admin port |
| `target_port` | one of the two | `public_port` | 1–65535 |
| `protocol` | no | `tcp` | `tcp`, `udp` or `both` |
| `target_host` | no | `127.0.0.1` | host reachable from the client |
| `name` | no | `<protocol>-<port>` | up to 64 characters |
| `enabled` | no | `true` | disabled forwards keep their configuration but do not listen |

A `409` is returned when the port is already used by another forward with an
overlapping protocol, or when the operating system refuses to bind it.
Ports below 1024 work when the server runs with `CAP_NET_BIND_SERVICE`, which
the installer's systemd unit grants.

Examples:

```bash
# Expose a Minecraft Java server running on the client itself
curl -k -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"a1b2c3d4e5f6","name":"Minecraft","public_port":25565,"target_port":25565}' \
  "$SR/forwards"

# UDP game (Minecraft Bedrock) on another machine in the client's LAN
curl -k -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"a1b2c3d4e5f6","name":"Bedrock","protocol":"udp","public_port":19132,"target_host":"192.168.1.50","target_port":19132}' \
  "$SR/forwards"

# Temporarily disable a forward
curl -k -X PATCH -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled":false}' "$SR/forwards/0f1e2d3c4b5a"

# Remove it
curl -k -X DELETE -H "Authorization: Bearer $SR_TOKEN" "$SR/forwards/0f1e2d3c4b5a"
```

### API tokens (session only)

| Method | Path | Body | Result |
|---|---|---|---|
| `GET` | `/tokens` | – | `[{"id","name","prefix","created_at","last_used_at"}]` |
| `POST` | `/tokens` | `{"name"}` | `201` token object including the one-time `token` value |
| `DELETE` | `/tokens/{id}` | – | revoke |

These endpoints require a browser session so that a leaked automation token
cannot mint new tokens. Use the web interface to manage them.

## Installer and download endpoints

These are not JSON endpoints but are served from the same port:

| Path | Purpose |
|---|---|
| `GET /install/client.sh?token=sr_c_…` | Linux/macOS installer for the client owning the token |
| `GET /install/client.ps1?token=sr_c_…` | Windows PowerShell installer |
| `GET /dl/spawnrelay_<os>_<arch>[.exe]` | client binary; served from `<data-dir>/bin/` or the running executable |

## A complete automation example

```bash
#!/usr/bin/env bash
# Create (or reuse) a client and expose a game server on it.
set -euo pipefail
SR="https://relay.example.com:8443/api/v1"
AUTH=(-k -sS -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json")

client_id=$(curl "${AUTH[@]}" "$SR/clients" | jq -r '.[] | select(.name=="basement-pc") | .id')
if [ -z "$client_id" ]; then
  client=$(curl "${AUTH[@]}" -d '{"name":"basement-pc"}' "$SR/clients")
  client_id=$(jq -r .id <<<"$client")
  echo "Run this on the game machine:"; jq -r .install.linux <<<"$client"
fi

curl "${AUTH[@]}" -d "{\"client_id\":\"$client_id\",\"name\":\"Valheim\",\"protocol\":\"udp\",\"public_port\":2456,\"target_port\":2456}" "$SR/forwards" | jq .public_addr
```
