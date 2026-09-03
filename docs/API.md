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
  "forwards_total": 8,
  "forward_groups_total": 3,
  "server_update": {"available": true, "version": "v0.5.0"},
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
{
  "public_host": "relay.example.com",
  "detected_public_host": "203.0.113.5",
  "effective_public_host": "relay.example.com",
  "firewall": "auto",
  "auto_update_clients": false,
  "server_version": "v0.3.0",
  "firewall_modes": ["auto", "off", "ufw", "firewalld", "nftables", "iptables"],
  "firewall_status": {
    "mode": "auto",
    "managed": true,
    "agent": "connected",
    "backend": "ufw",
    "active": true,
    "last_sync": "2026-09-03T10:00:00Z",
    "socket": "/var/lib/spawnrelay/agent.sock"
  }
}
```

`firewall_status.agent` is one of `connected`, `not installed` (no agent
socket in the data directory), `unreachable` (the agent did not answer; see
`error`) or `off`. `backend` is the firewall tool in use, or `none` when the
agent found no active host firewall. `note` and `error` carry human-readable
detail when present. See [Host firewall](#host-firewall).

#### `PUT /settings` (session only)

Body: any subset of `{"public_host": "relay.example.com", "firewall": "auto",
"auto_update_clients": true}`. An empty `public_host` reverts to the detected
address. The public host is used in generated install commands and in the
`public_addr` of every forward. `firewall` must be one of `firewall_modes`;
changing it triggers an immediate firewall sync. Switching to `off` stops
managing the firewall but leaves the rules that were already created in
place. `auto_update_clients` pushes the server's version to any client that
connects with a different one (see [Client updates](#client-updates)).

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
  "forward_count": 8,
  "forward_group_count": 3,
  "update": {
    "available": true,
    "server_version": "v0.3.0",
    "allow_update": true,
    "last": {"state": "done", "target_version": "v0.2.0", "detail": "updated to v0.2.0", "requested_at": "…", "updated_at": "…"}
  },
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
| `POST` | `/clients/{id}/update` | – | `202` client; pushes the server's version to the connected client, `409` with the reason when it cannot (see below) |
| `POST` | `/clients/update-all` | – | `202` `{"requested": n, "requested_ids": […], "skipped": [{"id","name","reason"}]}` |

Example:

```bash
curl -k -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"basement-pc"}' "$SR/clients"
```

### Client updates

The server knows every connected client's version (`client_version`), and it
serves client binaries for all platforms (`/dl/…`, filled by the server
installer from the release matching the server). `update.available` is true
when the client is online, runs a different version than the server, accepts
pushed updates and a binary for its OS/architecture exists on the server;
otherwise `update.reason` says why. `update.last` is the most recent attempt:

| `last.state` | Meaning |
|---|---|
| `pending` | requested; `detail` follows the client's progress (downloading, installing, restarting) |
| `done` | the client reconnected running `target_version` |
| `failed` | the client reported an error in `detail`, reconnected on the old version, or did not answer within 3 minutes |

How a push works: the server sends an `update` message on the control
stream with the binary name, size and SHA-256. The client downloads it over
a new stream of the same pinned tunnel (never over the management port),
refuses it on any size or hash mismatch, runs `<new binary> version` and
refuses unless it prints the server's version, swaps it into place and
restarts itself (exec in place on Linux and macOS, a detached child on
Windows). Players connected through that client are disconnected for a few
seconds. Clients installed before v0.3.0 must be reinstalled once with their
install command; after that they accept pushes. Clients can opt out with
`SPAWNRELAY_ALLOW_UPDATE=0` in their `client.env`.

With `auto_update_clients` on, the server pushes to every client that connects
with a different version, retrying a failed client at most once an hour.
Automatic updates are paused while the server runs a `dev` build.

### Forwards

A forward opens a public port on the relay and relays everything that arrives
there through the tunnel to `target_host:target_port` as seen from the client
machine. `target_host` defaults to `127.0.0.1`; use another LAN address to
expose a server on a different machine in the client's network.

Every forward belongs to a [forward group](#forward-groups). A forward created
here is a group of one (`group_id` equals `id`); games that need several ports
are easier to manage through the group endpoints, which is also what the web
UI uses.

Forward object:

```json
{
  "id": "0f1e2d3c4b5a",
  "group_id": "0f1e2d3c4b5a",
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
  },
  "firewall": {"state": "open"}
}
```

`protocol` is `tcp`, `udp` or `both`. `bytes_in` counts bytes received on the
public port; `bytes_out` counts bytes sent back to players.

`firewall.state` reports whether the host firewall lets players reach the
public port (see [Host firewall](#host-firewall)):

| State | Meaning |
|---|---|
| `open` | SpawnRelay added a rule for this port |
| `existing` | a rule that is not SpawnRelay's already allows the port; nothing was added and it will not be removed |
| `closed` | the forward is disabled, so SpawnRelay's rule was removed |
| `error` | the firewall tool refused; `firewall.error` has the message |
| `none` | the agent is running but found no active host firewall |
| `unmanaged` | firewall management is off or the agent is not installed |

| Method | Path | Body | Result |
|---|---|---|---|
| `GET` | `/forwards` | – | all forwards, sorted by public port. Filter with `?client_id=…` |
| `POST` | `/forwards` | see below | `201` created forward; the public port is bound and opened in the firewall immediately |
| `GET` | `/forwards/{id}` | – | one forward |
| `PATCH` | `/forwards/{id}` | any subset of the create fields | listeners are restarted and firewall rules updated if needed. A member of a multi-port group cannot change `client_id` on its own (`400`); move the group instead |
| `DELETE` | `/forwards/{id}` | – | closes the public port and removes its firewall rule. Deleting a member shrinks its group; a group with no members disappears |

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

### Forward groups

A forward group is a set of forwards created from one **port spec** and
managed as a unit: one name, client, target host and enabled flag, expanded
into one forward per public port. Each port still has its own listener,
firewall rule and counters. Use groups for games that need several ports.

Port spec grammar, entries separated by commas and/or whitespace:

| Entry | Meaning |
|---|---|
| `7777` | one port |
| `7780-7784` | an inclusive range |
| `7777/udp` | protocol for this entry: `tcp`, `udp` or `both`. Without a suffix the group's `protocol` applies (default `tcp`) |
| `27015>37015` | relay to a different port on the target host. For a range the target names the first port and the rest shift by the same offset, so `2000-2005>3000` targets 3000–3005 |

Example: `7780-7784/udp, 5673, 15673, 25673>35673` with `protocol: "tcp"`
opens five UDP ports and three TCP ports, relaying 25673 to 35673.

A spec may expand to at most 64 public ports. Malformed entries, ports outside
1–65535 (public or target), an empty spec, or the same public port listed
twice with an overlapping protocol are rejected with `400` naming the entry.
Listing a port once as `/tcp` and once as `/udp` is fine.

Group object:

```json
{
  "id": "9a8b7c6d5e4f",
  "client_id": "a1b2c3d4e5f6",
  "client_name": "basement-pc",
  "name": "Dune Awakening",
  "protocol": "udp",
  "ports": "5673/tcp, 7780-7784/udp, 15673/tcp, 25673/tcp>35673",
  "target_host": "192.168.1.20",
  "enabled": true,
  "created_at": "…", "updated_at": "…",
  "public_host": "relay.example.com",
  "stats": {"listening": true, "active_tcp": 1, "active_udp": 4, "total_connections": 57, "bytes_in": 1280000, "bytes_out": 54000000},
  "firewall": {"state": "open"},
  "forwards": [ …member forward objects, sorted by public port… ]
}
```

`ports` is the canonical rendering of the members: sorted by port, contiguous
runs collapsed into ranges, the protocol always shown and `>target` only when
it differs. `protocol` is the lowest-port member's protocol. `enabled` is true
only when every member is enabled. `stats` sums the members' counters, and
`stats.listening` is true only when every enabled member is listening.
`firewall` is the worst state among enabled members (`error` wins, then
`existing`, `open`), with the first error message.

| Method | Path | Body | Result |
|---|---|---|---|
| `GET` | `/forward-groups` | – | all groups, sorted by lowest public port. Filter with `?client_id=…` |
| `POST` | `/forward-groups` | see below | `201` created group with all ports bound and opened in the firewall |
| `GET` | `/forward-groups/{id}` | – | one group |
| `PATCH` | `/forward-groups/{id}` | any subset of the create fields | members are matched by public port and protocol: kept ports keep their `id` and counters, removed ports are closed, new ports are opened |
| `DELETE` | `/forward-groups/{id}` | – | closes every member's port; returns `{"ok":true,"forwards_removed":n}` |

Create body fields:

| Field | Required | Default | Notes |
|---|---|---|---|
| `client_id` | yes | – | id of an existing client |
| `ports` | yes | – | port spec, see above |
| `protocol` | no | `tcp` | protocol for entries without a `/tcp`, `/udp` or `/both` suffix. Also defaults to `tcp` on `PATCH` when omitted |
| `target_host` | no | `127.0.0.1` | host reachable from the client, shared by every port |
| `name` | no | the canonical `ports` | up to 64 characters |
| `enabled` | no | `true` | applies to every member |

Creates and updates are all-or-nothing: if any port is the tunnel or admin
port, is already used by a forward outside the group, or cannot be bound, the
response is `409` naming that port and nothing changes. Changing `client_id`
on a group moves every member.

Examples:

```bash
# Dune Awakening: a UDP range plus three TCP ports on a machine in the client's LAN
curl -k -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"a1b2c3d4e5f6","name":"Dune Awakening","ports":"7780-7784/udp, 5673, 15673, 25673","target_host":"192.168.1.20"}' \
  "$SR/forward-groups"

# Add two more UDP ports; the existing eight keep their ids and counters
curl -k -X PATCH -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"ports":"7780-7786/udp, 5673, 15673, 25673"}' "$SR/forward-groups/9a8b7c6d5e4f"

# Take the whole game offline without losing its configuration
curl -k -X PATCH -H "Authorization: Bearer $SR_TOKEN" -H "Content-Type: application/json" \
  -d '{"enabled":false}' "$SR/forward-groups/9a8b7c6d5e4f"

# Remove all of its ports
curl -k -X DELETE -H "Authorization: Bearer $SR_TOKEN" "$SR/forward-groups/9a8b7c6d5e4f"
```

### Host firewall

SpawnRelay keeps the relay host's own firewall in step with its configuration:
the tunnel port, the management port and the public port of every enabled
forward are opened, and a forward's rule is removed as soon as it is disabled
or deleted. A firewall problem never fails a forward request; it is reported
in the forward's `firewall` field and in `GET /settings`.

The relay server runs unprivileged, so the actual firewall changes are made by
a separate root-only process, `spawnrelay agent`, installed by the server
installer as `spawnrelay-agent.service` (before v0.5: `spawnrelay firewall-agent`
and `spawnrelay-firewall.service`; a server still finds such an agent, but it
cannot install updates). The server talks to it over a unix socket in the data
directory and can ask for two things only: "make the set of ports you have
opened equal to this list" and "install this release tag" (see
[Server updates](#server-updates-session-only)). Every rule the agent creates
is tagged `spawnrelay:<forward id>` (`spawnrelay:tunnel` and
`spawnrelay:admin` for the relay's own ports); it never adds, changes or
removes anything else, so rules you created by hand, including one that
happens to allow the same port, are left alone.

Supported backends, detected automatically in this order when the mode is
`auto`: **firewalld** (`firewall-cmd`, runtime and permanent, default zone),
**ufw** (when active), **nftables** (tagged accept rules inserted at the top
of every input chain), **iptables** (tagged rules inserted at the top of
`INPUT`, plus `ip6tables` when installed). Raw nftables and iptables rules are
not persisted by SpawnRelay; the server re-syncs at start-up, on every
change and every five minutes, which restores them after a reboot once the
base ruleset is back.

The agent cannot open ports in a cloud provider's security group.
Those still have to be opened by hand.

Sync cadence: on server start, after every forward or client change, when
the firewall mode changes, every five minutes, and every 20 seconds while
the last sync failed or the agent is not installed.

### Server updates (session only)

The server checks the latest release of its GitHub repository (`--update-repo`,
default `Ruben-C/SpawnRelay`) at start-up and hourly. `GET /status` carries
the result as `server_update` so the UI can show an indicator; the endpoints
below require an interactive admin session, API tokens are refused with `403`.

| Method | Path | Body | Result |
|---|---|---|---|
| `GET` | `/server/update` | – | update status, see below |
| `POST` | `/server/update/check` | – | re-checks GitHub now, then returns the status |
| `POST` | `/server/update` | `{"version"?, "reinstall"?}` | `202` and the status once the update has started |

```json
{
  "running_version": "v0.4.0",
  "latest_version": "v0.5.0",
  "checked_at": "…",
  "check_error": "",
  "available": true,
  "reason": "",
  "supported": true,
  "install_command": "curl -fsSL https://raw.githubusercontent.com/Ruben-C/SpawnRelay/main/scripts/install-server.sh | sudo bash",
  "last": {"state": "done", "from": "v0.3.0", "to": "v0.4.0", "detail": "updated to v0.4.0", "started_at": "…", "finished_at": "…"}
}
```

`available` is true only when both versions parse as `vMAJOR.MINOR.PATCH` and
the latest is newer; a `dev` build never has an update and `reason` says so.
`supported` is true when a root agent that can install updates answers on
the socket; otherwise `reason` explains and `install_command` is the manual
way. `last` is the most recent attempt (`pending`, `done`, `failed` or
`rolled_back`) or `null`.

`POST /server/update` without a body installs the latest release. With
`version` it must be the latest release, or the running version together with
`"reinstall": true`; anything else is `400` (older versions are never
installed). It is `409` while an update is pending, when nothing is available
or when the host is not supported.

What happens: the server downloads every client binary of the release into
`<data-dir>/updates/<tag>/` and verifies each against the release's
`SHA256SUMS` (any mismatch fails the update before anything is touched). It
then hands only the tag to the agent, which downloads and verifies the server
tarball itself, keeps the current binary as `<binary>.previous`, installs the
new one, restarts `spawnrelay-server.service` and waits up to 60 seconds for
the new version to answer on the admin port. If it does not, the previous
binary is restored and the attempt ends as `rolled_back`. The agent restarts
itself last. The new server moves the staged client binaries into
`<data-dir>/bin/` on start-up, so client pushes always match the running
version. Sessions do not survive the restart: sign in again afterwards.

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
