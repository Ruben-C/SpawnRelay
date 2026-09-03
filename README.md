# SpawnRelay

SpawnRelay lets you host game servers at home (or anywhere behind NAT/CGNAT)
without opening ports or exposing your machine to the internet. A small relay
runs on a cheap VPS; your game machine makes one outbound, encrypted connection
to it; players connect to the VPS and their traffic is relayed through that
tunnel to your game server.

```
 players ──▶ relay.example.com:25565 ──▶ [ SpawnRelay server (VPS) ]
                                                 │  one outbound TLS tunnel
                                                 ▼
                                    [ SpawnRelay client ] ──▶ 127.0.0.1:25565 (your game server)
```

- **One binary** for server and client, no dependencies, Linux/macOS/Windows/FreeBSD.
- **TCP and UDP** forwards, so it works for Minecraft, Valheim, Rust, Source games, …
- **Web management interface** with one-line client install commands.
- **REST API with tokens** for automation ([docs/API.md](docs/API.md)).
- **Secure by default**: TLS tunnel with certificate pinning, per-client tokens, hashed admin/API credentials, hardened systemd units.

## 1. Install the server (VPS)

On a Linux VPS with systemd, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Ruben-C/SpawnRelay/main/scripts/install-server.sh | sudo bash
```

The installer downloads the latest release, creates a `spawnrelay` system user,
writes `/etc/spawnrelay/server.env`, starts `spawnrelay-server.service` and
prints the management URL, the generated admin password and the tunnel
certificate fingerprint.

The installer also starts `spawnrelay-firewall.service`, a small root-only
agent that opens and closes ports in the VPS's own firewall (ufw, firewalld,
nftables or iptables, detected automatically) as you manage forwards. See
[Host firewall](#host-firewall). If your VPS sits behind a cloud security
group, open these there:

| Port | Purpose |
|---|---|
| `7443/tcp` | tunnel port clients connect to |
| `8443/tcp` | management interface and API (HTTPS) |
| every forward port you create | players |

Options are environment variables, e.g. `SPAWNRELAY_PUBLIC_HOST=relay.example.com`
or `SPAWNRELAY_ADMIN_PORT=443`. See the header of
[scripts/install-server.sh](scripts/install-server.sh).

To install from a local checkout instead of a release, run the same script
from the repository root; it builds with the local Go toolchain.

## 2. Add a client

Open `https://<your-vps>:8443` (the certificate is self-signed, accept the
warning once), sign in as `admin` with the printed password, then
**Clients → Add client**. You get a one-liner for the game machine:

```bash
curl -fsSL -k https://relay.example.com:8443/install/client.sh?token=sr_c_… | sudo bash
```

or on Windows (elevated PowerShell):

```powershell
irm -SkipCertificateCheck 'https://relay.example.com:8443/install/client.ps1?token=sr_c_…' | iex
```

The script downloads the client binary from your relay, writes
`/etc/spawnrelay/client.env` (server, token, pinned fingerprint) and installs a
service (`spawnrelay-client` on systemd, a launchd daemon on macOS, a scheduled
task on Windows). The client shows as **Online** in the interface within a
second or two.

The client never listens for incoming connections; it only dials out to the
relay's tunnel port and to the local game ports you forward.

## 3. Create port forwards

**Forwards → Add forward** (or the **+ Forward** button on a client). Pick a
game preset or enter the port and protocol, and the relay starts listening
immediately. Give players `relay.example.com:<public port>`.

Forwards can be edited, disabled/enabled and deleted at any time. Traffic
counters and active connection counts are shown live.

## Host firewall

SpawnRelay manages the relay's host firewall for you across the whole
lifecycle of a forward: creating or enabling a forward opens its public port,
disabling or deleting it closes the port again, and the tunnel and management
ports are kept open too. The **Forwards** tab shows the firewall state of
every forward and **Settings → Host firewall** shows which backend is in use.

- The relay server itself stays unprivileged. Firewall changes are made by
  `spawnrelay firewall-agent`, a root-only helper (`spawnrelay-firewall.service`)
  that listens on `/var/lib/spawnrelay/firewall.sock` and accepts exactly one
  request: the list of ports that should be open.
- Every rule it creates is tagged `spawnrelay:<id>`. It never touches other
  rules, so your SSH rule and anything else you configured by hand are safe,
  and a hand-made rule that already allows a forward's port is reused rather
  than duplicated or removed.
- Backends: firewalld, ufw, nftables, iptables (auto-detected in that order,
  or pick one explicitly in Settings). Choose **Off** to leave the firewall
  entirely to yourself.
- Cloud security groups (AWS, Hetzner, DigitalOcean, …) are outside the VPS
  and still need to be opened by hand.

## Automation / API

Create a token under **API tokens** and use it as a bearer token:

```bash
curl -k -H "Authorization: Bearer sr_api_…" -H "Content-Type: application/json" \
  -d '{"client_id":"<id>","name":"Valheim","protocol":"udp","public_port":2456,"target_port":2456}' \
  https://relay.example.com:8443/api/v1/forwards
```

Full reference: [docs/API.md](docs/API.md).

## How it works

- The client opens a TLS connection to the tunnel port and verifies the
  server's self-signed certificate against the SHA-256 fingerprint that was
  embedded in its install command. This gives an authenticated, encrypted
  channel without DNS or a public CA.
- Over that connection a [yamux](https://github.com/hashicorp/yamux) session
  multiplexes many streams. For every TCP connection that reaches a public port
  the server opens a stream and the client dials the target. For UDP, one
  stream is opened per remote peer and datagrams travel length-prefixed; idle
  peers are reaped after 90 seconds.
- Configuration lives in `<data-dir>/state.json` (`/var/lib/spawnrelay` on
  the VPS). Admin passwords are PBKDF2-hashed and API tokens are stored as
  SHA-256 hashes; client tokens are stored in clear so their install command
  can be shown again.

## Configuration reference

Server flags (each also readable from the environment variable in brackets):

| Flag | Default | Purpose |
|---|---|---|
| `--data-dir` `[SPAWNRELAY_DATA_DIR]` | `/var/lib/spawnrelay` (root) or `~/.spawnrelay` | state, certificates, client binaries in `bin/` |
| `--tunnel-addr` `[SPAWNRELAY_TUNNEL_ADDR]` | `:7443` | listener for clients |
| `--admin-addr` `[SPAWNRELAY_ADMIN_ADDR]` | `:8443` | HTTPS management UI/API |
| `--public-host` `[SPAWNRELAY_PUBLIC_HOST]` | detected | hostname/IP used in install commands and player addresses |
| `--admin-cert` / `--admin-key` | self-signed | your own certificate for the management interface |
| `--firewall-socket` `[SPAWNRELAY_FIREWALL_SOCKET]` | `<data-dir>/firewall.sock` | unix socket of the firewall agent |
| `--reset-admin-password` | – | generate a new admin password at start (written to `<data-dir>/initial-admin-password`) |
| `--log-level`, `--log-format` | `info`, `text` | logging |

Client flags: `--server host:port`, `--token`, `--fingerprint`, `--env-file`
(`[SPAWNRELAY_SERVER]`, `[SPAWNRELAY_TOKEN]`, `[SPAWNRELAY_FINGERPRINT]`).

Firewall agent flags (`spawnrelay firewall-agent`, run as root): `--data-dir`,
`--socket` (`[SPAWNRELAY_FIREWALL_SOCKET]`), `--log-level`, `--log-format`.
The backend is chosen from the server's settings on every request, so the
agent needs no configuration of its own.

Serving client binaries for other platforms: the server hands out its own
executable to clients on the same OS/architecture. For other platforms put
builds named `spawnrelay_<os>_<arch>[.exe]` into `<data-dir>/bin/`
(`make build-all` produces them in `dist/`; the server installer fetches them
from the GitHub release automatically).

## Development

```bash
make build            # bin/spawnrelay
make run-server       # server on 127.0.0.1 with ./dev-data, admin at https://127.0.0.1:8443
make build-all        # cross-compile into dist/
go test ./...
```

Lost the admin password? Stop the server, run it once with
`--reset-admin-password`, and read `<data-dir>/initial-admin-password`.

## License

MIT
