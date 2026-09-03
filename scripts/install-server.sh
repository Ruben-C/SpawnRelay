#!/usr/bin/env bash
# SpawnRelay server installer (Linux + systemd).
#
#   curl -fsSL https://raw.githubusercontent.com/Ruben-C/SpawnRelay/main/scripts/install-server.sh | sudo bash
#
# Environment overrides:
#   SPAWNRELAY_REPO         GitHub repo to download releases from (default Ruben-C/SpawnRelay)
#   SPAWNRELAY_VERSION      release tag to install (default: latest)
#   SPAWNRELAY_BINARY       path to a locally built spawnrelay binary (skips download)
#   SPAWNRELAY_BIN_SOURCE   directory of client binaries (spawnrelay_<os>_<arch>[.exe]) to publish
#   SPAWNRELAY_TUNNEL_PORT  tunnel port clients connect to (default 7443)
#   SPAWNRELAY_ADMIN_PORT   management UI/API HTTPS port (default 8443)
#   SPAWNRELAY_PUBLIC_HOST  public hostname/IP (default: auto-detected public IP)
set -euo pipefail

REPO="${SPAWNRELAY_REPO:-Ruben-C/SpawnRelay}"
VERSION="${SPAWNRELAY_VERSION:-latest}"
TUNNEL_PORT="${SPAWNRELAY_TUNNEL_PORT:-7443}"
ADMIN_PORT="${SPAWNRELAY_ADMIN_PORT:-8443}"
DATA_DIR=/var/lib/spawnrelay
CONF_DIR=/etc/spawnrelay
BIN=/usr/local/bin/spawnrelay
SVC_USER=spawnrelay

log() { printf '\033[1;36m[spawnrelay]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[spawnrelay] error:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (pipe into 'sudo bash')"
[ "$(uname -s)" = "Linux" ] || die "the server installer supports Linux only"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
command -v curl >/dev/null 2>&1 || die "curl is required"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l) ARCH=arm ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

release_url() { # $1 = asset name
  if [ "$VERSION" = "latest" ]; then
    echo "https://github.com/${REPO}/releases/latest/download/$1"
  else
    echo "https://github.com/${REPO}/releases/download/${VERSION}/$1"
  fi
}

# ---- binary ---------------------------------------------------------------
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
if [ -n "${SPAWNRELAY_BINARY:-}" ]; then
  log "using local binary ${SPAWNRELAY_BINARY}"
  install -m 0755 "${SPAWNRELAY_BINARY}" "$BIN"
elif [ -f go.mod ] && command -v go >/dev/null 2>&1; then
  log "building from source with $(go version | cut -d' ' -f3)"
  go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" -o "$tmpdir/spawnrelay" ./cmd/spawnrelay
  install -m 0755 "$tmpdir/spawnrelay" "$BIN"
else
  asset="spawnrelay_linux_${ARCH}.tar.gz"
  log "downloading $(release_url "$asset")"
  curl -fsSL "$(release_url "$asset")" -o "$tmpdir/$asset" || die "download failed; set SPAWNRELAY_BINARY to a local build"
  tar -xzf "$tmpdir/$asset" -C "$tmpdir"
  install -m 0755 "$tmpdir/spawnrelay" "$BIN"
fi
log "installed $BIN ($("$BIN" version))"

# ---- user, directories ------------------------------------------------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
fi
mkdir -p "$DATA_DIR/bin" "$CONF_DIR"
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"
chmod 0700 "$DATA_DIR"

# Client binaries for other platforms (served at /dl/...). Best effort.
if [ -n "${SPAWNRELAY_BIN_SOURCE:-}" ]; then
  cp -f "${SPAWNRELAY_BIN_SOURCE}"/spawnrelay_* "$DATA_DIR/bin/" 2>/dev/null || true
elif [ -z "${SPAWNRELAY_BINARY:-}" ] && [ ! -f go.mod ]; then
  for target in linux_amd64 linux_arm64 linux_arm darwin_amd64 darwin_arm64 windows_amd64.exe windows_arm64.exe; do
    if curl -fsSL "$(release_url "spawnrelay_${target}")" -o "$DATA_DIR/bin/spawnrelay_${target}" 2>/dev/null; then
      chmod 0755 "$DATA_DIR/bin/spawnrelay_${target}"
    fi
  done
fi
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR/bin"

# ---- configuration ---------------------------------------------------------
PUBLIC_HOST="${SPAWNRELAY_PUBLIC_HOST:-}"
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)"
fi
if [ ! -f "$CONF_DIR/server.env" ]; then
  umask 077
  cat >"$CONF_DIR/server.env" <<ENV
# SpawnRelay server configuration. Restart with: systemctl restart spawnrelay-server
SPAWNRELAY_DATA_DIR=${DATA_DIR}
SPAWNRELAY_TUNNEL_ADDR=:${TUNNEL_PORT}
SPAWNRELAY_ADMIN_ADDR=:${ADMIN_PORT}
SPAWNRELAY_PUBLIC_HOST=${PUBLIC_HOST}
# Optional: use your own certificate for the management interface
#SPAWNRELAY_ADMIN_CERT=/etc/letsencrypt/live/relay.example.com/fullchain.pem
#SPAWNRELAY_ADMIN_KEY=/etc/letsencrypt/live/relay.example.com/privkey.pem
ENV
  chmod 0640 "$CONF_DIR/server.env"
  chown root:"$SVC_USER" "$CONF_DIR/server.env"
  log "wrote $CONF_DIR/server.env"
else
  log "keeping existing $CONF_DIR/server.env"
fi

# The firewall agent runs as root so the relay server itself never needs
# firewall privileges. It only ever adds/removes rules tagged "spawnrelay:".
cat >/etc/systemd/system/spawnrelay-firewall.service <<UNIT
[Unit]
Description=SpawnRelay firewall agent (opens/closes relay ports in the host firewall)
After=network-online.target ufw.service firewalld.service nftables.service
Wants=network-online.target

[Service]
EnvironmentFile=${CONF_DIR}/server.env
ExecStart=${BIN} firewall-agent
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/spawnrelay-server.service <<UNIT
[Unit]
Description=SpawnRelay relay server
After=network-online.target spawnrelay-firewall.service
Wants=network-online.target spawnrelay-firewall.service

[Service]
User=${SVC_USER}
Group=${SVC_USER}
EnvironmentFile=${CONF_DIR}/server.env
ExecStart=${BIN} server
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${DATA_DIR}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now spawnrelay-firewall.service
systemctl restart spawnrelay-firewall.service
systemctl enable --now spawnrelay-server.service
systemctl restart spawnrelay-server.service

# ---- summary ---------------------------------------------------------------
for _ in $(seq 1 20); do
  [ -f "$DATA_DIR/initial-admin-password" ] && break
  sleep 0.5
done
FINGERPRINT="$(openssl x509 -in "$DATA_DIR/tunnel.crt" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f' || true)"

echo
log "SpawnRelay server is running."
echo
echo "  Management UI : https://${PUBLIC_HOST:-<this-server-ip>}:${ADMIN_PORT}"
echo "  Username      : admin"
if [ -f "$DATA_DIR/initial-admin-password" ]; then
  echo "  Password      : $(cat "$DATA_DIR/initial-admin-password")"
  echo "                  (stored in $DATA_DIR/initial-admin-password until you change it)"
else
  echo "  Password      : unchanged (already configured)"
fi
echo "  Tunnel port   : ${TUNNEL_PORT}/tcp"
[ -n "$FINGERPRINT" ] && echo "  Fingerprint   : sha256:${FINGERPRINT}"
echo
echo "  The UI uses a self-signed certificate; your browser will warn once."
echo "  Host firewall : managed by spawnrelay-firewall (ufw/firewalld/nftables/iptables detected"
echo "                  automatically; see Settings in the UI). It opens ${TUNNEL_PORT}/tcp,"
echo "                  ${ADMIN_PORT}/tcp and every forward you create."
echo "  If this VPS sits behind a cloud security group, open those ports there too."
echo "  Logs: journalctl -u spawnrelay-server -u spawnrelay-firewall -f"
