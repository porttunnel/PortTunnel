#!/usr/bin/env bash
set -euo pipefail

# === Config (change if you fork/move the binary) ===
PT_URL="https://github.com/ahm3d/PortTunnel/raw/refs/heads/main/dist/porttunnel"
PT_BIN="/usr/local/bin/porttunnel"
PT_USER="porttunnel"
PT_GROUP="porttunnel"
PT_ENV_DIR="/etc/porttunnel"
PT_ENV_FILE="${PT_ENV_DIR}/porttunnel.env"
PT_DATA_DIR="/var/lib/porttunnel"
PT_LOG_DIR="/var/log/porttunnel"
PT_SVC="/etc/systemd/system/porttunnel.service"

usage() {
  cat <<EOF
Usage: sudo $0 [install|update|uninstall|restart|status]

install   - Download and install PortTunnel binary and service (default)
update    - Re-download binary and restart service
uninstall - Stop service and remove files (keeps logs by default)
restart   - Restart the PortTunnel service
status    - Show systemd status
EOF
}

need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (use sudo)." >&2
    exit 1
  fi
}

detect_systemd() {
  if ! pidof systemd >/dev/null 2>&1; then
    echo "This script requires systemd." >&2
    exit 1
  fi
}

ensure_tools() {
  for t in curl install getent; do
    command -v "$t" >/dev/null 2>&1 || {
      echo "Missing required tool: $t" >&2
      exit 1
    }
  done
}

create_user() {
  if ! getent group "$PT_GROUP" >/dev/null; then
    groupadd --system "$PT_GROUP"
  fi
  if ! id "$PT_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$PT_DATA_DIR" --shell /usr/sbin/nologin -g "$PT_GROUP" "$PT_USER"
  fi
}

create_dirs() {
  install -d -m 0755 "$PT_ENV_DIR"
  install -d -m 0755 -o "$PT_USER" -g "$PT_GROUP" "$PT_DATA_DIR"
  install -d -m 0755 -o "$PT_USER" -g "$PT_GROUP" "$PT_LOG_DIR"
}

write_env() {
  if [[ ! -f "$PT_ENV_FILE" ]]; then
    cat >"$PT_ENV_FILE" <<'EOF'
# Environment config for PortTunnel service
# Add CLI flags to PT_OPTS, e.g.:
# PT_OPTS="--host 127.0.0.1 --port 8080"
PT_OPTS=""
EOF
    chmod 0644 "$PT_ENV_FILE"
  fi
}

download_binary() {
  echo "Downloading PortTunnel binary..."
  tmp="$(mktemp)"
  curl -fsSL "$PT_URL" -o "$tmp"
  chmod +x "$tmp"
  install -m 0755 "$tmp" "$PT_BIN"
  rm -f "$tmp"
  echo "Installed binary to $PT_BIN"
}

write_service() {
  cat >"$PT_SVC" <<EOF
[Unit]
Description=PortTunnel Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${PT_USER}
Group=${PT_GROUP}
EnvironmentFile=${PT_ENV_FILE}
WorkingDirectory=${PT_DATA_DIR}
ExecStart=${PT_BIN} \$PT_OPTS
Restart=on-failure
RestartSec=2

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectClock=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=${PT_DATA_DIR} ${PT_LOG_DIR}
StateDirectory=porttunnel
LogsDirectory=porttunnel
UMask=027

# If you need to bind ports <1024, uncomment:
# AmbientCapabilities=CAP_NET_BIND_SERVICE
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$PT_SVC"
}

daemon_reload_enable_start() {
  systemctl daemon-reload
  systemctl enable --now porttunnel.service
  systemctl --no-pager status porttunnel.service
}

do_install() {
  need_root
  detect_systemd
  ensure_tools
  create_user
  create_dirs
  write_env
  download_binary
  write_service
  daemon_reload_enable_start
  echo
  echo "✅ PortTunnel installed and running."
  echo "• Binary: $PT_BIN"
  echo "• Service: porttunnel.service"
  echo "• Env file (add flags in PT_OPTS): $PT_ENV_FILE"
  echo "• Data dir: $PT_DATA_DIR"
  echo "• Logs dir: $PT_LOG_DIR (journalctl -u porttunnel also works)"
}

do_update() {
  need_root
  ensure_tools
  download_binary
  systemctl restart porttunnel.service || true
  systemctl --no-pager status porttunnel.service
  echo "✅ PortTunnel updated."
}

do_uninstall() {
  need_root
  echo "Stopping and disabling service..."
  systemctl disable --now porttunnel.service || true
  echo "Removing files..."
  rm -f "$PT_SVC"
  systemctl daemon-reload || true
  rm -f "$PT_BIN"
  rm -rf "$PT_ENV_DIR"
  # Keep logs by default; uncomment next line to remove logs too:
  # rm -rf "$PT_LOG_DIR"
  # Remove user/group if desired (only if no other resources use them):
  if id "$PT_USER" >/dev/null 2>&1; then userdel "$PT_USER" || true; fi
  if getent group "$PT_GROUP" >/devNull 2>&1; then groupdel "$PT_GROUP" || true; fi
  echo "✅ PortTunnel uninstalled (logs kept in $PT_LOG_DIR)."
}

do_restart() {
  need_root
  systemctl restart porttunnel.service
  systemctl --no-pager status porttunnel.service
}

do_status() {
  systemctl --no-pager status porttunnel.service
  echo
  journalctl -u porttunnel -n 50 --no-pager || true
}

case "${1:-install}" in
  install)   do_install ;;
  update)    do_update ;;
  uninstall) do_uninstall ;;
  restart)   do_restart ;;
  status)    do_status ;;
  *)         usage; exit 1 ;;
esac

