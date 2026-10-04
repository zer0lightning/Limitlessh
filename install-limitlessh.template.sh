#!/usr/bin/env bash
# install-limitlessh.sh - install limitlessh, a hardened SSH tarpit inspired by
# endlessh (https://github.com/skeeto/endlessh), on Ubuntu.
#
# Self-contained: the limitlessh program is embedded at the bottom of this
# script. Run with --help for usage.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
VERSION="1.0.1"

# Defaults (environment variables also work, flags override them)
PORT="${PORT:-22}"                       # tarpit port
SSH_PORT="${SSH_PORT:-2200}"             # new port for the real sshd
DELAY="${DELAY:-10}"                     # seconds between banner lines
MAX_LINE="${MAX_LINE:-32}"
MAX_CLIENTS="${MAX_CLIENTS:-4096}"
PER_IP="${PER_IP:-8}"
PER_NET="${PER_NET:-32}"
MAX_LIFETIME="${MAX_LIFETIME:-0}"        # 0 = hold forever
SUMMARY_INTERVAL="${SUMMARY_INTERVAL:-600}"
LOG_LEVEL="${LOG_LEVEL:-info}"
MOVE_SSH=1
ASSUME_YES=0
ACTION="install"

PY_DIR="/usr/local/lib/limitlessh"
PY_BIN="$PY_DIR/limitlessh.py"
CONF_DIR="/etc/limitlessh"
CONF="$CONF_DIR/limitlessh.conf"
SOCKET_UNIT="/etc/systemd/system/limitlessh.socket"
SERVICE_UNIT="/etc/systemd/system/limitlessh.service"
SSHD_CONF="/etc/ssh/sshd_config"
SSH_SOCKET_OVERRIDE_DIR="/etc/systemd/system/ssh.socket.d"
SSH_SOCKET_OVERRIDE="$SSH_SOCKET_OVERRIDE_DIR/10-limitlessh-port.conf"
BACKUP_DIR="/root/limitlessh-ssh-backup-$(date +%Y%m%d-%H%M%S)"

usage() {
  cat <<EOF
$SCRIPT_NAME v$VERSION - install limitlessh, a hardened SSH tarpit (inspired by endlessh)

limitlessh holds SSH scanners and bots on an endless fake banner. Compared
with endlessh it limits connections per IP and per network, drops the oldest
connection from the busiest network when full (instead of going dead), never
reads client data, logs a summary instead of a line per connection, and runs
under systemd with no privileges and no network access of its own.

Usage:
  sudo $SCRIPT_NAME [options]
  sudo $SCRIPT_NAME --uninstall
  $SCRIPT_NAME --print-units [options]

Options:
  -p, --port PORT           Tarpit port                              (default: $PORT)
  -s, --ssh-port PORT       New port for the real sshd               (default: $SSH_PORT)
      --no-ssh-move         Never touch sshd; fail if it holds PORT
  -d, --delay SECONDS       Seconds between banner lines             (default: $DELAY)
  -l, --max-line N          Max banner line length, 3-253            (default: $MAX_LINE)
  -c, --max-clients N       Max clients held at once                 (default: $MAX_CLIENTS)
  -i, --per-ip N            Max clients per IP address               (default: $PER_IP)
  -n, --per-net N           Max clients per /24 (IPv4) or /64 (IPv6) (default: $PER_NET)
  -t, --max-lifetime SEC    Drop clients after SEC seconds, 0=never  (default: $MAX_LIFETIME)
      --summary-interval S  Seconds between summary log lines, 0=off (default: $SUMMARY_INTERVAL)
  -v, --log-level LEVEL     debug, info, warning or error            (default: $LOG_LEVEL)
  -y, --yes                 Don't ask for confirmation
      --print-units         Print the config and systemd units that would be
                            installed, then exit (no root needed)
  -u, --uninstall           Remove limitlessh (does not change sshd back)
  -h, --help                Show this help and exit
  -V, --version             Show version and exit

Environment variables PORT, SSH_PORT, DELAY, MAX_LINE, MAX_CLIENTS, PER_IP,
PER_NET, MAX_LIFETIME, SUMMARY_INTERVAL and LOG_LEVEL set the same defaults.

Examples:
  sudo $SCRIPT_NAME                          # sshd -> 2200, tarpit -> 22
  sudo $SCRIPT_NAME -s 4822                  # sshd -> 4822, tarpit -> 22
  sudo $SCRIPT_NAME -p 2222 --no-ssh-move    # tarpit on 2222, sshd untouched
  sudo $SCRIPT_NAME --uninstall

After installing:
  journalctl -u limitlessh -f               # logs (a summary every 10 min)
  sudo systemctl kill -s USR1 limitlessh    # log current stats now
  sudo systemctl reload limitlessh          # re-read $CONF

IMPORTANT: keep an existing SSH session open while this runs. Afterwards,
test 'ssh -p <ssh-port> user@host' from a new terminal before closing it,
and open the new port in any cloud firewall / security group.
EOF
}

usage_error() { echo "$SCRIPT_NAME: $*" >&2; echo "Try '$SCRIPT_NAME --help'." >&2; exit 2; }
need_arg() { [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || usage_error "option '$1' requires a value"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--port)          need_arg "$@"; PORT="$2"; shift 2 ;;
    --port=*)           PORT="${1#*=}"; shift ;;
    -s|--ssh-port)      need_arg "$@"; SSH_PORT="$2"; shift 2 ;;
    --ssh-port=*)       SSH_PORT="${1#*=}"; shift ;;
    --no-ssh-move)      MOVE_SSH=0; shift ;;
    -d|--delay)         need_arg "$@"; DELAY="$2"; shift 2 ;;
    --delay=*)          DELAY="${1#*=}"; shift ;;
    -l|--max-line)      need_arg "$@"; MAX_LINE="$2"; shift 2 ;;
    --max-line=*)       MAX_LINE="${1#*=}"; shift ;;
    -c|--max-clients)   need_arg "$@"; MAX_CLIENTS="$2"; shift 2 ;;
    --max-clients=*)    MAX_CLIENTS="${1#*=}"; shift ;;
    -i|--per-ip)        need_arg "$@"; PER_IP="$2"; shift 2 ;;
    --per-ip=*)         PER_IP="${1#*=}"; shift ;;
    -n|--per-net)       need_arg "$@"; PER_NET="$2"; shift 2 ;;
    --per-net=*)        PER_NET="${1#*=}"; shift ;;
    -t|--max-lifetime)  need_arg "$@"; MAX_LIFETIME="$2"; shift 2 ;;
    --max-lifetime=*)   MAX_LIFETIME="${1#*=}"; shift ;;
    --summary-interval) need_arg "$@"; SUMMARY_INTERVAL="$2"; shift 2 ;;
    --summary-interval=*) SUMMARY_INTERVAL="${1#*=}"; shift ;;
    -v|--log-level)     need_arg "$@"; LOG_LEVEL="$2"; shift 2 ;;
    --log-level=*)      LOG_LEVEL="${1#*=}"; shift ;;
    -y|--yes)           ASSUME_YES=1; shift ;;
    --print-units)      ACTION="print"; shift ;;
    -u|--uninstall)     ACTION="uninstall"; shift ;;
    -h|--help|-help|help) usage; exit 0 ;;
    -V|--version)       echo "$SCRIPT_NAME v$VERSION"; exit 0 ;;
    --) shift; break ;;
    *)  usage_error "unknown option '$1'" ;;
  esac
done

# Digit counts are capped so bash arithmetic can't overflow and wrap an
# out-of-range value into a valid-looking one.
is_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
is_uint() { [[ "$1" =~ ^[0-9]{1,7}$ ]]; }
is_num()  { [[ "$1" =~ ^[0-9]{1,8}([.][0-9]{1,6})?$ ]]; }

if [[ "$ACTION" != "uninstall" ]]; then
  is_port "$PORT"     || usage_error "invalid --port '$PORT' (1-65535)"
  is_port "$SSH_PORT" || usage_error "invalid --ssh-port '$SSH_PORT' (1-65535)"
  (( 10#$PORT != 10#$SSH_PORT )) || usage_error "--port and --ssh-port must differ"
  is_num "$DELAY"            || usage_error "invalid --delay '$DELAY'"
  is_uint "$MAX_LINE"        || usage_error "invalid --max-line '$MAX_LINE'"
  is_uint "$MAX_CLIENTS"     || usage_error "invalid --max-clients '$MAX_CLIENTS'"
  is_uint "$PER_IP"          || usage_error "invalid --per-ip '$PER_IP'"
  is_uint "$PER_NET"         || usage_error "invalid --per-net '$PER_NET'"
  is_num "$MAX_LIFETIME"     || usage_error "invalid --max-lifetime '$MAX_LIFETIME'"
  is_num "$SUMMARY_INTERVAL" || usage_error "invalid --summary-interval '$SUMMARY_INTERVAL'"
  [[ "$LOG_LEVEL" =~ ^(debug|info|warning|error|0|1|2)$ ]] \
    || usage_error "invalid --log-level '$LOG_LEVEL' (debug, info, warning, error)"
  # limitlessh itself checks ranges (e.g. max-line 3-253) before anything changes
  PORT=$((10#$PORT)); SSH_PORT=$((10#$SSH_PORT)); MAX_CLIENTS=$((10#$MAX_CLIENTS))
fi

log() { echo "==> $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Generated files
# ---------------------------------------------------------------------------
NOFILE=$(( MAX_CLIENTS + 256 ))
MEMORY_MAX_MB=$(( MAX_CLIENTS * 16 / 1024 + 64 ))
(( MEMORY_MAX_MB >= 128 )) || MEMORY_MAX_MB=128

config_text() {
  cat <<EOF
# limitlessh configuration - see: $PY_BIN --help
# Apply changes with: sudo systemctl reload limitlessh
# The listening port is set in $SOCKET_UNIT (ListenStream=).
delay            = $DELAY
max-line         = $MAX_LINE
max-clients      = $MAX_CLIENTS
per-ip           = $PER_IP
per-net          = $PER_NET
ipv4-prefix      = 24
ipv6-prefix      = 64
max-lifetime     = $MAX_LIFETIME
summary-interval = $SUMMARY_INTERVAL
log-level        = $LOG_LEVEL
EOF
}

socket_unit_text() {
  cat <<EOF
[Unit]
Description=limitlessh SSH tarpit (listening socket)
Documentation=https://github.com/skeeto/endlessh

[Socket]
ListenStream=$PORT
BindIPv6Only=both
Backlog=4096
# Small buffers from the handshake on, so clients can't park data in kernel memory
ReceiveBuffer=1024
SendBuffer=2048

[Install]
WantedBy=sockets.target
EOF
}

service_unit_text() {
  cat <<EOF
[Unit]
Description=limitlessh SSH tarpit (inspired by endlessh)
Documentation=https://github.com/skeeto/endlessh
Requires=limitlessh.socket
After=limitlessh.socket

[Service]
Type=simple
ExecStart=/usr/bin/python3 -I -B $PY_BIN --config $CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Resources
LimitNOFILE=$NOFILE
MemoryMax=${MEMORY_MAX_MB}M
TasksMax=16
# Under a connection flood, yield CPU to everything else (including sshd)
CPUWeight=20

# Identity: a throwaway user with no capabilities
DynamicUser=yes
PrivateUsers=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

# No network of its own: systemd hands over the listening socket, so even a
# compromised process can't open connections anywhere.
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX

# Filesystem and kernel
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectProc=invisible
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
UMask=0077

# System calls
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF
}

write_program() {  # $1 = destination
  cat > "$1" <<'LIMITLESSH_PY_EOF'
@@LIMITLESSH_PY@@
LIMITLESSH_PY_EOF
}

check_settings() {  # validate with limitlessh's own rules before changing anything
  local tmp; tmp="$(mktemp)"
  write_program "$tmp"
  local conf; conf="$(mktemp /tmp/limitlessh-settings.XXXXXX)"
  config_text > "$conf"
  if ! python3 -I -B "$tmp" --config "$conf" --check-config >/dev/null; then
    rm -f "$tmp" "$conf"
    exit 2
  fi
  rm -f "$tmp" "$conf"
}

if [[ "$ACTION" == "print" ]]; then
  if command -v python3 >/dev/null; then check_settings; fi
  echo "# ---- $CONF";         config_text;        echo
  echo "# ---- $SOCKET_UNIT";  socket_unit_text;   echo
  echo "# ---- $SERVICE_UNIT"; service_unit_text
  exit 0
fi

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0  (see --help)"

confirm() {
  (( ASSUME_YES )) && return 0
  [[ -t 0 ]] || die "Not running interactively; re-run with --yes to confirm."
  local reply
  read -r -p "$1 [y/N] " reply
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]] || { echo "Aborted."; exit 1; }
}

ufw_active() { command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; }

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if [[ "$ACTION" == "uninstall" ]]; then
  confirm "Remove limitlessh (units, program, config)?"
  OLD_PORT="$(sed -n 's/^ListenStream=\([0-9]*\)$/\1/p' "$SOCKET_UNIT" 2>/dev/null | head -1 || true)"
  log "Stopping and removing limitlessh"
  systemctl disable --now limitlessh.socket limitlessh.service 2>/dev/null || true
  rm -f "$SOCKET_UNIT" "$SERVICE_UNIT"
  rm -rf "$PY_DIR" "$CONF_DIR"
  systemctl daemon-reload
  # Leave a port-22 rule alone so restoring sshd to 22 can't lock you out
  if [[ -n "$OLD_PORT" && "$OLD_PORT" != "22" ]] && ufw_active; then
    ufw delete allow "${OLD_PORT}/tcp" >/dev/null 2>&1 || true
    log "Removed ufw rule for ${OLD_PORT}/tcp (if it existed)"
  fi
  echo "limitlessh removed."
  echo "sshd was NOT changed. To restore its old config, copy back a backup from"
  echo "/root/limitlessh-ssh-backup-*/ssh and remove $SSH_SOCKET_OVERRIDE if present."
  exit 0
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if ! command -v python3 >/dev/null; then
  log "Installing python3"
  apt-get update -y
  apt-get install -y python3
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
  || die "Python 3.8 or newer is required (found $(python3 -V 2>&1))"
SYSTEMD_VER="$(systemctl --version | awk 'NR==1{print $2}')"
[[ "$SYSTEMD_VER" =~ ^[0-9]+$ ]] && (( SYSTEMD_VER >= 247 )) \
  || die "systemd 247 or newer is required (Ubuntu 22.04+); found ${SYSTEMD_VER:-unknown}"
check_settings

port_in_use() { [[ -n "$(ss -ltnH "sport = :$1" 2>/dev/null)" ]]; }

socket_listens_on() {  # $1 = socket unit, $2 = port
  systemctl is-active --quiet "$1" 2>/dev/null \
    && systemctl show -p Listen --value "$1" 2>/dev/null | grep -qE ":$2 \("
}

listener_exes() {  # executables of processes listening on port $1
  local pid
  ss -ltnpH "sport = :$1" 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u |
    while read -r pid; do readlink -f "/proc/$pid/exe" 2>/dev/null || true; done
}

port_holder() {  # prints none | self | ssh | endlessh | other
  # Owners are identified by executable path or systemd unit state. Process
  # names are not trusted: any local user can name a process "sshd".
  local exes sshd_bin
  port_in_use "$1" || { echo none; return; }
  exes="$(listener_exes "$1")"
  sshd_bin="$(readlink -f "$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)")"
  if socket_listens_on limitlessh.socket "$1"; then echo self
  elif socket_listens_on ssh.socket "$1" || grep -qxF "$sshd_bin" <<<"$exes"; then echo ssh
  elif systemctl is-active --quiet endlessh 2>/dev/null \
       && grep -qxE '/usr/(local/)?bin/endlessh' <<<"$exes"; then echo endlessh
  else echo other
  fi
}

ssh_socket_mode() {
  systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null
}

# ---------------------------------------------------------------------------
# Move sshd off the tarpit port
# ---------------------------------------------------------------------------
rollback_ssh() {
  echo "!! Rolling back SSH changes from $BACKUP_DIR" >&2
  cp -a "$BACKUP_DIR/ssh/." /etc/ssh/
  rm -f "$SSH_SOCKET_OVERRIDE"
  systemctl daemon-reload
  if ssh_socket_mode; then systemctl restart ssh.socket || true; fi
  systemctl restart ssh || true
}

move_ssh() {
  port_in_use "$SSH_PORT" && die "Port $SSH_PORT is already in use; choose another --ssh-port."

  log "Moving sshd from port $PORT to $SSH_PORT (backup: $BACKUP_DIR)"
  mkdir -p "$BACKUP_DIR"
  cp -a /etc/ssh "$BACKUP_DIR/ssh"

  # Firewall first, so we can't lock ourselves out
  if ufw_active; then
    log "Allowing ${SSH_PORT}/tcp in ufw"
    ufw allow "${SSH_PORT}/tcp" comment 'sshd'
  fi

  # Port directives are cumulative, so comment out every existing one
  # (main config and drop-ins), then set the new port in the main config.
  sed -i -E 's/^[[:space:]]*Port[[:space:]]+/#&/' "$SSHD_CONF"
  if compgen -G "/etc/ssh/sshd_config.d/*.conf" >/dev/null; then
    sed -i -E 's/^[[:space:]]*Port[[:space:]]+/#&/' /etc/ssh/sshd_config.d/*.conf
  fi
  if grep -qE '^[[:space:]]*Match[[:space:]]' "$SSHD_CONF"; then
    sed -i -E "0,/^[[:space:]]*Match[[:space:]]/s//Port ${SSH_PORT}\n&/" "$SSHD_CONF"
  else
    echo "Port ${SSH_PORT}" >> "$SSHD_CONF"
  fi

  mkdir -p /run/sshd
  if ! sshd -t; then rollback_ssh; die "sshd config test failed; changes rolled back."; fi

  # Ubuntu 22.10+ uses socket activation; 22.10/23.04 ignore sshd_config's
  # Port, and on 24.04+ this override is harmless and takes precedence.
  if ssh_socket_mode; then
    log "ssh.socket detected; writing override"
    mkdir -p "$SSH_SOCKET_OVERRIDE_DIR"
    printf '[Socket]\nListenStream=\nListenStream=%s\n' "$SSH_PORT" > "$SSH_SOCKET_OVERRIDE"
    systemctl daemon-reload
    systemctl restart ssh.socket
    systemctl restart ssh 2>/dev/null || true
  else
    systemctl daemon-reload
    systemctl restart ssh
  fi

  sleep 2
  if ! port_in_use "$SSH_PORT"; then
    rollback_ssh
    die "sshd is not listening on $SSH_PORT; changes rolled back."
  fi
  if port_in_use "$PORT"; then
    rollback_ssh
    die "Port $PORT is still in use after moving sshd; changes rolled back."
  fi
  log "sshd is now listening on port $SSH_PORT"
}

case "$(port_holder "$PORT")" in
  none) ;;
  self)
    log "Reinstalling over the existing limitlessh on port $PORT"
    systemctl stop limitlessh.socket limitlessh.service 2>/dev/null || true
    ;;
  ssh)
    (( MOVE_SSH )) || die "sshd is listening on port $PORT and --no-ssh-move was given.
Choose another --port, or drop --no-ssh-move to move sshd to $SSH_PORT."
    confirm "sshd is on port $PORT. Move it to port $SSH_PORT and put limitlessh on $PORT?"
    move_ssh
    ;;
  endlessh)
    confirm "endlessh is on port $PORT. Stop and disable it so limitlessh can replace it?"
    systemctl disable --now endlessh 2>/dev/null || true
    sleep 1
    port_in_use "$PORT" && die "endlessh still holds port $PORT; stop it manually and re-run."
    log "endlessh stopped and disabled (its files are left in place)"
    ;;
  other)
    die "Port $PORT is used by something else:
$(ss -ltnpH "sport = :$PORT")"
    ;;
esac

# Any leftover limitlessh units on a different port are replaced below
systemctl stop limitlessh.socket limitlessh.service 2>/dev/null || true

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
safe_dir() {  # create root-owned dir; refuse symlinks
  [[ -L "$1" ]] && die "$1 is a symlink; refusing to install there"
  install -d -m 0755 -o root -g root "$1"
  chown root:root "$1"; chmod 0755 "$1"
}

log "Installing $PY_BIN"
safe_dir "$PY_DIR"
PY_TMP="$(mktemp "$PY_DIR/.limitlessh.XXXXXX")"
write_program "$PY_TMP"
chmod 0755 "$PY_TMP"
mv -f "$PY_TMP" "$PY_BIN"

log "Writing $CONF"
safe_dir "$CONF_DIR"
[[ -f "$CONF" ]] && cp -a "$CONF" "$CONF.bak"
config_text > "$CONF"
chmod 0644 "$CONF"

log "Installing systemd units"
socket_unit_text  > "$SOCKET_UNIT"
service_unit_text > "$SERVICE_UNIT"
chmod 0644 "$SOCKET_UNIT" "$SERVICE_UNIT"

systemctl daemon-reload
systemctl enable --now limitlessh.socket
systemctl enable limitlessh.service >/dev/null 2>&1 || true
systemctl start limitlessh.service

if ufw_active; then
  log "Allowing ${PORT}/tcp in ufw"
  ufw allow "${PORT}/tcp" comment 'limitlessh tarpit'
fi

# ---------------------------------------------------------------------------
# Verify: connect and expect a banner line
# ---------------------------------------------------------------------------
log "Testing the tarpit on port $PORT"
if timeout 6 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT && head -c 1 <&3 >/dev/null" 2>/dev/null \
   && systemctl is-active --quiet limitlessh.service; then
  log "Tarpit answered with a banner"
else
  journalctl -u limitlessh -n 20 --no-pager >&2 || true
  die "limitlessh is not answering on port $PORT (see log above)."
fi

echo
echo "Done."
echo "  limitlessh tarpit : port ${PORT}"
echo "  config            : $CONF  (apply with: sudo systemctl reload limitlessh)"
echo "  logs              : journalctl -u limitlessh -f"
echo "  stats now         : sudo systemctl kill -s USR1 limitlessh"
if [[ -d "$BACKUP_DIR" ]]; then
  echo "  real sshd         : port ${SSH_PORT}  (backup of /etc/ssh in $BACKUP_DIR)"
  echo
  echo "  BEFORE closing this session, test from a NEW terminal:"
  echo "      ssh -p ${SSH_PORT} ${SUDO_USER:-user}@<this-server>"
  echo "  If your host has a cloud firewall / security group, open ${SSH_PORT}/tcp there too."
fi
