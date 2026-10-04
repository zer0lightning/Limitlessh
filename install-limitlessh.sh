#!/usr/bin/env bash
# install-limitlessh.sh - install limitlessh, a hardened SSH tarpit inspired by
# endlessh (https://github.com/skeeto/endlessh), on Ubuntu.
#
# Self-contained: limitlessh and limitlessh-report are embedded in this
# script. Run with --help for usage.

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
VERSION="1.1.0"

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
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-90}"
GEO_EDITION="${GEO_EDITION:-city}"       # city | country
CONN_LOG=1
GEO=1
PURGE=0
MOVE_SSH=1
ASSUME_YES=0
ACTION="install"

PY_DIR="/usr/local/lib/limitlessh"
PY_BIN="$PY_DIR/limitlessh.py"
REPORT_BIN="$PY_DIR/limitlessh-report.py"
REPORT_LINK="/usr/local/bin/limitlessh-report"
GEO_SERVICE_UNIT="/etc/systemd/system/limitlessh-geoupdate.service"
GEO_TIMER_UNIT="/etc/systemd/system/limitlessh-geoupdate.timer"
STATE_DIR="/var/lib/limitlessh"
LOGS_DIR="/var/log/limitlessh"
GEO_DIR="/var/lib/limitlessh-geo"
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
reads client data, and runs under systemd with no privileges and no network
access of its own. It records every connection to a rotated JSON log, and
limitlessh-report turns that into reports with country, city, ASN and ISP.

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
      --log-retention-days N  Keep connection logs N days, 0=by count  (default: $LOG_RETENTION_DAYS)
      --no-connection-log   Don't record connections (no reports)
      --geo-edition E       Geolocation database: city (~250 MB) or
                            country (~10 MB), plus ASN (~25 MB)      (default: $GEO_EDITION)
      --no-geo              Don't download geolocation databases
  -y, --yes                 Don't ask for confirmation
      --print-units         Print the config and systemd units that would be
                            installed, then exit (no root needed)
  -u, --uninstall           Remove limitlessh (does not change sshd back)
      --purge               With --uninstall: also delete logs, stats and
                            geolocation databases
  -h, --help                Show this help and exit
  -V, --version             Show version and exit

Environment variables PORT, SSH_PORT, DELAY, MAX_LINE, MAX_CLIENTS, PER_IP,
PER_NET, MAX_LIFETIME, SUMMARY_INTERVAL, LOG_LEVEL, LOG_RETENTION_DAYS and
GEO_EDITION set the same defaults.

Examples:
  sudo $SCRIPT_NAME                          # sshd -> 2200, tarpit -> 22
  sudo $SCRIPT_NAME -s 4822                  # sshd -> 4822, tarpit -> 22
  sudo $SCRIPT_NAME -p 2222 --no-ssh-move    # tarpit on 2222, sshd untouched
  sudo $SCRIPT_NAME --uninstall

After installing:
  sudo limitlessh-report                    # report for the last 7 days
  sudo limitlessh-report --ip 203.0.113.7   # history of one IP
  sudo limitlessh-report --csv out.csv      # raw records with geolocation
  journalctl -u limitlessh -f               # service log (a summary every 10 min)
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
    --log-retention-days) need_arg "$@"; LOG_RETENTION_DAYS="$2"; shift 2 ;;
    --log-retention-days=*) LOG_RETENTION_DAYS="${1#*=}"; shift ;;
    --no-connection-log) CONN_LOG=0; shift ;;
    --geo-edition)      need_arg "$@"; GEO_EDITION="$2"; shift 2 ;;
    --geo-edition=*)    GEO_EDITION="${1#*=}"; shift ;;
    --no-geo)           GEO=0; shift ;;
    --purge)            PURGE=1; shift ;;
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
  is_num "$LOG_RETENTION_DAYS" || usage_error "invalid --log-retention-days '$LOG_RETENTION_DAYS'"
  [[ "$GEO_EDITION" =~ ^(city|country)$ ]] || usage_error "invalid --geo-edition '$GEO_EDITION' (city or country)"
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

# Connection log (JSON lines) and stats, read by limitlessh-report.
# Comment out log-file to stop recording IP addresses.
$(if (( CONN_LOG )); then echo "log-file           = $LOGS_DIR/connections.log"; else echo "# log-file         = $LOGS_DIR/connections.log"; fi)
log-max-size       = 20
log-max-files      = 50
log-retention-days = $LOG_RETENTION_DAYS
log-rate           = 200
stats-file         = $STATE_DIR/stats.json
stats-interval     = 60
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

# Writable places: logs and stats only (owned by the throwaway user, root can read)
StateDirectory=limitlessh
StateDirectoryMode=0700
LogsDirectory=limitlessh
LogsDirectoryMode=0700

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

geo_service_text() {
  cat <<EOF
[Unit]
Description=limitlessh: update geolocation databases (DB-IP Lite, CC BY 4.0)
Documentation=https://db-ip.com/db/lite.php
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -B $REPORT_BIN --update-geo --geo-edition $GEO_EDITION --geo-dir $GEO_DIR --quiet
TimeoutStartSec=30min
Nice=10
IOSchedulingClass=idle
MemoryMax=512M
TasksMax=8

StateDirectory=limitlessh-geo
StateDirectoryMode=0755
DynamicUser=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
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
UMask=0022
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
EOF
}

geo_timer_text() {
  cat <<EOF
[Unit]
Description=limitlessh: monthly geolocation database update

[Timer]
OnCalendar=*-*-05 04:00:00
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

write_program() {  # $1 = destination
  cat > "$1" <<'LIMITLESSH_PY_EOF'
#!/usr/bin/env python3
"""
limitlessh - a hardened SSH tarpit, inspired by endlessh
(https://github.com/skeeto/endlessh by Chris Wellons).

It accepts SSH connections and trickles an endless, random pre-banner at
them, so scanners and bots waste their time instead of yours.

What it does differently from endlessh:
  * Never reads what clients send. Reading is paused and kernel buffers are
    kept tiny, so there is no parser to attack and clients can't make it
    grow its memory.
  * Always accepts, then enforces per-IP, per-network and global limits, so
    the listen queue never fills and one host can't switch the tarpit off.
  * When full, it drops the oldest connection from the busiest network
    instead of refusing newcomers.
  * Drops clients that stop reading, and optionally clients held too long.
  * Logs a periodic summary instead of a line per connection, and can write
    a rotated, rate-capped JSON log of every connection plus lifetime stats
    for the limitlessh-report tool.
  * Supports systemd socket activation, so it can run with no privileges and
    no network access of its own.

Python 3.8+ standard library only. Linux recommended.
"""

import argparse
import asyncio
import collections
import concurrent.futures
import datetime
import glob
import gzip
import ipaddress
import json
import logging
import math
import os
import random
import resource
import shutil
import signal
import socket
import string
import sys
import time

VERSION = "1.1.0"
PROG = "limitlessh"
LOG = logging.getLogger(PROG)

# Bytes we let asyncio buffer per client before deciding it has stopped
# reading. Lines are at most 255 bytes, so this is only reached once the
# kernel's send buffer is already full.
WRITE_HIGH_WATER = 1024
# Spare file descriptors kept for the listener, logging and the event loop.
FD_HEADROOM = 128
# Distinct source addresses remembered per summary window. Without a cap an
# attacker rotating addresses (trivial with an IPv6 prefix) grows this table
# until the service runs out of memory. Extra sources are only counted.
MAX_TRACKED_SOURCES = 10000
# Kernel buffer sizes. Set on the listening socket so accepted connections
# get them from the handshake: setting them after accept() is too late, the
# TCP window is already agreed and a client can park ~32 KiB in the kernel.
RCVBUF_BYTES = 1024
SNDBUF_BYTES = 2048
LINE_ALPHABET = (string.ascii_letters + string.digits + string.punctuation + " ").encode()


class ConfigError(Exception):
    pass


# ---------------------------------------------------------------------------
# Options: one table drives the command line, the config file and validation
# ---------------------------------------------------------------------------

def _ranged(cast, lo, hi):
    def convert(value):
        try:
            x = cast(value)
        except (TypeError, ValueError):
            raise ValueError("expected %s, got %r" % (cast.__name__, value))
        if x != x or x < lo or x > hi:  # x != x catches NaN
            raise ValueError("must be between %s and %s, got %s" % (lo, hi, value))
        return x
    convert.__name__ = cast.__name__
    return convert


def _log_level(value):
    v = str(value).strip().lower()
    v = {"0": "warning", "1": "info", "2": "debug", "quiet": "warning", "warn": "warning"}.get(v, v)
    if v not in ("debug", "info", "warning", "error"):
        raise ValueError("must be debug, info, warning or error (or 0/1/2), got %r" % value)
    return v


def _path(value):
    v = str(value).strip()
    if v == "":
        return ""
    if not os.path.isabs(v) or any(c in v for c in "\0\n\r"):
        raise ValueError("must be an absolute path or empty, got %r" % value)
    return os.path.normpath(v)


def _bind_addr(value):
    v = str(value).strip()
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValueError("must be an IP address such as :: or 0.0.0.0, got %r" % value)
    return v


# name, converter, default, help
OPTIONS = [
    ("port", _ranged(int, 1, 65535), 2222,
     "TCP port to listen on (ignored when socket-activated by systemd)"),
    ("bind", _bind_addr, "::",
     "address to listen on; '::' means all IPv4 and IPv6 (ignored when socket-activated)"),
    ("delay", _ranged(float, 0.1, 3600.0), 10.0,
     "seconds between banner lines"),
    ("jitter", _ranged(float, 0.0, 0.9), 0.3,
     "random +/- fraction applied to each delay"),
    ("max-line", _ranged(int, 3, 253), 32,
     "maximum banner line length in bytes, excluding CRLF"),
    ("max-clients", _ranged(int, 1, 1000000), 4096,
     "maximum clients held at once; when full the oldest from the busiest network is dropped"),
    ("per-ip", _ranged(int, 1, 1000000), 8,
     "maximum clients held per IP address"),
    ("per-net", _ranged(int, 1, 1000000), 32,
     "maximum clients held per network (see --ipv4-prefix / --ipv6-prefix)"),
    ("ipv4-prefix", _ranged(int, 8, 32), 24,
     "IPv4 prefix length that counts as one network"),
    ("ipv6-prefix", _ranged(int, 16, 128), 64,
     "IPv6 prefix length that counts as one network"),
    ("max-lifetime", _ranged(float, 0.0, 1e7), 0.0,
     "drop a client after this many seconds (0 = hold forever)"),
    ("summary-interval", _ranged(float, 0.0, 86400.0), 600.0,
     "seconds between summary log lines (0 = off)"),
    ("top", _ranged(int, 0, 100), 5,
     "how many top source addresses to show in each summary"),
    ("log-level", _log_level, "info",
     "debug (one line per connection), info, warning or error"),
    ("log-file", _path, "",
     "append one JSON line per connection to this file ('' = off)"),
    ("log-max-size", _ranged(float, 1.0, 10240.0), 20.0,
     "rotate the connection log when it reaches this many MiB"),
    ("log-max-files", _ranged(int, 1, 10000), 20,
     "rotated, gzip-compressed connection logs to keep"),
    ("log-retention-days", _ranged(float, 0.0, 36500.0), 90.0,
     "delete rotated connection logs older than this many days (0 = keep by count only)"),
    ("log-rate", _ranged(int, 1, 1000000), 200,
     "maximum connection log lines per second; extra events are counted as suppressed"),
    ("stats-file", _path, "",
     "write live and lifetime stats as JSON to this file ('' = off)"),
    ("stats-interval", _ranged(float, 5.0, 3600.0), 60.0,
     "seconds between stats file updates"),
]
OPTION_MAP = {name: (conv, default) for name, conv, default, _ in OPTIONS}


def attr(name):
    return name.replace("-", "_")


class Config(object):
    def __init__(self, values):
        for name, (_, default) in OPTION_MAP.items():
            setattr(self, attr(name), values.get(name, default))

    def items(self):
        return [(name, getattr(self, attr(name))) for name, _, _, _ in OPTIONS]


def read_config_file(path):
    """Parse 'key = value' or 'key value' lines. '#' starts a comment."""
    values = {}
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise ConfigError("cannot read config %s: %s" % (path, e.strerror or e))
    for lineno, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line:
            key, _, value = line.partition("=")
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                raise ConfigError("%s:%d: expected 'key = value'" % (path, lineno))
            key, value = parts
        key = key.strip().lower().replace("_", "-")
        value = value.strip()
        if key not in OPTION_MAP:
            raise ConfigError("%s:%d: unknown option '%s'" % (path, lineno, key))
        try:
            values[key] = OPTION_MAP[key][0](value)
        except ValueError as e:
            raise ConfigError("%s:%d: %s: %s" % (path, lineno, key, e))
    return values


def build_config(config_path, cli_values):
    values = {}
    if config_path:
        values.update(read_config_file(config_path))
    values.update(cli_values)
    return Config(values)


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog=PROG,
        description="limitlessh %s - a hardened SSH tarpit, inspired by endlessh." % VERSION,
        epilog=(
            "Settings come from built-in defaults, then --config, then command-line flags. "
            "Signals: SIGHUP reloads the config file, SIGUSR1 logs current stats, "
            "SIGTERM/SIGINT shut down cleanly."
        ),
    )
    p.add_argument("-f", "--config", metavar="FILE", help="read settings from FILE")
    p.add_argument("--check-config", action="store_true",
                   help="validate settings, print the effective values and exit")
    p.add_argument("-V", "--version", action="version", version="%s %s" % (PROG, VERSION))
    def cli_type(conv):
        def wrapped(value):
            try:
                return conv(value)
            except ValueError as e:
                raise argparse.ArgumentTypeError(str(e))
        wrapped.__name__ = conv.__name__
        return wrapped

    for name, conv, default, help_text in OPTIONS:
        p.add_argument("--" + name, dest=attr(name), type=cli_type(conv), default=None,
                       metavar=attr(name).upper(),
                       help="%s (default: %s)" % (help_text, default))
    args = p.parse_args(argv)
    cli = {name: getattr(args, attr(name)) for name in OPTION_MAP
           if getattr(args, attr(name)) is not None}
    return args, cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%ds" % seconds
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            parts.append("%d%s" % (seconds // size, unit))
            seconds %= size
    return "".join(parts[:2])


def fmt_bytes(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return ("%d%s" % (n, unit)) if unit == "B" else ("%.1f%s" % (n, unit))
        n /= 1024.0


class JournalFormatter(logging.Formatter):
    """Prefix lines with <N> so journald records the right priority."""
    PRIORITY = {logging.DEBUG: 7, logging.INFO: 6, logging.WARNING: 4,
                logging.ERROR: 3, logging.CRITICAL: 2}

    def format(self, record):
        return "<%d>%s" % (self.PRIORITY.get(record.levelno, 6), super().format(record))


def stderr_is_journal():
    """True only if stderr really is the journal stream systemd describes."""
    value = os.environ.get("JOURNAL_STREAM", "")
    try:
        dev, ino = (int(x) for x in value.split(":"))
        st = os.fstat(sys.stderr.fileno())
    except (ValueError, OSError):
        return False
    return st.st_dev == dev and st.st_ino == ino


def setup_logging(level):
    handler = logging.StreamHandler(sys.stderr)
    if stderr_is_journal():
        handler.setFormatter(JournalFormatter("%(message)s"))
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    set_log_level(level)


def set_log_level(level):
    logging.getLogger().setLevel(getattr(logging, level.upper()))
    # asyncio is chatty at debug level; keep it at warning unless debugging
    logging.getLogger("asyncio").setLevel(logging.DEBUG if level == "debug" else logging.WARNING)


# ---------------------------------------------------------------------------
# Connection log and stats file
# ---------------------------------------------------------------------------

def iso_utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EventLog(object):
    """Append-only JSON-lines log of connections.

    Bounded on every axis an attacker could push: lines per second (extra
    events are counted, not written), file size (rotated), number of rotated
    files and their age (pruned). Rotated files are gzip-compressed on a
    single background thread so the event loop never blocks on it.
    """

    ERROR_BACKOFF = 60.0

    def __init__(self, cfg, loop):
        self.cfg = cfg
        self.loop = loop
        self.path = None
        self.fh = None
        self.size = 0
        self.second = 0
        self.in_second = 0
        self.suppressed = 0
        self.total_suppressed = 0
        self.retry_at = 0.0
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="logzip")

    # -- file handling ------------------------------------------------------

    def configure(self, cfg):
        self.cfg = cfg
        if cfg.log_file != self.path:
            self.close()
            self.path = cfg.log_file or None
            if self.path:
                self._open()
                self.pool.submit(self._housekeeping)

    def _open(self):
        try:
            self.fh = open(self.path, "a", encoding="utf-8", buffering=65536)
            self.size = self.fh.tell()
        except OSError as e:
            self._failed("cannot open connection log %s: %s" % (self.path, e.strerror or e))

    def _failed(self, message):
        LOG.error("%s; retrying in %ds", message, self.ERROR_BACKOFF)
        if self.fh is not None:
            try:
                self.fh.close()
            except OSError:
                pass
        self.fh = None
        self.retry_at = time.monotonic() + self.ERROR_BACKOFF

    def close(self):
        if self.fh is not None:
            self._flush_suppressed(force=True)
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None

    def shutdown(self):
        self.close()
        self.pool.shutdown(wait=True)

    # -- writing -------------------------------------------------------------

    def _writable(self):
        if not self.path:
            return False
        if self.fh is None:
            if time.monotonic() < self.retry_at:
                return False
            self._open()
        return self.fh is not None

    def record(self, data):
        """Rate-limited write of one event."""
        if not self.path:
            return
        now = int(time.time())
        if now != self.second:
            self._flush_suppressed()
            self.second = now
            self.in_second = 0
        if self.in_second >= self.cfg.log_rate:
            self.suppressed += 1
            self.total_suppressed += 1
            return
        self.in_second += 1
        self._write(data)

    def _flush_suppressed(self, force=False):
        if self.suppressed and (force or int(time.time()) != self.second):
            n, self.suppressed = self.suppressed, 0
            self._write({"ts": iso_utc(self.second or time.time()), "suppressed": n})

    def _write(self, data):
        if not self._writable():
            return
        line = json.dumps(data, separators=(",", ":"), ensure_ascii=True) + "\n"
        try:
            self.fh.write(line)
            self.size += len(line)
            if self.size >= self.cfg.log_max_size * 1048576:
                self._rotate()
        except OSError as e:
            self._failed("cannot write connection log %s: %s" % (self.path, e.strerror or e))

    def flush(self):
        self._flush_suppressed()
        if self.fh is not None:
            try:
                self.fh.flush()
            except OSError as e:
                self._failed("cannot write connection log %s: %s" % (self.path, e.strerror or e))

    # -- rotation and pruning -----------------------------------------------

    def _rotated_prefix(self):
        base = self.path[:-4] if self.path.endswith(".log") else self.path
        return base + "-"

    def _rotate(self):
        self.fh.flush()
        self.fh.close()
        self.fh = None
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        dest = "%s%s.log" % (self._rotated_prefix(), stamp)
        n = 1
        while os.path.exists(dest) or os.path.exists(dest + ".gz"):
            dest = "%s%s-%d.log" % (self._rotated_prefix(), stamp, n)
            n += 1
        os.rename(self.path, dest)
        self._open()
        self.pool.submit(self._housekeeping)

    def _housekeeping(self):
        """Runs on the background thread: compress rotated logs, then prune."""
        try:
            prefix = self._rotated_prefix()
            for raw in sorted(glob.glob(glob.escape(prefix) + "*.log")):
                tmp = raw + ".gz.tmp"
                with open(raw, "rb") as src, gzip.open(tmp, "wb", compresslevel=6) as dst:
                    shutil.copyfileobj(src, dst, 1048576)
                os.replace(tmp, raw + ".gz")
                os.unlink(raw)
            rotated = sorted(glob.glob(glob.escape(prefix) + "*.log.gz"))
            excess = rotated[:-self.cfg.log_max_files] if len(rotated) > self.cfg.log_max_files else []
            cutoff = time.time() - self.cfg.log_retention_days * 86400
            for path in rotated:
                if path in excess or (self.cfg.log_retention_days > 0 and os.path.getmtime(path) < cutoff):
                    os.unlink(path)
        except OSError as e:
            LOG.warning("connection log housekeeping failed: %s", e)

    def prune_later(self):
        if self.path:
            self.pool.submit(self._housekeeping)


def _clean_counters(data, keys):
    """Accept only finite, non-negative numbers from a stats file."""
    out = dict.fromkeys(keys, 0)
    if isinstance(data, dict):
        for key in keys:
            v = data.get(key)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and 0 <= v < 1e18:
                out[key] = v
    return out


def load_lifetime(path, keys):
    """Return (counters, since_ts, peak, peak_ts) from a previous stats file."""
    now = time.time()
    if not path:
        return dict.fromkeys(keys, 0), now, 0, now
    try:
        with open(path, encoding="utf-8") as f:
            if os.fstat(f.fileno()).st_size > 1048576:
                raise ValueError("stats file too large")
            data = json.load(f)
        life = data.get("lifetime", {}) if isinstance(data, dict) else {}
        counters = _clean_counters(life.get("counters"), keys)
        since = life.get("since_ts")
        since = since if isinstance(since, (int, float)) and 0 < since <= now else now
        peak = life.get("peak_active")
        peak = int(peak) if isinstance(peak, int) and 0 <= peak < 1e9 else 0
        peak_ts = life.get("peak_ts")
        peak_ts = peak_ts if isinstance(peak_ts, (int, float)) and 0 < peak_ts <= now else now
        return counters, since, peak, peak_ts
    except FileNotFoundError:
        return dict.fromkeys(keys, 0), now, 0, now
    except (OSError, ValueError, TypeError, AttributeError) as e:
        LOG.warning("ignoring unreadable stats file %s: %s", path, e)
        return dict.fromkeys(keys, 0), now, 0, now


# ---------------------------------------------------------------------------
# The tarpit
# ---------------------------------------------------------------------------

class Client(object):
    __slots__ = ("transport", "ip", "net", "start", "wall_start", "timer", "sent", "active")

    def __init__(self, transport, ip, net, start):
        self.transport = transport
        self.ip = ip
        self.net = net
        self.start = start
        self.wall_start = time.time()
        self.timer = None
        self.sent = 0
        self.active = True


class TarpitProtocol(asyncio.Protocol):
    __slots__ = ("tarpit", "client")

    def __init__(self, tarpit):
        self.tarpit = tarpit
        self.client = None

    def connection_made(self, transport):
        self.client = self.tarpit.on_connect(transport)

    def data_received(self, data):
        pass  # reading is paused; anything that slips through is discarded

    def eof_received(self):
        return False  # client closed its side; close ours too

    def pause_writing(self):
        # Our tiny writes only back up once the kernel buffer is full,
        # meaning the client has stopped reading. Don't hold memory for it.
        if self.client is not None:
            self.tarpit.drop(self.client, "stalled")

    def resume_writing(self):
        pass

    def connection_lost(self, exc):
        if self.client is not None:
            self.tarpit.release(self.client, "closed")
            self.client = None


class Tarpit(object):
    COUNTERS = ("accepted", "rejected_ip", "rejected_net", "rejected_bad", "evicted",
                "stalled", "expired", "shutdown", "closed", "wasted", "sent")

    def __init__(self, cfg, loop, events=None):
        self.cfg = cfg
        self.loop = loop
        self.events = events
        self.started_ts = time.time()
        (self.life_base, self.life_since, self.life_peak,
         self.life_peak_ts) = load_lifetime(cfg.stats_file, self.COUNTERS)
        self.rand = random.Random()
        self.clients = collections.OrderedDict()   # Client -> None, oldest first
        self.by_ip = collections.Counter()
        self.by_net = {}                           # net -> OrderedDict(Client -> None)
        # Networks grouped by how many clients they hold, so finding the
        # busiest network is O(1) instead of a scan over every network.
        self.buckets = {}                          # count -> OrderedDict(net -> None)
        self.top_bucket = 0
        self.totals = dict.fromkeys(self.COUNTERS, 0)
        self.window = dict.fromkeys(self.COUNTERS, 0)
        self.window_sources = collections.Counter()
        self.window_untracked = 0
        self.window_start = loop.time()
        self.peak = 0

    # -- accounting ---------------------------------------------------------

    def count(self, key, amount=1):
        self.totals[key] += amount
        self.window[key] += amount

    def _move_net(self, net, old, new):
        if old > 0:
            bucket = self.buckets[old]
            del bucket[net]
            if not bucket:
                del self.buckets[old]
        if new > 0:
            self.buckets.setdefault(new, collections.OrderedDict())[net] = None
            if new > self.top_bucket:
                self.top_bucket = new

    def busiest_net(self):
        while self.top_bucket > 0 and self.top_bucket not in self.buckets:
            self.top_bucket -= 1
        if self.top_bucket == 0:
            return None
        return next(iter(self.buckets[self.top_bucket]))

    # -- connection lifecycle ----------------------------------------------

    def classify(self, transport):
        peer = transport.get_extra_info("peername")
        try:
            ip = ipaddress.ip_address(str(peer[0]).split("%", 1)[0])
        except (TypeError, ValueError, IndexError):
            return None
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        prefix = self.cfg.ipv4_prefix if ip.version == 4 else self.cfg.ipv6_prefix
        net = ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False)
        return str(ip), str(net)

    def on_connect(self, transport):
        cfg = self.cfg
        who = self.classify(transport)
        if who is None:
            self.count("rejected_bad")
            transport.abort()
            return None
        ip, net = who
        sources = self.window_sources
        if ip in sources or len(sources) < MAX_TRACKED_SOURCES:
            sources[ip] += 1
        else:
            self.window_untracked += 1

        if self.by_ip[ip] >= cfg.per_ip:
            self.count("rejected_ip")
            LOG.debug("reject %s: per-ip limit (%d)", ip, cfg.per_ip)
            self._event(time.time(), ip, 0.0, 0, "rejected-ip")
            transport.abort()
            return None
        members = self.by_net.get(net)
        if members is not None and len(members) >= cfg.per_net:
            self.count("rejected_net")
            LOG.debug("reject %s: per-net limit (%d) for %s", ip, cfg.per_net, net)
            self._event(time.time(), ip, 0.0, 0, "rejected-net")
            transport.abort()
            return None
        while len(self.clients) >= cfg.max_clients:
            if not self.evict_one():
                break

        self._tune_socket(transport)
        transport.pause_reading()
        transport.set_write_buffer_limits(high=WRITE_HIGH_WATER)

        client = Client(transport, ip, net, self.loop.time())
        self.clients[client] = None
        self.by_ip[ip] += 1
        if members is None:
            members = self.by_net[net] = collections.OrderedDict()
        old = len(members)
        members[client] = None
        self._move_net(net, old, old + 1)
        self.count("accepted")
        if len(self.clients) > self.peak:
            self.peak = len(self.clients)
        if len(self.clients) > self.life_peak:
            self.life_peak = len(self.clients)
            self.life_peak_ts = time.time()
        LOG.debug("accept %s (active=%d)", ip, len(self.clients))

        # First line arrives quickly so the client commits to waiting.
        self._schedule(client, self.rand.uniform(0.2, min(1.5, cfg.delay)))
        return client

    def _tune_socket(self, transport):
        sock = transport.get_extra_info("socket")
        if sock is None:
            return
        opts = [(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES),
                (socket.SOL_SOCKET, socket.SO_SNDBUF, SNDBUF_BYTES)]
        tcp_user_timeout = getattr(socket, "TCP_USER_TIMEOUT", None)
        if tcp_user_timeout is not None:
            # Give up on peers that stop acknowledging data (vanished hosts),
            # freeing their slot instead of waiting ~15 min of retransmits.
            ms = int((self.cfg.delay * 3 + 60) * 1000)
            opts.append((socket.IPPROTO_TCP, tcp_user_timeout, ms))
        for level, opt, value in opts:
            try:
                sock.setsockopt(level, opt, value)
            except OSError:
                pass

    def evict_one(self):
        net = self.busiest_net()
        if net is None:
            return False
        victim = next(iter(self.by_net[net]))
        LOG.debug("evict %s (busiest network %s)", victim.ip, net)
        self.drop(victim, "evicted")
        return True

    def drop(self, client, reason):
        """Close a client we decided to get rid of."""
        if self.release(client, reason):
            client.transport.abort()

    def release(self, client, reason):
        """Forget a client. Returns False if it was already forgotten."""
        if not client.active:
            return False
        client.active = False
        if client.timer is not None:
            client.timer.cancel()
            client.timer = None
        del self.clients[client]
        self.by_ip[client.ip] -= 1
        if self.by_ip[client.ip] <= 0:
            del self.by_ip[client.ip]
        members = self.by_net[client.net]
        old = len(members)
        del members[client]
        if not members:
            del self.by_net[client.net]
        self._move_net(client.net, old, old - 1)

        held = self.loop.time() - client.start
        if reason != "closed":
            self.count(reason)
        self.count("closed")
        self.count("wasted", held)
        self.count("sent", client.sent)
        LOG.debug("close %s: %s after %s, %d bytes", client.ip, reason, fmt_duration(held), client.sent)
        self._event(client.wall_start, client.ip, held, client.sent, reason)
        return True

    def _event(self, ts, ip, held, sent, result):
        if self.events is not None:
            self.events.record({"ts": iso_utc(ts), "ip": ip, "dur": round(held, 1),
                                "bytes": sent, "result": result})

    # -- sending -------------------------------------------------------------

    def _schedule(self, client, delay):
        client.timer = self.loop.call_later(delay, self._send, client)

    def _next_delay(self):
        j = self.cfg.jitter
        return self.cfg.delay * self.rand.uniform(1.0 - j, 1.0 + j)

    def make_line(self):
        n = self.rand.randint(3, self.cfg.max_line)
        line = bytes(self.rand.choices(LINE_ALPHABET, k=n))
        if line.startswith(b"SSH-"):
            line = b"X" + line[1:]
        return line + b"\r\n"

    def _send(self, client):
        client.timer = None
        if not client.active:
            return
        transport = client.transport
        if transport.is_closing():
            self.release(client, "closed")
            return
        lifetime = self.cfg.max_lifetime
        if lifetime and self.loop.time() - client.start >= lifetime:
            self.drop(client, "expired")
            return
        line = self.make_line()
        transport.write(line)  # may call pause_writing() and drop the client
        if not client.active:
            return
        client.sent += len(line)
        self._schedule(client, self._next_delay())

    # -- reporting -----------------------------------------------------------

    def summary(self, reset):
        now = self.loop.time()
        w, t = self.window, self.totals
        rejected = w["rejected_ip"] + w["rejected_net"] + w["rejected_bad"]
        top = ", ".join("%s(%d)" % kv for kv in self.window_sources.most_common(self.cfg.top))
        if self.window_untracked:
            top += "%s+%d from untracked sources" % (", " if top else "", self.window_untracked)
        LOG.info(
            "summary: active=%d networks=%d peak=%d | last %s: new=%d closed=%d "
            "rejected=%d (per-ip %d, per-net %d) evicted=%d stalled=%d expired=%d | "
            "total: accepted=%d attacker-time=%s sent=%s%s",
            len(self.clients), len(self.by_net), self.peak, fmt_duration(now - self.window_start),
            w["accepted"], w["closed"], rejected, w["rejected_ip"], w["rejected_net"],
            w["evicted"], w["stalled"], w["expired"],
            t["accepted"], fmt_duration(t["wasted"] + self.active_time(now)),
            fmt_bytes(t["sent"] + sum(c.sent for c in self.clients)),
            (" | top: " + top) if top else "",
        )
        if reset:
            self.window = dict.fromkeys(self.COUNTERS, 0)
            self.window_sources.clear()
            self.window_untracked = 0
            self.window_start = now
            self.peak = len(self.clients)

    def active_time(self, now):
        return sum(now - c.start for c in self.clients)

    def quiet(self):
        return (not self.clients and not any(self.window.values())
                and not self.window_sources and not self.window_untracked)

    def enforce_limits(self):
        """Apply new limits after a reload by dropping clients over them."""
        while len(self.clients) > self.cfg.max_clients:
            if not self.evict_one():
                break
        for members in list(self.by_net.values()):
            while len(members) > self.cfg.per_net:
                self.drop(next(iter(members)), "evicted")
        for client in list(self.clients):
            if client.active and self.by_ip[client.ip] > self.cfg.per_ip:
                self.drop(client, "evicted")

    def shutdown(self):
        for client in list(self.clients):
            if client.active:
                self.release(client, "shutdown")
                client.transport.abort()

    def stats_snapshot(self):
        now = self.loop.time()
        wall = time.time()
        lifetime = {k: self.life_base[k] + self.totals[k] for k in self.COUNTERS}
        active_time = self.active_time(now)
        return {
            "version": 1,
            "program": "limitlessh %s" % VERSION,
            "updated": iso_utc(wall), "updated_ts": round(wall, 3),
            "started": iso_utc(self.started_ts), "started_ts": round(self.started_ts, 3),
            "active": len(self.clients),
            "networks": len(self.by_net),
            "max_clients": self.cfg.max_clients,
            "active_time": round(active_time, 1),
            "session": {"counters": {k: (round(v, 1) if isinstance(v, float) else v)
                                     for k, v in self.totals.items()}},
            "lifetime": {
                "since": iso_utc(self.life_since), "since_ts": round(self.life_since, 3),
                "peak_active": self.life_peak,
                "peak": iso_utc(self.life_peak_ts), "peak_ts": round(self.life_peak_ts, 3),
                "counters": {k: (round(v, 1) if isinstance(v, float) else v) for k, v in lifetime.items()},
                "log_suppressed": self.events.total_suppressed if self.events else 0,
            },
        }

    def write_stats(self):
        path = self.cfg.stats_file
        if not path:
            return
        tmp = "%s.tmp.%d" % (path, os.getpid())
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.stats_snapshot(), f, indent=1, sort_keys=True)
                f.write("\n")
            os.replace(tmp, path)
        except OSError as e:
            LOG.warning("cannot write stats file %s: %s", path, e.strerror or e)
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def activated_socket():
    """Return the listening socket passed by systemd, or None."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    try:
        count = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        count = 0
    for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(key, None)
    if count < 1:
        return None
    if count > 1:
        LOG.warning("systemd passed %d sockets; using the first", count)
    sock = socket.socket(fileno=3)
    if sock.type != socket.SOCK_STREAM:
        raise ConfigError("socket passed by systemd is not a TCP stream socket")
    return sock


def bind_socket(cfg):
    addr = cfg.bind
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if addr == "::" else 1)
            except OSError:
                pass
        sock.bind((addr, cfg.port))
    except OSError as e:
        sock.close()
        if family == socket.AF_INET6 and addr == "::" and e.errno in (97, 99):  # no IPv6 on host
            LOG.warning("IPv6 unavailable, listening on IPv4 only")
            fallback = Config(dict(cfg.items()))
            fallback.bind = "0.0.0.0"
            return bind_socket(fallback)
        raise ConfigError("cannot listen on [%s]:%d: %s" % (addr, cfg.port, e.strerror or e))
    return sock


def shrink_listener_buffers(sock):
    """Accepted sockets inherit these, so the advertised TCP window is small
    from the first packet and clients can't park data in kernel memory."""
    for opt, value in ((socket.SO_RCVBUF, RCVBUF_BYTES), (socket.SO_SNDBUF, SNDBUF_BYTES)):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, value)
        except OSError:
            pass


def fit_fd_limit(cfg):
    """Make sure we can actually hold max-clients connections."""
    need = cfg.max_clients + FD_HEADROOM
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < need:
        target = need if hard == resource.RLIM_INFINITY else min(need, hard)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
        except (ValueError, OSError):
            pass
    if soft < need:
        capped = max(1, soft - FD_HEADROOM)
        LOG.warning("open file limit is %d; lowering max-clients from %d to %d "
                    "(raise LimitNOFILE= to allow more)", soft, cfg.max_clients, capped)
        cfg.max_clients = capped


async def serve(cfg, sock, activated, config_path, cli_values):
    loop = asyncio.get_running_loop()
    events = EventLog(cfg, loop)
    events.configure(cfg)
    tarpit = Tarpit(cfg, loop, events)
    server = await loop.create_server(lambda: TarpitProtocol(tarpit), sock=sock, backlog=4096)
    name = sock.getsockname()
    LOG.info("limitlessh %s listening on [%s]:%d%s (max-clients=%d per-ip=%d per-net=%d delay=%gs)",
             VERSION, name[0], name[1], " via systemd" if activated else "",
             cfg.max_clients, cfg.per_ip, cfg.per_net, cfg.delay)
    if os.geteuid() == 0 and not activated:
        LOG.warning("running as root; prefer the systemd units, which run it unprivileged")
    if cfg.log_file:
        LOG.info("connection log: %s (max %d lines/s)", cfg.log_file, cfg.log_rate)
    events.record({"ts": iso_utc(time.time()), "event": "start", "version": VERSION})

    stop = loop.create_future()
    summary_timer = [None]
    timers = {}

    def every(name, interval_fn, action):
        """Run action every interval_fn() seconds; re-read interval each time."""
        def tick():
            try:
                action()
            finally:
                timers[name] = loop.call_later(interval_fn(), tick)
        if name in timers:
            timers[name].cancel()
        timers[name] = loop.call_later(interval_fn(), tick)

    every("flush", lambda: 1.0, events.flush)
    every("stats", lambda: tarpit.cfg.stats_interval, tarpit.write_stats)
    every("prune", lambda: 3600.0, events.prune_later)
    tarpit.write_stats()

    def schedule_summary():
        if summary_timer[0] is not None:
            summary_timer[0].cancel()
            summary_timer[0] = None
        if tarpit.cfg.summary_interval > 0:
            summary_timer[0] = loop.call_later(tarpit.cfg.summary_interval, on_summary)

    def on_summary():
        summary_timer[0] = None
        if not tarpit.quiet():
            tarpit.summary(reset=True)
        schedule_summary()

    def on_reload():
        if not config_path:
            LOG.info("SIGHUP received but no --config file; nothing to reload")
            return
        try:
            new = build_config(config_path, cli_values)
        except ConfigError as e:
            LOG.error("reload failed, keeping current settings: %s", e)
            return
        if not activated and (new.port != cfg.port or new.bind != cfg.bind):
            LOG.warning("port/bind changes need a restart; keeping [%s]:%d", cfg.bind, cfg.port)
        new.port, new.bind = cfg.port, cfg.bind
        fit_fd_limit(new)
        tarpit.cfg = new
        events.configure(new)
        set_log_level(new.log_level)
        tarpit.enforce_limits()
        schedule_summary()
        every("stats", lambda: tarpit.cfg.stats_interval, tarpit.write_stats)
        tarpit.write_stats()
        LOG.info("reloaded %s (max-clients=%d per-ip=%d per-net=%d delay=%gs)",
                 config_path, new.max_clients, new.per_ip, new.per_net, new.delay)

    def on_stop(signame):
        LOG.info("%s received, shutting down", signame)
        if not stop.done():
            stop.set_result(None)

    loop.add_signal_handler(signal.SIGTERM, on_stop, "SIGTERM")
    loop.add_signal_handler(signal.SIGINT, on_stop, "SIGINT")
    loop.add_signal_handler(signal.SIGHUP, on_reload)
    def on_usr1():
        tarpit.summary(reset=False)
        tarpit.write_stats()
        events.flush()

    loop.add_signal_handler(signal.SIGUSR1, on_usr1)
    schedule_summary()

    try:
        await stop
    finally:
        for handle in timers.values():
            handle.cancel()
        server.close()
        tarpit.shutdown()
        await server.wait_closed()
        tarpit.summary(reset=False)
        tarpit.write_stats()
        events.record({"ts": iso_utc(time.time()), "event": "stop", "version": VERSION})
        events.shutdown()


def main(argv=None):
    args, cli_values = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        cfg = build_config(args.config, cli_values)
    except ConfigError as e:
        print("%s: %s" % (PROG, e), file=sys.stderr)
        return 2
    if args.check_config:
        for name, value in cfg.items():
            print("%-19s %s" % (name, value))
        return 0

    setup_logging(cfg.log_level)
    try:
        sock = activated_socket()
        activated = sock is not None
        if sock is None:
            sock = bind_socket(cfg)
    except ConfigError as e:
        LOG.error("%s", e)
        return 1
    shrink_listener_buffers(sock)
    fit_fd_limit(cfg)
    try:
        asyncio.run(serve(cfg, sock, activated, args.config, cli_values))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
LIMITLESSH_PY_EOF
}

write_report() {  # $1 = destination
  cat > "$1" <<'LIMITLESSH_REPORT_EOF'
#!/usr/bin/env python3
"""
limitlessh-report - reports, raw-log export and IP geolocation for limitlessh.

Reads the connection log written by limitlessh (JSON lines, rotated and
gzip-compressed) plus its stats file, and enriches IP addresses with country,
region, city, ASN and organisation from local MaxMind-format (.mmdb)
databases: DB-IP Lite (free, downloaded with --update-geo) or MaxMind GeoLite2.

Geolocation runs here, offline and on demand, not in the internet-facing
tarpit. Everything read (logs, stats, databases) is treated as untrusted:
inputs are size-limited and validated, and text is sanitised before it reaches
a terminal or a spreadsheet.

Python 3.8+ standard library only.
"""

import argparse
import collections
import csv
import datetime
import glob
import gzip
import hashlib
import ipaddress
import json
import math
import mmap
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request

VERSION = "1.1.0"
PROG = "limitlessh-report"

DEFAULT_LOG = "/var/log/limitlessh/connections.log"
DEFAULT_STATS = "/var/lib/limitlessh/stats.json"
DEFAULT_GEO_DIR = "/var/lib/limitlessh-geo"

# Database file names we look for, in order of preference.
CITY_FILES = ("GeoLite2-City.mmdb", "GeoIP2-City.mmdb", "dbip-city-lite.mmdb")
COUNTRY_FILES = ("GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb", "dbip-country-lite.mmdb")
ASN_FILES = ("GeoIP2-ISP.mmdb", "GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")

DBIP_URL = "https://download.db-ip.com/free/dbip-{edition}-lite-{month}.mmdb.gz"
MAX_DOWNLOAD_BYTES = 400 * 1048576      # compressed
MAX_DATABASE_BYTES = 1536 * 1048576     # decompressed
MAX_LOG_LINE = 4096
# Well-known addresses any complete database covers; used to sanity-check downloads.
VERIFY_PROBES = ("1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222")
RESULTS = ("closed", "evicted", "stalled", "expired", "shutdown", "rejected-ip", "rejected-net")
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class ReportError(Exception):
    pass


# ---------------------------------------------------------------------------
# MaxMind DB (.mmdb) reader
# https://maxmind.github.io/MaxMind-DB/
# ---------------------------------------------------------------------------

class MMDBError(Exception):
    pass


class MMDB(object):
    """Minimal, defensive reader for MaxMind DB format v2 files.

    Every read is bounds-checked and each lookup has value, payload and depth
    budgets, so a corrupt or malicious file raises MMDBError instead of
    hanging or exhausting memory.
    """

    METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
    MAX_DEPTH = 128
    MAX_VALUES = 1 << 16
    MAX_PAYLOAD = 1 << 21

    def __init__(self, path):
        self.path = path
        self._file = open(path, "rb")
        try:
            size = os.fstat(self._file.fileno()).st_size
            if size < 64 or size > MAX_DATABASE_BYTES:
                raise MMDBError("unexpected file size %d" % size)
            self.buf = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            self.size = size
            self._read_metadata()
        except (OSError, ValueError) as e:
            self.close()
            raise MMDBError(str(e))
        except MMDBError:
            self.close()
            raise

    def close(self):
        buf = getattr(self, "buf", None)
        if buf is not None:
            buf.close()
            self.buf = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- metadata ------------------------------------------------------------

    def _read_metadata(self):
        window_start = max(0, self.size - 128 * 1024)
        pos = self.buf.rfind(self.METADATA_MARKER, window_start)
        if pos < 0:
            raise MMDBError("metadata marker not found; not a MaxMind DB file")
        meta_start = pos + len(self.METADATA_MARKER)
        meta = self._decode_root(meta_start, meta_start, self.size)
        if not isinstance(meta, dict):
            raise MMDBError("metadata is not a map")
        try:
            self.node_count = int(meta["node_count"])
            self.record_size = int(meta["record_size"])
            self.ip_version = int(meta["ip_version"])
            major = int(meta.get("binary_format_major_version", 0))
        except (KeyError, TypeError, ValueError):
            raise MMDBError("metadata missing required fields")
        if major != 2:
            raise MMDBError("unsupported format version %r" % major)
        if self.record_size not in (24, 28, 32):
            raise MMDBError("unsupported record size %r" % self.record_size)
        if self.ip_version not in (4, 6):
            raise MMDBError("unsupported ip_version %r" % self.ip_version)
        self.node_bytes = self.record_size // 4
        self.tree_size = self.node_count * self.node_bytes
        if self.node_count <= 0 or self.tree_size + 16 > pos:
            raise MMDBError("search tree does not fit in file")
        self.data_start = self.tree_size + 16
        self.data_end = pos
        self.database_type = str(meta.get("database_type", ""))
        epoch = meta.get("build_epoch", 0)
        self.build_epoch = int(epoch) if isinstance(epoch, int) else 0
        self.metadata = meta
        self._ipv4_start = None

    # -- search tree ------------------------------------------------------------

    def _record(self, node, right):
        off = node * self.node_bytes
        if off + self.node_bytes > self.tree_size:
            raise MMDBError("search tree node out of range")
        b = self.buf[off:off + self.node_bytes]
        if self.record_size == 24:
            return int.from_bytes(b[3:6] if right else b[0:3], "big")
        if self.record_size == 28:
            if right:
                return ((b[3] & 0x0F) << 24) | int.from_bytes(b[4:7], "big")
            return ((b[3] & 0xF0) << 20) | int.from_bytes(b[0:3], "big")
        return int.from_bytes(b[4:8] if right else b[0:4], "big")

    def _start_node(self, version):
        if self.ip_version == 4 or version == 6:
            return 0
        if self._ipv4_start is None:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, False)
            self._ipv4_start = node
        return self._ipv4_start

    def lookup(self, ip):
        """Return the record for ip (an ipaddress object), or None."""
        if ip.version == 6 and self.ip_version == 4:
            return None
        packed = ip.packed
        bits = len(packed) * 8
        node = self._start_node(ip.version)
        value = int.from_bytes(packed, "big")
        for i in range(bits):
            if node >= self.node_count:
                break
            node = self._record(node, (value >> (bits - 1 - i)) & 1)
        if node == self.node_count:
            return None
        if node < self.node_count:
            raise MMDBError("search tree too deep")
        offset = node - self.node_count + self.tree_size
        if offset < self.data_start or offset >= self.data_end:
            raise MMDBError("data pointer out of range")
        return self._decode_root(offset, self.data_start, self.data_end)

    # -- data section ------------------------------------------------------------
    # Budgets follow the MaxMind DB spec's reader resource limits: every lookup
    # gets 65,536 values and 2 MiB of string/bytes payload, charged *before*
    # anything is copied, and re-charged each time a pointer reuses a target.
    # That stops "payload amplification" files where thousands of pointers to
    # one large value would otherwise materialise gigabytes from a tiny file.

    def _decode_root(self, offset, base, end):
        state = {"values": self.MAX_VALUES - 1, "payload": self.MAX_PAYLOAD,
                 "depth": 0, "base": base, "end": end}
        value, _ = self._decode(offset, state, False)
        return value

    def _need(self, offset, n, state):
        if offset < 0 or n < 0 or offset + n > state["end"]:
            raise MMDBError("read past end of data")

    def _enter(self, state, values):
        state["values"] -= values
        if state["values"] < 0:
            raise MMDBError("too many values in one record")
        state["depth"] += 1
        if state["depth"] > self.MAX_DEPTH:
            raise MMDBError("data nested too deeply")

    def _charge(self, state, size):
        state["payload"] -= size
        if state["payload"] < 0:
            raise MMDBError("record payload exceeds 2 MiB")

    def _decode(self, offset, state, pointer_target):
        buf = self.buf
        self._need(offset, 1, state)
        ctrl = buf[offset]
        offset += 1
        kind = ctrl >> 5
        if kind == 1:  # pointer; its size bits are not a size
            if pointer_target:
                raise MMDBError("pointer to a pointer")
            ss = (ctrl >> 3) & 0x3
            vvv = ctrl & 0x7
            self._need(offset, ss + 1, state)
            ptr = int.from_bytes(buf[offset:offset + ss + 1], "big")
            if ss < 3:
                ptr |= vvv << ((ss + 1) * 8)
                ptr += (0, 2048, 526336)[ss]
            target = state["base"] + ptr
            if target < state["base"] or target >= state["end"]:
                raise MMDBError("pointer out of range")
            state["depth"] += 1
            if state["depth"] > self.MAX_DEPTH:
                raise MMDBError("data nested too deeply")
            value, _ = self._decode(target, state, True)
            state["depth"] -= 1
            return value, offset + ss + 1
        if kind == 0:  # extended type
            self._need(offset, 1, state)
            kind = 7 + buf[offset]
            offset += 1
            if kind < 8 or kind > 15:
                raise MMDBError("invalid extended type %d" % kind)
        size = ctrl & 0x1F
        if size >= 29:
            extra = size - 28
            self._need(offset, extra, state)
            n = int.from_bytes(buf[offset:offset + extra], "big")
            size = (29, 285, 65821)[extra - 1] + n
            offset += extra
        if kind == 2:  # utf-8 string
            self._charge(state, size)
            self._need(offset, size, state)
            return bytes(buf[offset:offset + size]).decode("utf-8", "replace"), offset + size
        if kind == 7:  # map
            self._enter(state, size * 2)
            result = {}
            for _ in range(size):
                key, offset = self._decode(offset, state, False)
                if not isinstance(key, str):
                    raise MMDBError("map key is not a string")
                result[key], offset = self._decode(offset, state, False)
            state["depth"] -= 1
            return result, offset
        if kind in (5, 6, 9, 10):  # unsigned ints
            if size > {5: 2, 6: 4, 9: 8, 10: 16}[kind]:
                raise MMDBError("bad unsigned int size")
            self._need(offset, size, state)
            return int.from_bytes(buf[offset:offset + size], "big"), offset + size
        if kind == 11:  # array
            self._enter(state, size)
            result = []
            for _ in range(size):
                item, offset = self._decode(offset, state, False)
                result.append(item)
            state["depth"] -= 1
            return result, offset
        if kind == 3:  # double
            if size != 8:
                raise MMDBError("bad double size")
            self._need(offset, 8, state)
            return struct.unpack(">d", buf[offset:offset + 8])[0], offset + 8
        if kind == 4:  # bytes
            self._charge(state, size)
            self._need(offset, size, state)
            return bytes(buf[offset:offset + size]), offset + size
        if kind == 8:  # int32
            if size > 4:
                raise MMDBError("bad int32 size")
            self._need(offset, size, state)
            v = int.from_bytes(buf[offset:offset + size], "big")
            if size == 4 and v & 0x80000000:
                v -= 1 << 32
            return v, offset + size
        if kind == 14:  # boolean
            if size > 1:
                raise MMDBError("bad boolean")
            return bool(size), offset
        if kind == 15:  # float
            if size != 4:
                raise MMDBError("bad float size")
            self._need(offset, 4, state)
            return struct.unpack(">f", buf[offset:offset + 4])[0], offset + 4
        raise MMDBError("unsupported data type %d" % kind)


# ---------------------------------------------------------------------------
# Geolocation
# ---------------------------------------------------------------------------

def _name(rec, key):
    part = rec.get(key) if isinstance(rec, dict) else None
    if isinstance(part, dict):
        names = part.get("names")
        if isinstance(names, dict) and isinstance(names.get("en"), str):
            return names["en"]
    return ""


def _code(rec, key):
    part = rec.get(key) if isinstance(rec, dict) else None
    if isinstance(part, dict) and isinstance(part.get("iso_code"), str):
        return part["iso_code"]
    return ""


class Geo(object):
    FIELDS = ("country_code", "country", "region", "city", "latitude", "longitude", "asn", "org")
    EMPTY = dict.fromkeys(FIELDS, "")

    def __init__(self, geo_dir, warn=True):
        self.loc = self.asn = None
        self.loc_path = self.asn_path = None
        self.cache = {}
        self.errors = 0
        for name in CITY_FILES + COUNTRY_FILES:
            path = os.path.join(geo_dir, name)
            if os.path.isfile(path):
                try:
                    self.loc = MMDB(path)
                    self.loc_path = path
                    break
                except MMDBError as e:
                    if warn:
                        print("%s: warning: ignoring %s: %s" % (PROG, path, e), file=sys.stderr)
        for name in ASN_FILES:
            path = os.path.join(geo_dir, name)
            if os.path.isfile(path):
                try:
                    self.asn = MMDB(path)
                    self.asn_path = path
                    break
                except MMDBError as e:
                    if warn:
                        print("%s: warning: ignoring %s: %s" % (PROG, path, e), file=sys.stderr)

    @property
    def available(self):
        return self.loc is not None or self.asn is not None

    def sources(self):
        out = []
        for db, path in ((self.loc, self.loc_path), (self.asn, self.asn_path)):
            if db is not None:
                built = time.strftime("%Y-%m-%d", time.gmtime(db.build_epoch)) if db.build_epoch else "?"
                out.append((os.path.basename(path), db.database_type, built))
        return out

    def uses_dbip(self):
        return any("dbip" in os.path.basename(p or "") for p in (self.loc_path, self.asn_path))

    def lookup(self, ip_text):
        hit = self.cache.get(ip_text)
        if hit is not None:
            return hit
        result = dict(self.EMPTY)
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return result
        if not ip.is_global:
            result["country"] = "(private/reserved)"
        else:
            if self.loc is not None:
                try:
                    rec = self.loc.lookup(ip) or {}
                    result["country_code"] = _code(rec, "country") or _code(rec, "registered_country")
                    result["country"] = _name(rec, "country") or _name(rec, "registered_country")
                    subs = rec.get("subdivisions")
                    if isinstance(subs, list) and subs:
                        result["region"] = _name({"s": subs[0]}, "s")
                    result["city"] = _name(rec, "city")
                    loc = rec.get("location")
                    if isinstance(loc, dict):
                        lat, lon = loc.get("latitude"), loc.get("longitude")
                        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                            result["latitude"], result["longitude"] = round(lat, 4), round(lon, 4)
                except MMDBError:
                    self.errors += 1
            if self.asn is not None:
                try:
                    rec = self.asn.lookup(ip) or {}
                    num = rec.get("autonomous_system_number")
                    if isinstance(num, int):
                        result["asn"] = num
                    org = rec.get("isp") or rec.get("autonomous_system_organization") or rec.get("organization")
                    if isinstance(org, str):
                        result["org"] = org
                except MMDBError:
                    self.errors += 1
        if len(self.cache) < 500000:
            self.cache[ip_text] = result
        return result


class NoGeo(object):
    available = False

    def sources(self):
        return []

    def uses_dbip(self):
        return False

    def lookup(self, ip_text):
        return dict(Geo.EMPTY)


# ---------------------------------------------------------------------------
# Geo database updater (DB-IP Lite, CC BY 4.0)
# ---------------------------------------------------------------------------

def _months_to_try():
    now = datetime.datetime.now(datetime.timezone.utc)
    this = now.strftime("%Y-%m")
    prev = (now.replace(day=1) - datetime.timedelta(days=1)).strftime("%Y-%m")
    return (this, prev)


def _download(url, dest, limit):
    req = urllib.request.Request(url, headers={"User-Agent": "limitlessh-report/%s" % VERSION})
    with urllib.request.urlopen(req, timeout=60) as resp:
        if resp.status != 200:
            raise ReportError("HTTP %d for %s" % (resp.status, url))
        length = resp.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > limit:
            raise ReportError("%s is larger than the %d MiB limit" % (url, limit // 1048576))
        total = 0
        h = hashlib.sha256()
        with open(dest, "wb") as out:
            while True:
                chunk = resp.read(1048576)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ReportError("%s exceeded the %d MiB limit" % (url, limit // 1048576))
                h.update(chunk)
                out.write(chunk)
    return h.hexdigest(), total


def _gunzip(src, dest, limit):
    total = 0
    with gzip.open(src, "rb") as zin, open(dest, "wb") as out:
        while True:
            chunk = zin.read(1048576)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ReportError("decompressed database exceeds %s bytes; refusing" % fmt_int(limit))
            out.write(chunk)
    return total


def _verify_database(path, kind):
    with MMDB(path) as db:
        dtype = db.database_type.lower()
        if kind == "asn" and "asn" not in dtype:
            raise ReportError("downloaded file is a %r database, expected ASN" % db.database_type)
        if kind != "asn" and kind not in dtype:
            raise ReportError("downloaded file is a %r database, expected %s" % (db.database_type, kind))
        if db.build_epoch and db.build_epoch < time.time() - 400 * 86400:
            raise ReportError("downloaded database is more than 400 days old")
        if not any(isinstance(db.lookup(ipaddress.ip_address(a)), dict) for a in VERIFY_PROBES):
            raise ReportError("database has no data for well-known addresses; refusing it")
        return db.database_type, db.build_epoch


def update_geo(geo_dir, edition, quiet=False):
    if edition not in ("city", "country"):
        raise ReportError("edition must be city or country")
    os.makedirs(geo_dir, mode=0o755, exist_ok=True)
    installed = {}
    for kind in (edition, "asn"):
        final = os.path.join(geo_dir, "dbip-%s-lite.mmdb" % kind)
        errors = []
        done = False
        for month in _months_to_try():
            url = DBIP_URL.format(edition=kind, month=month)
            gz_fd, gz_tmp = tempfile.mkstemp(prefix=".dl-", suffix=".gz", dir=geo_dir)
            db_fd, db_tmp = tempfile.mkstemp(prefix=".db-", suffix=".mmdb", dir=geo_dir)
            os.close(gz_fd)
            os.close(db_fd)
            try:
                if not quiet:
                    print("downloading %s" % url)
                digest, size = _download(url, gz_tmp, MAX_DOWNLOAD_BYTES)
                _gunzip(gz_tmp, db_tmp, MAX_DATABASE_BYTES)
                dtype, built = _verify_database(db_tmp, kind)
                os.chmod(db_tmp, 0o644)
                os.replace(db_tmp, final)
                installed[kind] = {"file": os.path.basename(final), "url": url, "month": month,
                                   "sha256_gz": digest, "type": dtype,
                                   "built": time.strftime("%Y-%m-%d", time.gmtime(built)) if built else ""}
                if not quiet:
                    print("installed %s (%s, %.1f MiB download)" % (final, dtype, size / 1048576.0))
                done = True
                break
            except urllib.error.HTTPError as e:
                errors.append("%s: HTTP %d" % (url, e.code))
            except (urllib.error.URLError, OSError, ReportError, MMDBError, EOFError, gzip.BadGzipFile) as e:
                errors.append("%s: %s" % (url, getattr(e, "reason", None) or e))
            finally:
                for tmp in (gz_tmp, db_tmp):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
        if not done:
            raise ReportError("could not update %s database (existing files kept):\n  %s"
                              % (kind, "\n  ".join(errors)))
    # A city database replaces a country one and vice versa
    other = "country" if edition == "city" else "city"
    try:
        os.unlink(os.path.join(geo_dir, "dbip-%s-lite.mmdb" % other))
    except OSError:
        pass
    info = {"updated": time.strftime(TS_FORMAT, time.gmtime()), "source": "DB-IP Lite (CC BY 4.0, https://db-ip.com)",
            "databases": installed}
    tmp = os.path.join(geo_dir, ".source.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(info, f, indent=1)
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(geo_dir, "source.json"))


# ---------------------------------------------------------------------------
# Reading the connection log
# ---------------------------------------------------------------------------

def parse_when(text, now):
    """'24h', '7d', '30m', '2w', 'all', '2026-10-01', '2026-10-01T12:00' -> epoch seconds."""
    t = text.strip().lower()
    if t in ("all", "0", ""):
        return 0.0
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhdw])", t)
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
        return now - float(m.group(1)) * mult
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(text.strip(), fmt))
        except ValueError:
            pass
    raise ReportError("cannot understand time %r (use e.g. 24h, 7d, 2026-10-01, all)" % text)


def log_files(log_path):
    """Rotated logs (oldest first) followed by the current log."""
    base = log_path[:-4] if log_path.endswith(".log") else log_path
    rotated = sorted(glob.glob(glob.escape(base + "-") + "*.log.gz") +
                     glob.glob(glob.escape(base + "-") + "*.log"))
    files = rotated + ([log_path] if os.path.exists(log_path) else [])
    return files


def _rotated_stamp(path):
    m = re.search(r"-(\d{8}T\d{6}Z)(?:-\d+)?\.log(?:\.gz)?$", path)
    if m:
        try:
            return float(datetime.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ")
                         .replace(tzinfo=datetime.timezone.utc).timestamp())
        except ValueError:
            pass
    return None


def _bounded_lines(fh):
    """Yield lines, skipping any longer than MAX_LOG_LINE without buffering them."""
    while True:
        line = fh.readline(MAX_LOG_LINE + 1)
        if not line:
            return
        if len(line) > MAX_LOG_LINE and not line.endswith("\n"):
            while True:  # discard the rest of an over-long line
                rest = fh.readline(65536)
                if not rest or rest.endswith("\n"):
                    break
            yield None
            continue
        yield line


class LogStats(object):
    def __init__(self):
        self.invalid = 0
        self.suppressed = 0
        self.starts = 0
        self.files = 0


def read_records(log_path, since, until, stats):
    """Yield validated connection records within [since, until]."""
    for path in log_files(log_path):
        stamp = _rotated_stamp(path)
        if stamp is not None and stamp < since:
            continue  # rotated before the period started
        stats.files += 1
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                for line in _bounded_lines(fh):
                    rec = _parse_line(line, stats)
                    if rec is not None and since <= rec["t"] <= until:
                        yield rec
        except (OSError, EOFError, gzip.BadGzipFile) as e:
            print("%s: warning: cannot fully read %s: %s" % (PROG, path, e), file=sys.stderr)


def _parse_line(line, stats):
    if line is None:
        stats.invalid += 1
        return None
    line = line.strip()
    if not line:
        return None
    try:
        d = json.loads(line)
    except ValueError:
        stats.invalid += 1
        return None
    if not isinstance(d, dict):
        stats.invalid += 1
        return None
    if "suppressed" in d:
        n = d.get("suppressed")
        if isinstance(n, int) and 0 < n < 10 ** 12:
            stats.suppressed += n
        return None
    if "event" in d:
        if d.get("event") == "start":
            stats.starts += 1
        return None
    try:
        t = datetime.datetime.strptime(str(d["ts"]), TS_FORMAT).replace(tzinfo=datetime.timezone.utc).timestamp()
        ip = str(ipaddress.ip_address(str(d["ip"])))
        dur = float(d.get("dur", 0))
        sent = int(d.get("bytes", 0))
        result = str(d.get("result", ""))
    except (KeyError, ValueError, TypeError, OverflowError):
        stats.invalid += 1
        return None
    if not (0 <= dur < 1e9 and math.isfinite(dur)) or not 0 <= sent < 10 ** 15 or result not in RESULTS:
        stats.invalid += 1
        return None
    return {"t": t, "ip": ip, "dur": dur, "bytes": sent, "result": result}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

HOLD_BUCKETS = ((10, "<10s"), (60, "10s-1m"), (300, "1-5m"), (1800, "5-30m"),
                (7200, "30m-2h"), (43200, "2-12h"), (float("inf"), ">12h"))


class Report(object):
    def __init__(self, geo, local_time=True, top=10):
        self.geo = geo
        self.local = local_time
        self.top = top
        self.results = collections.Counter()
        self.trapped = 0
        self.rejected = 0
        self.wasted = 0.0
        self.sent = 0
        self.first = None
        self.last = None
        self.ips = {}
        self.hold = collections.Counter()
        self.hours = collections.Counter()
        self.days = {}
        self.longest = []

    def add(self, r):
        t = r["t"]
        self.first = t if self.first is None else min(self.first, t)
        self.last = t if self.last is None else max(self.last, t)
        ip = self.ips.get(r["ip"])
        if ip is None:
            ip = self.ips[r["ip"]] = {"conns": 0, "rejected": 0, "time": 0.0, "bytes": 0,
                                      "first": t, "last": t, "longest": 0.0}
        ip["first"] = min(ip["first"], t)
        ip["last"] = max(ip["last"], t)
        stamp = datetime.datetime.fromtimestamp(t) if self.local else \
            datetime.datetime.fromtimestamp(t, datetime.timezone.utc)
        self.hours[stamp.hour] += 1
        day = self.days.setdefault(stamp.strftime("%Y-%m-%d"),
                                   {"trapped": 0, "rejected": 0, "time": 0.0, "ips": set()})
        day["ips"].add(r["ip"]) if len(day["ips"]) < 200000 else None
        self.results[r["result"]] += 1
        if r["result"].startswith("rejected"):
            self.rejected += 1
            ip["rejected"] += 1
            day["rejected"] += 1
            return
        self.trapped += 1
        self.wasted += r["dur"]
        self.sent += r["bytes"]
        ip["conns"] += 1
        ip["time"] += r["dur"]
        ip["bytes"] += r["bytes"]
        ip["longest"] = max(ip["longest"], r["dur"])
        day["trapped"] += 1
        day["time"] += r["dur"]
        for limit, label in HOLD_BUCKETS:
            if r["dur"] < limit:
                self.hold[label] += 1
                break
        if len(self.longest) < self.top or r["dur"] > self.longest[-1]["dur"]:
            self.longest.append(r)
            self.longest.sort(key=lambda x: -x["dur"])
            del self.longest[self.top:]

    # -- derived tables ------------------------------------------------------

    def networks(self):
        nets = set()
        for ip in self.ips:
            a = ipaddress.ip_address(ip)
            nets.add(str(ipaddress.ip_network("%s/%d" % (a, 24 if a.version == 4 else 64), strict=False)))
        return len(nets)

    def by_group(self, key_fn):
        groups = {}
        for ip, s in self.ips.items():
            g = self.geo.lookup(ip)
            key = key_fn(g)
            e = groups.get(key)
            if e is None:
                e = groups[key] = {"ips": 0, "conns": 0, "rejected": 0, "time": 0.0, "geo": g}
            e["ips"] += 1
            e["conns"] += s["conns"]
            e["rejected"] += s["rejected"]
            e["time"] += s["time"]
        return groups

    def top_ips(self, key):
        return sorted(self.ips.items(), key=lambda kv: (-kv[1][key], kv[0]))[:self.top]

    def as_dict(self, period, live, new_ips, log_stats):
        countries = self.by_group(lambda g: (g["country_code"], g["country"]))
        asns = self.by_group(lambda g: (g["asn"], g["org"]))

        def ip_row(ip, s):
            g = self.geo.lookup(ip)
            return dict(ip=ip, conns=s["conns"], rejected=s["rejected"], time=round(s["time"], 1),
                        longest=round(s["longest"], 1), first=iso(s["first"]), last=iso(s["last"]), **g)

        return {
            "generated": iso(time.time()),
            "period": {"since": iso(period[0]) if period[0] else None, "until": iso(period[1]),
                       "first_event": iso(self.first) if self.first else None,
                       "last_event": iso(self.last) if self.last else None},
            "live": live,
            "overview": {
                "trapped": self.trapped, "rejected": self.rejected, "unique_ips": len(self.ips),
                "unique_networks": self.networks(), "new_ips": new_ips,
                "attacker_time": round(self.wasted, 1), "bytes_sent": self.sent,
                "avg_hold": round(self.wasted / self.trapped, 1) if self.trapped else 0,
                "longest_hold": round(self.longest[0]["dur"], 1) if self.longest else 0,
                "service_starts": log_stats.starts, "suppressed_log_lines": log_stats.suppressed,
                "invalid_log_lines": log_stats.invalid,
            },
            "results": dict(self.results),
            "hold_time": {label: self.hold[label] for _, label in HOLD_BUCKETS},
            "top_ips_by_time": [ip_row(ip, s) for ip, s in self.top_ips("time")],
            "top_ips_by_connections": [ip_row(ip, s) for ip, s in self.top_ips("conns")],
            "top_countries": [dict(country_code=k[0], country=k[1], ips=v["ips"], conns=v["conns"],
                                   rejected=v["rejected"], time=round(v["time"], 1))
                              for k, v in sorted(countries.items(), key=lambda kv: (-kv[1]["conns"] - kv[1]["rejected"], str(kv[0])))[:self.top]],
            "top_asns": [dict(asn=k[0], org=k[1], ips=v["ips"], conns=v["conns"],
                              rejected=v["rejected"], time=round(v["time"], 1))
                         for k, v in sorted(asns.items(), key=lambda kv: (-kv[1]["conns"] - kv[1]["rejected"], str(kv[0])))[:self.top]],
            "longest_sessions": [dict(start=iso(r["t"]), ip=r["ip"], duration=round(r["dur"], 1),
                                      bytes=r["bytes"], result=r["result"], **self.geo.lookup(r["ip"]))
                                 for r in self.longest],
            "daily": {d: {"trapped": v["trapped"], "rejected": v["rejected"], "ips": len(v["ips"]),
                          "time": round(v["time"], 1)} for d, v in sorted(self.days.items())},
            "hour_of_day": {h: self.hours[h] for h in range(24)},
            "time_zone": "local" if self.local else "UTC",
            "geo_sources": [dict(file=f, type=t, built=b) for f, t, b in self.geo.sources()],
        }


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(TS_FORMAT)


def load_live(path):
    try:
        with open(path, encoding="utf-8") as f:
            if os.fstat(f.fileno()).st_size > 1048576:
                return None
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def new_ip_count(log_path, report, since):
    """IPs whose first appearance in all available logs is inside the period."""
    if not since:
        return len(report.ips)
    seen_before = set()
    stats = LogStats()
    for rec in read_records(log_path, 0, since - 0.001, stats):
        if rec["ip"] in report.ips:
            seen_before.add(rec["ip"])
    return len(report.ips) - len(seen_before)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


def clean(text, width=None):
    """Strip control and bidi characters so data can't drive the terminal."""
    s = _CONTROL.sub("", str(text))
    if width is not None and len(s) > width:
        s = s[:max(1, width - 1)] + "…"
    return s


def csv_cell(value):
    """Neutralise spreadsheet formula injection."""
    s = clean(value)
    if s and s[0] in "=+-@\t\r" and not re.fullmatch(r"-?\d+(\.\d+)?", s):
        s = "'" + s
    return s


def fmt_dur(seconds):
    seconds = int(round(seconds))
    if seconds < 60:
        return "%ds" % seconds
    out = []
    for unit, size in (("y", 31536000), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size:
            out.append("%d%s" % (seconds // size, unit))
            seconds %= size
        if len(out) == 2:
            break
    return " ".join(out)


def fmt_int(n):
    return "{:,}".format(int(n))


def fmt_bytes(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def fmt_time(iso_text, local):
    if not iso_text:
        return "-"
    dt = datetime.datetime.strptime(iso_text, TS_FORMAT).replace(tzinfo=datetime.timezone.utc)
    if local:
        dt = dt.astimezone()
    return dt.strftime("%Y-%m-%d %H:%M")


def bar(value, maximum, width=30):
    if maximum <= 0:
        return ""
    n = value / float(maximum) * width
    full = int(n)
    return "█" * full + ("▌" if n - full >= 0.5 else "")


def table(headers, rows, aligns):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    def line(cells):
        return "  " + "  ".join(c.rjust(w) if a == "r" else c.ljust(w)
                                for c, w, a in zip(cells, widths, aligns)).rstrip()
    out = [line(headers), "  " + "  ".join("─" * w for w in widths)]
    out += [line(r) for r in rows]
    return "\n".join(out)


def geo_label(g):
    if g.get("country") == "(private/reserved)":
        return "private"
    parts = [p for p in (g.get("city"), g.get("country_code") or g.get("country")) if p]
    return ", ".join(parts) if parts else "-"


def asn_label(g):
    if g.get("asn") == "" and not g.get("org"):
        return "-"
    return ("AS%s " % g["asn"] if g.get("asn") != "" else "") + (g.get("org") or "")


def render_text(d, local, geo_available, attribution):
    out = []
    w = out.append
    since = fmt_time(d["period"]["since"], local) if d["period"]["since"] else "start of logs"
    w("limitlessh report   %s → %s (%s)" % (since, fmt_time(d["period"]["until"], local),
                                          "local time" if local else "UTC"))
    live = d.get("live")
    if live:
        life = live.get("lifetime", {}) if isinstance(live.get("lifetime"), dict) else {}
        lc = life.get("counters", {}) if isinstance(life.get("counters"), dict) else {}
        def num(x):
            return x if isinstance(x, (int, float)) and not isinstance(x, bool) else 0
        uptime = num(live.get("updated_ts")) - num(live.get("started_ts"))
        w("Live      %s active of %s · up %s · stats updated %s" % (
            fmt_int(num(live.get("active"))), fmt_int(num(live.get("max_clients"))),
            fmt_dur(max(0, uptime)), fmt_time(clean(live.get("updated", "")), local) if live.get("updated") else "-"))
        w("Lifetime  since %s: %s trapped · %s attacker time · peak %s active (%s)" % (
            fmt_time(clean(life.get("since", "")), local) if life.get("since") else "-",
            fmt_int(num(lc.get("accepted"))), fmt_dur(num(lc.get("wasted")) + num(live.get("active_time"))),
            fmt_int(num(life.get("peak_active"))),
            fmt_time(clean(life.get("peak", "")), local) if life.get("peak") else "-"))
    o = d["overview"]
    w("")
    w("OVERVIEW")
    pairs = [
        ("Connections trapped", fmt_int(o["trapped"]), "Unique IPs", fmt_int(o["unique_ips"])),
        ("Rejected by limits", fmt_int(o["rejected"]), "Unique networks", fmt_int(o["unique_networks"])),
        ("Attacker time", fmt_dur(o["attacker_time"]), "New IPs", fmt_int(o["new_ips"])),
        ("Average hold", fmt_dur(o["avg_hold"]), "Longest hold", fmt_dur(o["longest_hold"])),
        ("Banner data sent", fmt_bytes(o["bytes_sent"]), "Service starts", fmt_int(o["service_starts"])),
    ]
    for a, b, c, e in pairs:
        w("  %-22s %12s     %-16s %12s" % (a, b, c, e))
    if o["suppressed_log_lines"] or o["invalid_log_lines"]:
        w("  Note: %s events not logged (rate cap), %s unreadable log lines skipped" % (
            fmt_int(o["suppressed_log_lines"]), fmt_int(o["invalid_log_lines"])))
    if not o["trapped"] and not o["rejected"]:
        w("")
        w("No connections in this period.")
        return "\n".join(out)

    total = sum(d["results"].values()) or 1
    w("")
    w("HOW CONNECTIONS ENDED")
    labels = {"closed": "client gave up", "evicted": "evicted (tarpit full)", "stalled": "stopped reading",
              "expired": "max lifetime reached", "shutdown": "service stopped",
              "rejected-ip": "rejected: per-IP limit", "rejected-net": "rejected: per-network limit"}
    biggest = max(d["results"].values())
    for key in RESULTS:
        n = d["results"].get(key, 0)
        if n:
            w("  %-28s %10s %6.1f%%  %s" % (labels[key], fmt_int(n), 100.0 * n / total, bar(n, biggest, 25)))

    w("")
    w("TIME HELD (trapped connections)")
    biggest = max(d["hold_time"].values()) or 1
    for label, n in d["hold_time"].items():
        w("  %-8s %10s %6.1f%%  %s" % (label, fmt_int(n), 100.0 * n / max(1, o["trapped"]), bar(n, biggest, 30)))

    def ip_rows(rows):
        return [[clean(r["ip"], 39), fmt_int(r["conns"]), fmt_int(r["rejected"]), fmt_dur(r["time"]),
                 clean(geo_label(r), 28), clean(asn_label(r), 34)] for r in rows]

    w("")
    w("TOP IPs BY ATTACKER TIME")
    w(table(["IP", "Trapped", "Rejected", "Time", "Location", "Network"],
            ip_rows(d["top_ips_by_time"]), "lrrrll"))
    w("")
    w("TOP IPs BY CONNECTIONS")
    w(table(["IP", "Trapped", "Rejected", "Time", "Location", "Network"],
            ip_rows(d["top_ips_by_connections"]), "lrrrll"))

    if geo_available:
        w("")
        w("TOP COUNTRIES")
        w(table(["Country", "IPs", "Trapped", "Rejected", "Time"],
                [[clean(("%s %s" % (r["country_code"], r["country"])).strip() or "unknown", 34),
                  fmt_int(r["ips"]), fmt_int(r["conns"]), fmt_int(r["rejected"]), fmt_dur(r["time"])]
                 for r in d["top_countries"]], "lrrrr"))
        w("")
        w("TOP NETWORKS (ASN / ISP)")
        w(table(["ASN", "Organisation", "IPs", "Trapped", "Rejected", "Time"],
                [["AS%s" % r["asn"] if r["asn"] != "" else "-", clean(r["org"] or "unknown", 40),
                  fmt_int(r["ips"]), fmt_int(r["conns"]), fmt_int(r["rejected"]), fmt_dur(r["time"])]
                 for r in d["top_asns"]], "llrrrr"))

    w("")
    w("LONGEST SESSIONS")
    w(table(["Started", "IP", "Held", "Ended", "Location", "Network"],
            [[fmt_time(r["start"], local), clean(r["ip"], 39), fmt_dur(r["duration"]), r["result"],
              clean(geo_label(r), 28), clean(asn_label(r), 30)] for r in d["longest_sessions"]], "llrlll"))

    days = list(d["daily"].items())[-14:]
    if days:
        w("")
        w("DAILY%s" % (" (last 14 days shown)" if len(d["daily"]) > 14 else ""))
        biggest = max(v["trapped"] + v["rejected"] for _, v in days) or 1
        w(table(["Date", "Trapped", "Rejected", "IPs", "Time", ""],
                [[day, fmt_int(v["trapped"]), fmt_int(v["rejected"]), fmt_int(v["ips"]), fmt_dur(v["time"]),
                  bar(v["trapped"] + v["rejected"], biggest, 25)] for day, v in days], "lrrrrl"))

    w("")
    w("HOUR OF DAY (%s, all connection attempts)" % ("local time" if local else "UTC"))
    hours = d["hour_of_day"]
    biggest = max(hours.values()) or 1
    for h in range(24):
        w("  %02d:00 %9s  %s" % (h, fmt_int(hours[h]), bar(hours[h], biggest, 40)))

    w("")
    if geo_available:
        src = ", ".join("%s (built %s)" % (f["file"], f["built"]) for f in d["geo_sources"])
        w("Geolocation: %s" % src)
        if attribution:
            w("IP geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0.")
    else:
        w("Geolocation: not available. Run 'sudo limitlessh-report --update-geo' to download DB-IP Lite.")
    return "\n".join(out)


def render_ip(ip_text, records, geo, local, limit):
    g = geo.lookup(ip_text)
    trapped = [r for r in records if not r["result"].startswith("rejected")]
    rejected = len(records) - len(trapped)
    total = sum(r["dur"] for r in trapped)
    out = ["IP %s" % clean(ip_text)]
    if geo.available:
        out.append("  Location   %s" % clean(", ".join(p for p in (g["city"], g["region"], g["country"]) if p) or "-"))
        if g["latitude"] != "":
            out.append("  Coords     %s, %s (approximate)" % (g["latitude"], g["longitude"]))
        out.append("  Network    %s" % clean(asn_label(g)))
    if not records:
        out.append("  No log entries for this IP in the period.")
        return "\n".join(out)
    out.append("  First seen %s" % fmt_time(iso(records[0]["t"]), local))
    out.append("  Last seen  %s" % fmt_time(iso(records[-1]["t"]), local))
    out.append("  Trapped    %s connections, %s total, longest %s" % (
        fmt_int(len(trapped)), fmt_dur(total), fmt_dur(max([r["dur"] for r in trapped] or [0]))))
    out.append("  Rejected   %s" % fmt_int(rejected))
    out.append("")
    shown = records[-limit:]
    out.append("Most recent %d events:" % len(shown))
    out.append(table(["Started", "Held", "Bytes", "Result"],
                     [[fmt_time(iso(r["t"]), local), fmt_dur(r["dur"]), fmt_int(r["bytes"]), r["result"]]
                      for r in shown], "lrrl"))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Reports, raw-log export and IP geolocation for limitlessh %s." % VERSION,
        epilog="Examples:\n"
               "  limitlessh-report                     last 7 days\n"
               "  limitlessh-report --since 24h --top 20\n"
               "  limitlessh-report --since all --json > report.json\n"
               "  limitlessh-report --ip 203.0.113.7\n"
               "  limitlessh-report --since 30d --csv connections.csv\n"
               "  limitlessh-report --lookup 8.8.8.8 1.1.1.1\n"
               "  limitlessh-report --update-geo        download DB-IP Lite databases\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--since", default="7d", help="start of period: 24h, 7d, 2w, 2026-10-01, all (default: 7d)")
    p.add_argument("--until", default="", help="end of period (default: now)")
    p.add_argument("--top", type=int, default=10, help="rows in top lists (default: 10)")
    p.add_argument("--utc", action="store_true", help="show times in UTC instead of local time")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="print the report as JSON")
    out.add_argument("--csv", metavar="FILE", help="export enriched raw records as CSV ('-' for stdout)")
    out.add_argument("--jsonl", metavar="FILE", help="export enriched raw records as JSON lines ('-' for stdout)")
    out.add_argument("--ip", metavar="ADDRESS", help="show details and history for one IP")
    out.add_argument("--lookup", nargs="+", metavar="ADDRESS", help="geolocate addresses and exit")
    out.add_argument("--update-geo", action="store_true", help="download or refresh DB-IP Lite databases")
    p.add_argument("--limit", type=int, default=50, help="events shown with --ip (default: 50)")
    p.add_argument("--no-geo", action="store_true", help="skip geolocation")
    p.add_argument("--geo-edition", choices=("city", "country"), default="city",
                   help="DB-IP edition for --update-geo: city (~250 MB) or country (~10 MB) (default: city)")
    p.add_argument("--log", default=DEFAULT_LOG, help="connection log (default: %s)" % DEFAULT_LOG)
    p.add_argument("--stats", default=DEFAULT_STATS, help="stats file (default: %s)" % DEFAULT_STATS)
    p.add_argument("--geo-dir", default=DEFAULT_GEO_DIR, help="geolocation databases (default: %s)" % DEFAULT_GEO_DIR)
    p.add_argument("-q", "--quiet", action="store_true", help="less output from --update-geo")
    p.add_argument("-V", "--version", action="version", version="%s %s" % (PROG, VERSION))
    args = p.parse_args(argv)
    if not 1 <= args.top <= 1000:
        p.error("--top must be between 1 and 1000")
    if not 1 <= args.limit <= 100000:
        p.error("--limit must be between 1 and 100000")
    return args


def open_output(path):
    if path == "-":
        return sys.stdout, False
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline=""), True


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.update_geo:
            update_geo(args.geo_dir, args.geo_edition, quiet=args.quiet)
            return 0

        geo = NoGeo() if args.no_geo else Geo(args.geo_dir)
        local = not args.utc

        if args.lookup:
            rows = []
            for a in args.lookup:
                try:
                    ip = str(ipaddress.ip_address(a.strip()))
                except ValueError:
                    raise ReportError("not an IP address: %r" % a)
                g = geo.lookup(ip)
                rows.append([ip, clean(", ".join(p for p in (g["city"], g["region"], g["country"]) if p) or "-", 48),
                             clean(asn_label(g), 44)])
            print(table(["IP", "Location", "Network"], rows, "lll"))
            if not geo.available:
                print("\nNo geolocation databases found in %s; run --update-geo." % args.geo_dir)
            return 0

        now = time.time()
        since = parse_when(args.since, now)
        until = parse_when(args.until, now) if args.until else now
        if until < since:
            raise ReportError("--until is before --since")
        if not log_files(args.log):
            raise ReportError("no connection log at %s (is log-file set in the limitlessh config?)" % args.log)
        log_stats = LogStats()

        if args.ip:
            try:
                target = str(ipaddress.ip_address(args.ip.strip()))
            except ValueError:
                raise ReportError("not an IP address: %r" % args.ip)
            records = [r for r in read_records(args.log, since, until, log_stats) if r["ip"] == target]
            print(render_ip(target, records, geo, local, args.limit))
            return 0

        if args.csv or args.jsonl:
            fh, close = open_output(args.csv or args.jsonl)
            count = 0
            try:
                if args.csv:
                    writer = csv.writer(fh)
                    writer.writerow(["time_utc", "ip", "result", "duration_s", "bytes"] + list(Geo.FIELDS))
                for r in read_records(args.log, since, until, log_stats):
                    g = geo.lookup(r["ip"])
                    if args.csv:
                        writer.writerow([iso(r["t"]), r["ip"], r["result"], r["dur"], r["bytes"]] +
                                        [csv_cell(g[k]) for k in Geo.FIELDS])
                    else:
                        fh.write(json.dumps(dict(time_utc=iso(r["t"]), ip=r["ip"], result=r["result"],
                                                 duration_s=r["dur"], bytes=r["bytes"], **g),
                                            ensure_ascii=True) + "\n")
                    count += 1
            finally:
                if close:
                    fh.close()
            if close:
                print("wrote %s records to %s" % (fmt_int(count), args.csv or args.jsonl), file=sys.stderr)
            return 0

        report = Report(geo, local_time=local, top=args.top)
        for r in read_records(args.log, since, until, log_stats):
            report.add(r)
        data = report.as_dict((since, until), load_live(args.stats),
                              new_ip_count(args.log, report, since), log_stats)
        if args.json:
            json.dump(data, sys.stdout, indent=1, ensure_ascii=True, default=str)
            sys.stdout.write("\n")
        else:
            print(render_text(data, local, geo.available, geo.uses_dbip()))
        return 0
    except ReportError as e:
        print("%s: %s" % (PROG, e), file=sys.stderr)
        return 1
    except PermissionError as e:
        print("%s: %s (try sudo)" % (PROG, e), file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
LIMITLESSH_REPORT_EOF
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
  write_report "$tmp"
  if ! python3 -I -B "$tmp" --version >/dev/null; then
    rm -f "$tmp" "$conf"
    die "embedded limitlessh-report failed to start"
  fi
  rm -f "$tmp" "$conf"
}

if [[ "$ACTION" == "print" ]]; then
  if command -v python3 >/dev/null; then check_settings; fi
  echo "# ---- $CONF";         config_text;        echo
  echo "# ---- $SOCKET_UNIT";  socket_unit_text;   echo
  echo "# ---- $SERVICE_UNIT"; service_unit_text
  if (( GEO )); then
    echo; echo "# ---- $GEO_SERVICE_UNIT"; geo_service_text
    echo; echo "# ---- $GEO_TIMER_UNIT"; geo_timer_text
  fi
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
  if (( PURGE )); then
    confirm "Remove limitlessh AND delete its logs, stats and geolocation databases?"
  else
    confirm "Remove limitlessh (units, program, config)? Logs and stats are kept."
  fi
  OLD_PORT="$(sed -n 's/^ListenStream=\([0-9]*\)$/\1/p' "$SOCKET_UNIT" 2>/dev/null | head -1 || true)"
  log "Stopping and removing limitlessh"
  systemctl disable --now limitlessh.socket limitlessh.service \
    limitlessh-geoupdate.timer limitlessh-geoupdate.service 2>/dev/null || true
  rm -f "$SOCKET_UNIT" "$SERVICE_UNIT" "$GEO_SERVICE_UNIT" "$GEO_TIMER_UNIT"
  if [[ -L "$REPORT_LINK" ]]; then rm -f "$REPORT_LINK"; fi
  rm -rf "$PY_DIR" "$CONF_DIR"
  systemctl daemon-reload
  if (( PURGE )); then
    # DynamicUser keeps the real directories under /var/{lib,log}/private
    rm -rf "$STATE_DIR" "$LOGS_DIR" "$GEO_DIR" \
      /var/lib/private/limitlessh /var/log/private/limitlessh /var/lib/private/limitlessh-geo
    log "Deleted logs, stats and geolocation databases"
  else
    echo "Kept: $LOGS_DIR (connection logs), $STATE_DIR (stats), $GEO_DIR (geolocation)."
    echo "Delete them with: sudo $SCRIPT_NAME --uninstall --purge"
  fi
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

log "Installing $REPORT_BIN and $REPORT_LINK"
REPORT_TMP="$(mktemp "$PY_DIR/.limitlessh-report.XXXXXX")"
write_report "$REPORT_TMP"
chmod 0755 "$REPORT_TMP"
mv -f "$REPORT_TMP" "$REPORT_BIN"
if [[ -e "$REPORT_LINK" && ! -L "$REPORT_LINK" ]]; then
  die "$REPORT_LINK exists and is not a symlink; refusing to replace it"
fi
ln -sfn "$REPORT_BIN" "$REPORT_LINK"

log "Writing $CONF"
safe_dir "$CONF_DIR"
[[ -f "$CONF" ]] && cp -a "$CONF" "$CONF.bak"
config_text > "$CONF"
chmod 0644 "$CONF"

log "Installing systemd units"
socket_unit_text  > "$SOCKET_UNIT"
service_unit_text > "$SERVICE_UNIT"
chmod 0644 "$SOCKET_UNIT" "$SERVICE_UNIT"
if (( GEO )); then
  geo_service_text > "$GEO_SERVICE_UNIT"
  geo_timer_text   > "$GEO_TIMER_UNIT"
  chmod 0644 "$GEO_SERVICE_UNIT" "$GEO_TIMER_UNIT"
else
  systemctl disable --now limitlessh-geoupdate.timer 2>/dev/null || true
  rm -f "$GEO_SERVICE_UNIT" "$GEO_TIMER_UNIT"
fi

systemctl daemon-reload
systemctl enable --now limitlessh.socket
systemctl enable limitlessh.service >/dev/null 2>&1 || true
systemctl start limitlessh.service

if ufw_active; then
  log "Allowing ${PORT}/tcp in ufw"
  ufw allow "${PORT}/tcp" comment 'limitlessh tarpit'
fi

if (( GEO )); then
  systemctl enable --now limitlessh-geoupdate.timer >/dev/null 2>&1 || true
  log "Downloading geolocation databases (DB-IP Lite, $GEO_EDITION + ASN); this can take a few minutes"
  if systemctl start limitlessh-geoupdate.service; then
    log "Geolocation databases installed in $GEO_DIR (refreshed monthly)"
  else
    echo "WARNING: geolocation download failed; reports will work without it." >&2
    echo "         Retry later: sudo systemctl start limitlessh-geoupdate.service" >&2
    echo "         Details:     journalctl -u limitlessh-geoupdate -n 20" >&2
  fi
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
if (( CONN_LOG )); then
  echo "  report            : sudo limitlessh-report            (see --help)"
  echo "  connection log    : $LOGS_DIR/connections.log  (kept $LOG_RETENTION_DAYS days)"
fi
if [[ -d "$BACKUP_DIR" ]]; then
  echo "  real sshd         : port ${SSH_PORT}  (backup of /etc/ssh in $BACKUP_DIR)"
  echo
  echo "  BEFORE closing this session, test from a NEW terminal:"
  echo "      ssh -p ${SSH_PORT} ${SUDO_USER:-user}@<this-server>"
  echo "  If your host has a cloud firewall / security group, open ${SSH_PORT}/tcp there too."
fi
