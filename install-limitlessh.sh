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
  * Logs a periodic summary instead of a line per connection.
  * Supports systemd socket activation, so it can run with no privileges and
    no network access of its own.

Python 3.8+ standard library only. Linux recommended.
"""

import argparse
import asyncio
import collections
import ipaddress
import logging
import os
import random
import resource
import signal
import socket
import string
import sys
import time

VERSION = "1.0.1"
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
# The tarpit
# ---------------------------------------------------------------------------

class Client(object):
    __slots__ = ("transport", "ip", "net", "start", "timer", "sent", "active")

    def __init__(self, transport, ip, net, start):
        self.transport = transport
        self.ip = ip
        self.net = net
        self.start = start
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
                "stalled", "expired", "closed", "wasted", "sent")

    def __init__(self, cfg, loop):
        self.cfg = cfg
        self.loop = loop
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
            transport.abort()
            return None
        members = self.by_net.get(net)
        if members is not None and len(members) >= cfg.per_net:
            self.count("rejected_net")
            LOG.debug("reject %s: per-net limit (%d) for %s", ip, cfg.per_net, net)
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
        return True

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
                self.release(client, "closed")
                client.transport.abort()


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
    tarpit = Tarpit(cfg, loop)
    server = await loop.create_server(lambda: TarpitProtocol(tarpit), sock=sock, backlog=4096)
    name = sock.getsockname()
    LOG.info("limitlessh %s listening on [%s]:%d%s (max-clients=%d per-ip=%d per-net=%d delay=%gs)",
             VERSION, name[0], name[1], " via systemd" if activated else "",
             cfg.max_clients, cfg.per_ip, cfg.per_net, cfg.delay)
    if os.geteuid() == 0 and not activated:
        LOG.warning("running as root; prefer the systemd units, which run it unprivileged")

    stop = loop.create_future()
    summary_timer = [None]

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
        set_log_level(new.log_level)
        tarpit.enforce_limits()
        schedule_summary()
        LOG.info("reloaded %s (max-clients=%d per-ip=%d per-net=%d delay=%gs)",
                 config_path, new.max_clients, new.per_ip, new.per_net, new.delay)

    def on_stop(signame):
        LOG.info("%s received, shutting down", signame)
        if not stop.done():
            stop.set_result(None)

    loop.add_signal_handler(signal.SIGTERM, on_stop, "SIGTERM")
    loop.add_signal_handler(signal.SIGINT, on_stop, "SIGINT")
    loop.add_signal_handler(signal.SIGHUP, on_reload)
    loop.add_signal_handler(signal.SIGUSR1, lambda: tarpit.summary(reset=False))
    schedule_summary()

    try:
        await stop
    finally:
        server.close()
        tarpit.shutdown()
        await server.wait_closed()
        tarpit.summary(reset=False)


def main(argv=None):
    args, cli_values = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        cfg = build_config(args.config, cli_values)
    except ConfigError as e:
        print("%s: %s" % (PROG, e), file=sys.stderr)
        return 2
    if args.check_config:
        for name, value in cfg.items():
            print("%-17s %s" % (name, value))
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
