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
