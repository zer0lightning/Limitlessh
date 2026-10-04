#!/usr/bin/env python3
"""
limitlessh-report - reports, live view, raw-log export and IP geolocation for limitlessh.

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
import io
import ipaddress
import json
import math
import mmap
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.request

VERSION = "1.2.3"
PROG = "limitlessh-report"

DEFAULT_LOG = "/var/log/limitlessh/connections.log"
DEFAULT_STATS = "/var/lib/limitlessh/stats.json"
DEFAULT_LIVE = "/var/lib/limitlessh/live.json"
DEFAULT_GEO_DIR = "/var/lib/limitlessh-geo"

# Database file names we look for, in order of preference.
CITY_FILES = ("GeoLite2-City.mmdb", "GeoIP2-City.mmdb", "dbip-city-lite.mmdb")
COUNTRY_FILES = ("GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb", "dbip-country-lite.mmdb")
ASN_FILES = ("GeoIP2-ISP.mmdb", "GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")

DBIP_URL = "https://download.db-ip.com/free/dbip-{edition}-lite-{month}.mmdb.gz"
MAX_DOWNLOAD_BYTES = 400 * 1048576      # compressed
MAX_DATABASE_BYTES = 1536 * 1048576     # decompressed
MAX_LOG_LINE = 4096
# Distinct IPs tracked per report. Beyond this, records are still counted in
# totals but not broken down per IP, so a huge log can't exhaust memory.
MAX_TRACKED_IPS = 500000
# Timestamps outside 2000-2100 in snapshot files are treated as invalid.
TS_MIN, TS_MAX = 946684800.0, 4102444800.0
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
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        self._file = os.fdopen(fd, "rb")
        try:
            st = os.fstat(self._file.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise MMDBError("not a regular file")
            size = st.st_size
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


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """https_only: refuse any redirect that would leave HTTPS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.full_url.startswith("https://") and not newurl.startswith("https://"):
            raise ReportError("refusing redirect from HTTPS to %s" % newurl[:100])
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url, out, limit):
    """Stream url into the open binary file `out`, enforcing a size limit."""
    req = urllib.request.Request(url, headers={"User-Agent": "limitlessh-report/%s" % VERSION})
    opener = urllib.request.build_opener(_HttpsOnlyRedirects)
    with opener.open(req, timeout=60) as resp:
        if resp.status != 200:
            raise ReportError("HTTP %d for %s" % (resp.status, url))
        length = resp.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > limit:
            raise ReportError("%s is larger than the %d MiB limit" % (url, limit // 1048576))
        total = 0
        h = hashlib.sha256()
        while True:
            chunk = resp.read(1048576)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ReportError("%s exceeded the %d MiB limit" % (url, limit // 1048576))
            h.update(chunk)
            out.write(chunk)
    out.flush()
    return h.hexdigest(), total


def _gunzip(src, dest, limit):
    """Decompress open file `src` into open file `dest`, enforcing a size limit."""
    src.seek(0)
    total = 0
    with gzip.GzipFile(fileobj=src, mode="rb") as zin:
        while True:
            chunk = zin.read(1048576)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ReportError("decompressed database exceeds %s bytes; refusing" % fmt_int(limit))
            dest.write(chunk)
    dest.flush()
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
        return clean(db.database_type, 64), db.build_epoch


def _enter_geo_dir(geo_dir):
    """Work inside geo_dir with the least privilege available.

    The directory normally belongs to the updater's DynamicUser. If root runs
    --update-geo, anything that user planted there (symlinks, swapped temp
    files) would otherwise be followed with root's privileges. So: hold the
    directory as the working directory, then, if we are root and the directory
    belongs to someone else, become that user before touching any file in it.
    Returns (restore, dropped): restore() returns to the previous directory
    when privileges were not dropped.
    """
    os.makedirs(geo_dir, mode=0o755, exist_ok=True)
    try:
        prev = os.open(".", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        prev = None
    dfd = os.open(geo_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        st = os.fstat(dfd)
        os.fchdir(dfd)
    finally:
        os.close(dfd)
    dropped = False
    if os.geteuid() == 0 and st.st_uid != 0:
        os.setgroups([])
        os.setgid(st.st_gid)
        os.setuid(st.st_uid)
        dropped = True

    def restore():
        if prev is not None:
            try:
                if not dropped:
                    os.fchdir(prev)
            except OSError:
                pass
            os.close(prev)
    return restore, dropped


def _fd_path(f):
    """A path that refers to the open file itself, not to a name someone could swap."""
    proc = "/proc/self/fd/%d" % f.fileno()
    return proc if os.path.exists(proc) else f.name


def update_geo(geo_dir, edition, quiet=False):
    if edition not in ("city", "country"):
        raise ReportError("edition must be city or country")
    restore, dropped = _enter_geo_dir(geo_dir)
    try:
        if dropped and not quiet:
            print("running as uid %d (owner of %s)" % (os.getuid(), geo_dir))
        _update_geo_here(geo_dir, edition, quiet)
    finally:
        restore()


def _update_geo_here(geo_dir, edition, quiet):
    """Runs with the geo directory as the working directory. Every temporary
    file is created with O_EXCL under a random name and written, verified and
    chmod-ed through its own descriptor; nothing is reopened by name."""
    installed = {}
    for kind in (edition, "asn"):
        final = "dbip-%s-lite.mmdb" % kind
        errors = []
        done = False
        for month in _months_to_try():
            url = DBIP_URL.format(edition=kind, month=month)
            gz = tempfile.NamedTemporaryFile(prefix=".dl-", suffix=".gz", dir=".", delete=False)
            db = tempfile.NamedTemporaryFile(prefix=".db-", suffix=".mmdb", dir=".", delete=False)
            try:
                if not quiet:
                    print("downloading %s" % url)
                digest, size = _download(url, gz, MAX_DOWNLOAD_BYTES)
                _gunzip(gz, db, MAX_DATABASE_BYTES)
                dtype, built = _verify_database(_fd_path(db), kind)
                os.fchmod(db.fileno(), 0o644)
                os.replace(db.name, final)
                installed[kind] = {"file": final, "url": url, "month": month,
                                   "sha256_gz": digest, "type": dtype,
                                   "built": time.strftime("%Y-%m-%d", time.gmtime(built)) if built else ""}
                if not quiet:
                    print("installed %s (%s, %.1f MiB download)"
                          % (os.path.join(geo_dir, final), dtype, size / 1048576.0))
                done = True
                break
            except urllib.error.HTTPError as e:
                errors.append("%s: HTTP %d" % (url, e.code))
            except (urllib.error.URLError, OSError, ReportError, MMDBError, EOFError, gzip.BadGzipFile) as e:
                errors.append("%s: %s" % (url, clean(getattr(e, "reason", None) or e, 200)))
            finally:
                for f in (gz, db):
                    f.close()
                    try:
                        os.unlink(f.name)  # unlink never follows symlinks
                    except OSError:
                        pass
        if not done:
            raise ReportError("could not update %s database (existing files kept):\n  %s"
                              % (kind, "\n  ".join(errors)))
    # A city database replaces a country one and vice versa
    other = "country" if edition == "city" else "city"
    try:
        os.unlink("dbip-%s-lite.mmdb" % other)
    except OSError:
        pass
    info = {"updated": time.strftime(TS_FORMAT, time.gmtime()), "source": "DB-IP Lite (CC BY 4.0, https://db-ip.com)",
            "databases": installed}
    with tempfile.NamedTemporaryFile("w", prefix=".source-", suffix=".json", dir=".",
                                     delete=False, encoding="utf-8") as f:
        json.dump(info, f, indent=1)
        os.fchmod(f.fileno(), 0o644)
    os.replace(f.name, "source.json")


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
    # The log directory belongs to the service user; don't follow links it may plant
    return [f for f in files if not os.path.islink(f)]


def _rotated_stamp(path):
    m = re.search(r"-(\d{8}T\d{6}Z)(?:-\d+)?\.log(?:\.gz)?$", path)
    if m:
        try:
            return float(datetime.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ")
                         .replace(tzinfo=datetime.timezone.utc).timestamp())
        except ValueError:
            pass
    return None


def _open_log(path):
    """Open a log for reading as text. The directory belongs to the service user,
    so refuse symlinks (O_NOFOLLOW, no check-then-open race) and anything that
    isn't a regular file, such as a FIFO that would block forever."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    raw = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(raw.fileno()).st_mode):
        raw.close()
        return None
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.GzipFile(fileobj=raw, mode="rb"), encoding="utf-8", errors="replace")
    return io.TextIOWrapper(raw, encoding="utf-8", errors="replace")


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
            fh = _open_log(path)
            if fh is None:
                print("%s: warning: skipping %s (not a regular file)" % (PROG, path), file=sys.stderr)
                continue
            with fh:
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
    except (ValueError, RecursionError):
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
        self.untracked = 0

    def add(self, r):
        t = r["t"]
        self.first = t if self.first is None else min(self.first, t)
        self.last = t if self.last is None else max(self.last, t)
        ip = self.ips.get(r["ip"])
        if ip is None:
            if len(self.ips) >= MAX_TRACKED_IPS:
                self.untracked += 1
                ip = {"conns": 0, "rejected": 0, "time": 0.0, "bytes": 0, "first": t, "last": t,
                      "longest": 0.0}  # counted in totals, not kept per IP
            else:
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
                "records_without_ip_breakdown": self.untracked,
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
    return read_json_file(path, 1048576)


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
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def clean(text, width=None):
    """Strip control and bidi characters so data can't drive the terminal.
    In ASCII mode, accented letters are transliterated (Linköping -> Linkoping)."""
    s = _CONTROL.sub("", str(text))
    if G is GLYPHS_ASCII or G.get("full") == "#":
        s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    if width is not None and len(s) > width:
        s = s[:max(1, width - 3)] + "..."
    return s


def csv_cell(value):
    """Neutralise spreadsheet formula injection."""
    s = clean(value)
    if s and s[0] in "=+-@\t\r" and not re.fullmatch(r"-?\d+(\.\d+)?", s):
        s = "'" + s
    return s


class Style(object):
    """ANSI colours. Applied only to text that has already been clean()ed."""
    CODES = {"bold": "1", "dim": "2", "italic": "3", "under": "4",
             "red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
             "grey": "90", "bred": "91", "bgreen": "92", "byellow": "93", "bblue": "94",
             "bmagenta": "95", "bcyan": "96", "white": "97", "inverse": "7"}

    def __init__(self, enabled=False):
        self.on = enabled

    def __call__(self, text, *styles):
        if not self.on or not styles:
            return text
        return "\x1b[%sm%s\x1b[0m" % (";".join(self.CODES[s] for s in styles), text)


S = Style(False)

# Bar and rule characters. Box-drawing blocks by default; plain ASCII with
# --ascii or when the terminal isn't UTF-8. No other symbols are used.
GLYPHS_UNICODE = {"full": "█", "half": "▌", "tiny": "▏", "empty": "░", "rule": "─"}
GLYPHS_ASCII = {"full": "#", "half": "", "tiny": "|", "empty": ".", "rule": "-"}
G = dict(GLYPHS_UNICODE)


def use_ascii(force):
    enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
    return force or bool(os.environ.get("LIMITLESSH_ASCII")) or enc not in ("utf8", "utf8sig")

RESULT_STYLE = {"closed": ("green",), "evicted": ("yellow",), "stalled": ("magenta",),
                "expired": ("blue",), "shutdown": ("grey",),
                "rejected-ip": ("red",), "rejected-net": ("bred",)}


def color_mode(choice):
    if choice == "always":
        return True
    if choice == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() and os.environ.get("TERM", "") not in ("", "dumb")


def vlen(s):
    return len(_ANSI.sub("", s))


def clip(s, width):
    """Cut a string to `width` visible characters, keeping colour codes intact."""
    if vlen(s) <= width:
        return s
    out, seen, i = [], 0, 0
    while i < len(s) and seen < width:
        m = _ANSI.match(s, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        out.append(s[i])
        seen += 1
        i += 1
    return "".join(out) + ("\x1b[0m" if S.on else "")


def pad(s, width, align="l"):
    gap = max(0, width - vlen(s))
    return (" " * gap + s) if align == "r" else (s + " " * gap)


def fmt_dur(seconds):
    seconds = int(round(max(0, seconds)))
    if seconds < 60:
        return "%ds" % seconds
    out = []
    for unit, size in (("y", 31536000), ("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if out or seconds >= size:  # largest unit, then the next one even if zero
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
    try:
        dt = datetime.datetime.strptime(iso_text, TS_FORMAT).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return "-"
    if local:
        dt = dt.astimezone()
    return dt.strftime("%Y-%m-%d %H:%M")


def fmt_clock(ts, local):
    if not TS_MIN <= num(ts) <= TS_MAX:
        return "-"
    dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    if local:
        dt = dt.astimezone()
    return dt.strftime("%m-%d %H:%M" if time.time() - ts > 86400 else "%H:%M:%S")


def dur_style(seconds, text):
    if seconds >= 3600:
        return S(text, "bgreen", "bold")
    if seconds >= 600:
        return S(text, "green")
    if seconds < 30:
        return S(text, "grey")
    return text


def bar(value, maximum, width=30, *styles):
    if maximum <= 0 or width <= 0:
        return ""
    n = value / float(maximum) * width
    full = int(n)
    text = G["full"] * full + (G["half"] if n - full >= 0.5 else "")
    if not text and value > 0:
        text = G["tiny"]
    return S(text, *styles) if styles else text


def gauge(value, maximum, width):
    frac = 0.0 if maximum <= 0 else min(1.0, value / float(maximum))
    full = int(round(frac * width))
    colour = "green" if frac < 0.6 else "yellow" if frac < 0.9 else "red"
    return S(G["full"] * full, colour) + S(G["empty"] * (width - full), "grey")


def heading(title, extra=""):
    line = S(title, "bold", "bcyan")
    return line + ("  " + S(extra, "grey") if extra else "")


def table(headers, rows, aligns, indent="  "):
    widths = [vlen(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], vlen(cell))

    def line(cells, head=False):
        parts = [pad(S(c, "bold") if head else c, w, a) for c, w, a in zip(cells, widths, aligns)]
        return (indent + "  ".join(parts)).rstrip()
    out = [line(headers, True), indent + S("  ".join(G["rule"] * w for w in widths), "grey")]
    out += [line(r) for r in rows]
    return "\n".join(out)


def geo_label(g):
    if g.get("country") == "(private/reserved)":
        return S("private", "grey")
    parts = [p for p in (g.get("city"), g.get("country_code") or g.get("country")) if p]
    return S(clean(", ".join(parts), 28), "cyan") if parts else S("-", "grey")


def asn_label(g, width=34):
    if g.get("asn") == "" and not g.get("org"):
        return S("-", "grey")
    num = ("AS%s " % g["asn"]) if g.get("asn") != "" else ""
    return S(num, "grey") + clean(g.get("org") or "", max(4, width - len(num)))


def ip_text(ip):
    return S(clean(ip, 39), "byellow")


def big(n):
    return S(n, "bold", "white")


def render_text(d, local, geo_available, attribution):
    out = []
    w = out.append
    since = fmt_time(d["period"]["since"], local) if d["period"]["since"] else "start of logs"
    w(S(" limitlessh report ", "bold", "inverse") + "  " +
      S("%s to %s (%s)" % (since, fmt_time(d["period"]["until"], local), "local time" if local else "UTC"), "grey"))
    live = d.get("live")
    if live:
        life = live.get("lifetime", {}) if isinstance(live.get("lifetime"), dict) else {}
        lc = life.get("counters", {}) if isinstance(life.get("counters"), dict) else {}
        uptime = num(live.get("updated_ts")) - num(live.get("started_ts"))
        w("%s %s active of %s, up %s, stats updated %s" % (
            S("Live    ", "bold"), big(fmt_int(num(live.get("active")))), fmt_int(num(live.get("max_clients"))),
            fmt_dur(max(0, uptime)), fmt_time(clean(live.get("updated", "")), local)))
        w("%s since %s: %s trapped, %s attacker time, peak %s active (%s)" % (
            S("Lifetime", "bold"), fmt_time(clean(life.get("since", "")), local),
            big(fmt_int(num(lc.get("accepted")))), big(fmt_dur(num(lc.get("wasted")) + num(live.get("active_time")))),
            fmt_int(num(life.get("peak_active"))), fmt_time(clean(life.get("peak", "")), local)))
    o = d["overview"]
    w("")
    w(heading("OVERVIEW"))
    pairs = [
        ("Connections trapped", fmt_int(o["trapped"]), "Unique IPs", fmt_int(o["unique_ips"])),
        ("Rejected by limits", fmt_int(o["rejected"]), "Unique networks", fmt_int(o["unique_networks"])),
        ("Attacker time", fmt_dur(o["attacker_time"]), "New IPs", fmt_int(o["new_ips"])),
        ("Average hold", fmt_dur(o["avg_hold"]), "Longest hold", fmt_dur(o["longest_hold"])),
        ("Banner data sent", fmt_bytes(o["bytes_sent"]), "Service starts", fmt_int(o["service_starts"])),
    ]
    for a, b, c, e in pairs:
        w("  %s %s     %s %s" % (pad(a, 22), pad(big(b), 12, "r"), pad(c, 16), pad(big(e), 12, "r")))
    if o.get("records_without_ip_breakdown"):
        w("  " + S("Note: more than %s distinct IPs; %s records are in totals but not in per-IP tables" % (
            fmt_int(MAX_TRACKED_IPS), fmt_int(o["records_without_ip_breakdown"])), "yellow"))
    if o["suppressed_log_lines"] or o["invalid_log_lines"]:
        w("  " + S("Note: %s events not logged (rate cap), %s unreadable log lines skipped" % (
            fmt_int(o["suppressed_log_lines"]), fmt_int(o["invalid_log_lines"])), "yellow"))
    if not o["trapped"] and not o["rejected"]:
        w("")
        w("No connections in this period.")
        return "\n".join(out)

    total = sum(d["results"].values()) or 1
    w("")
    w(heading("HOW CONNECTIONS ENDED"))
    labels = {"closed": "client gave up", "evicted": "evicted (tarpit full)", "stalled": "stopped reading",
              "expired": "max lifetime reached", "shutdown": "service stopped",
              "rejected-ip": "rejected: per-IP limit", "rejected-net": "rejected: per-network limit"}
    biggest = max(d["results"].values())
    for key in RESULTS:
        n = d["results"].get(key, 0)
        if n:
            w("  %s %s %6.1f%%  %s" % (pad(S(labels[key], *RESULT_STYLE[key]), 28), pad(fmt_int(n), 10, "r"),
                                     100.0 * n / total, bar(n, biggest, 25, *RESULT_STYLE[key])))

    w("")
    w(heading("TIME HELD", "trapped connections"))
    biggest = max(d["hold_time"].values()) or 1
    hold_colours = ("grey", "grey", "cyan", "cyan", "green", "bgreen", "bgreen")
    for (label, n), colour in zip(d["hold_time"].items(), hold_colours):
        w("  %-8s %10s %6.1f%%  %s" % (label, fmt_int(n), 100.0 * n / max(1, o["trapped"]), bar(n, biggest, 30, colour)))

    def ip_rows(rows):
        return [[ip_text(r["ip"]), fmt_int(r["conns"]), S(fmt_int(r["rejected"]), "red") if r["rejected"] else "0",
                 dur_style(r["time"], fmt_dur(r["time"])), geo_label(r), asn_label(r)] for r in rows]

    w("")
    w(heading("TOP IPs BY ATTACKER TIME"))
    w(table(["IP", "Trapped", "Rejected", "Time", "Location", "Network"], ip_rows(d["top_ips_by_time"]), "lrrrll"))
    w("")
    w(heading("TOP IPs BY CONNECTIONS"))
    w(table(["IP", "Trapped", "Rejected", "Time", "Location", "Network"], ip_rows(d["top_ips_by_connections"]), "lrrrll"))

    if geo_available:
        w("")
        w(heading("TOP COUNTRIES"))
        w(table(["Country", "IPs", "Trapped", "Rejected", "Time"],
                [[S(clean(("%s %s" % (r["country_code"], r["country"])).strip() or "unknown", 34), "cyan"),
                  fmt_int(r["ips"]), fmt_int(r["conns"]), fmt_int(r["rejected"]), fmt_dur(r["time"])]
                 for r in d["top_countries"]], "lrrrr"))
        w("")
        w(heading("TOP NETWORKS", "ASN / ISP"))
        w(table(["ASN", "Organisation", "IPs", "Trapped", "Rejected", "Time"],
                [[S("AS%s" % r["asn"], "grey") if r["asn"] != "" else S("-", "grey"),
                  clean(r["org"] or "unknown", 40),
                  fmt_int(r["ips"]), fmt_int(r["conns"]), fmt_int(r["rejected"]), fmt_dur(r["time"])]
                 for r in d["top_asns"]], "llrrrr"))

    w("")
    w(heading("LONGEST SESSIONS"))
    w(table(["Started", "IP", "Held", "Ended", "Location", "Network"],
            [[S(fmt_time(r["start"], local), "grey"), ip_text(r["ip"]), dur_style(r["duration"], fmt_dur(r["duration"])),
              S(r["result"], *RESULT_STYLE.get(r["result"], ())), geo_label(r), asn_label(r, 30)]
             for r in d["longest_sessions"]], "llrlll"))

    days = list(d["daily"].items())[-14:]
    if days:
        w("")
        w(heading("DAILY", "last 14 days shown" if len(d["daily"]) > 14 else ""))
        biggest = max(v["trapped"] + v["rejected"] for _, v in days) or 1
        w(table(["Date", "Trapped", "Rejected", "IPs", "Time", ""],
                [[day, fmt_int(v["trapped"]), fmt_int(v["rejected"]), fmt_int(v["ips"]), fmt_dur(v["time"]),
                  bar(v["trapped"], biggest, 25, "cyan") + bar(v["rejected"], biggest, 25, "red")]
                 for day, v in days], "lrrrrl"))

    w("")
    w(heading("HOUR OF DAY", "%s, all connection attempts" % ("local time" if local else "UTC")))
    hours = d["hour_of_day"]
    biggest = max(hours.values()) or 1
    for h in range(24):
        frac = hours[h] / float(biggest)
        colour = "bblue" if frac > 0.8 else "blue" if frac > 0.4 else "grey"
        w("  %02d:00 %9s  %s" % (h, fmt_int(hours[h]), bar(hours[h], biggest, 40, colour)))

    w("")
    if geo_available:
        src = ", ".join("%s (built %s)" % (f["file"], f["built"]) for f in d["geo_sources"])
        w(S("Geolocation: %s" % src, "grey"))
        if attribution:
            w(S("IP geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0.", "grey"))
    else:
        w(S("Geolocation: not available. Run 'sudo systemctl start limitlessh-geoupdate' to download DB-IP Lite.", "yellow"))
    return "\n".join(out)


def render_ip(ip_str, records, geo, local, limit):
    g = geo.lookup(ip_str)
    trapped = [r for r in records if not r["result"].startswith("rejected")]
    rejected = len(records) - len(trapped)
    total = sum(r["dur"] for r in trapped)
    out = [S(" IP ", "bold", "inverse") + " " + ip_text(ip_str)]
    if geo.available:
        out.append("  Location   %s" % S(clean(", ".join(p for p in (g["city"], g["region"], g["country"]) if p) or "-"), "cyan"))
        if g["latitude"] != "":
            out.append("  Coords     %s, %s %s" % (g["latitude"], g["longitude"], S("(approximate)", "grey")))
        out.append("  Network    %s" % asn_label(g, 60))
    if not records:
        out.append("  No log entries for this IP in the period.")
        return "\n".join(out)
    out.append("  First seen %s" % fmt_time(iso(records[0]["t"]), local))
    out.append("  Last seen  %s" % fmt_time(iso(records[-1]["t"]), local))
    out.append("  Trapped    %s connections, %s total, longest %s" % (
        big(fmt_int(len(trapped))), big(fmt_dur(total)), fmt_dur(max([r["dur"] for r in trapped] or [0]))))
    out.append("  Rejected   %s" % (S(fmt_int(rejected), "red") if rejected else "0"))
    out.append("")
    shown = records[-limit:]
    out.append(heading("Most recent %d events" % len(shown)))
    out.append(table(["Started", "Held", "Bytes", "Result"],
                     [[S(fmt_time(iso(r["t"]), local), "grey"), dur_style(r["dur"], fmt_dur(r["dur"])),
                       fmt_int(r["bytes"]), S(r["result"], *RESULT_STYLE.get(r["result"], ()))]
                      for r in shown], "lrrl"))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Live view
# ---------------------------------------------------------------------------

def num(v, default=0):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else default


def touch_request(path):
    """Ask limitlessh for live snapshots by touching LIVE-FILE.request.

    The directory belongs to the service's throwaway user and we run as root,
    so refuse symlinks (O_NOFOLLOW), FIFOs and other non-regular files, and
    files with extra hard links: a compromised service must not be able to
    make root create or touch files elsewhere.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as e:
        if e.errno == 13:
            raise ReportError("cannot write %s: permission denied (try sudo)" % path)
        raise ReportError("refusing to use %s: %s" % (path, e.strerror or e))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ReportError("refusing to use %s: not a plain file" % path)
        os.utime(fd)
    finally:
        os.close(fd)


def read_json_file(path, limit):
    """Read a JSON file without following symlinks; None if missing or unusable."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        data = f.read(limit + 1)
    if len(data) > limit:
        return None
    try:
        value = json.loads(data.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _ts(v):
    v = num(v)
    return v if TS_MIN <= v <= TS_MAX else 0.0


def _valid_ip(v):
    try:
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return None


def parse_live(raw):
    """Validate a live snapshot; everything in it is treated as untrusted."""
    if not raw:
        return None
    snap = {k: num(raw.get(k)) for k in ("active", "networks", "max_clients",
                                         "per_ip", "per_net", "delay", "peak_window", "active_time",
                                         "accepts_per_min", "rejects_per_min", "lifetime_accepted",
                                         "lifetime_wasted", "sessions_truncated")}
    snap["updated_ts"] = _ts(raw.get("updated_ts"))
    snap["started_ts"] = _ts(raw.get("started_ts"))
    for k in ("active", "networks", "max_clients", "per_ip", "per_net", "sessions_truncated",
              "accepts_per_min", "rejects_per_min", "lifetime_accepted"):
        snap[k] = min(max(snap[k], 0), 1e12)
    for k in ("active_time", "lifetime_wasted", "delay", "peak_window"):
        snap[k] = min(max(snap[k], 0), 1e13)
    sc = raw.get("session", {}).get("counters", {}) if isinstance(raw.get("session"), dict) else {}
    snap["counters"] = {k: min(max(num(sc.get(k)), 0), 1e15) for k in ("accepted", "rejected_ip", "rejected_net", "evicted",
                                                     "stalled", "expired", "closed", "wasted")} \
        if isinstance(sc, dict) else {}
    sessions = []
    for s in (raw.get("sessions") or [])[:100000] if isinstance(raw.get("sessions"), list) else []:
        if isinstance(s, dict):
            ip = _valid_ip(s.get("ip"))
            if ip:
                start = _ts(s.get("start_ts"))
                if start:
                    sessions.append({"ip": ip, "start_ts": start, "bytes": int(min(max(num(s.get("bytes")), 0), 1e15))})
    snap["sessions"] = sessions
    recent = []
    for e in (raw.get("recent") or [])[:1000] if isinstance(raw.get("recent"), list) else []:
        if isinstance(e, dict) and e.get("result") in RESULTS:
            ip = _valid_ip(e.get("ip"))
            if ip:
                when = _ts(e.get("ts"))
                if when:
                    recent.append({"ts": when, "ip": ip, "result": e["result"],
                                   "dur": min(max(num(e.get("dur")), 0), 1e10),
                                   "bytes": int(min(max(num(e.get("bytes")), 0), 1e15))})
    snap["recent"] = recent
    top = []
    for item in (raw.get("top_active_ips") or [])[:100] if isinstance(raw.get("top_active_ips"), list) else []:
        if isinstance(item, list) and len(item) == 2:
            ip = _valid_ip(item[0])
            if ip:
                top.append((ip, int(min(max(num(item[1]), 0), 1e9))))
    snap["top"] = top
    return snap


def side_by_side(left, right, left_width, gap=4):
    rows = max(len(left), len(right))
    left = left + [""] * (rows - len(left))
    right = right + [""] * (rows - len(right))
    return [pad(clip(a, left_width), left_width) + " " * gap + b for a, b in zip(left, right)]


def render_live(snap, geo, local, width, height, interval, stale_reason=None):
    now = time.time()
    lines = []
    w = lines.append
    title = S(" limitlessh live ", "bold", "inverse")
    if stale_reason:
        status = S(" STALE ", "bold", "inverse", "yellow") + " " + S(stale_reason, "byellow")
    else:
        status = S(" LIVE ", "bold", "inverse", "green") + S(" updated %s" % fmt_clock(snap["updated_ts"], local), "grey")
    right = S(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "   every %gs   q to quit" % interval, "grey")
    w(title + "  " + status + " " * max(1, width - vlen(title) - vlen(status) - vlen(right) - 2) + right)
    if snap is None:
        w("")
        w(S("  Waiting for data from limitlessh...", "yellow"))
        w(S("  Check that the service is running and that live-file is set in /etc/limitlessh/limitlessh.conf.", "grey"))
        return "\n".join(lines)

    gwidth = max(10, min(40, width - 60))
    active, cap = int(snap["active"]), int(snap["max_clients"])
    pct = 100.0 * active / cap if cap else 0
    w("")
    w("  %s %s / %s  %s %s     %s %s" % (S("ACTIVE   ", "bold"), big(fmt_int(active)), fmt_int(cap),
                                        gauge(active, cap, gwidth), S("%3.0f%%" % pct, "bold"),
                                        S("networks", "grey"), big(fmt_int(snap["networks"]))))
    w("  %s %s trapped   %s rejected   %s" % (
        S("PER MIN  ", "bold"), S("+" + fmt_int(snap["accepts_per_min"]), "bgreen", "bold"),
        S("-" + fmt_int(snap["rejects_per_min"]), "bred", "bold"),
        S("(limits: %d per IP, %d per network)" % (snap["per_ip"], snap["per_net"]), "grey")))
    held_now = sum(max(0.0, now - s["start_ts"]) for s in snap["sessions"]) if snap["sessions"] else snap["active_time"]
    w("  %s %s held right now   %s this run   %s lifetime   %s" % (
        S("ATTACKER ", "bold"), S(fmt_dur(held_now), "bgreen", "bold"),
        big(fmt_dur(snap["counters"].get("wasted", 0) + held_now)),
        big(fmt_dur(snap["lifetime_wasted"] + held_now)),
        S("up %s" % fmt_dur(now - snap["started_ts"]) if snap["started_ts"] else "", "grey")))
    c = snap["counters"]
    w("  %s %s trapped, %s closed, %s evicted, %s stalled, %s rejected" % (
        S("THIS RUN ", "bold"), big(fmt_int(c.get("accepted", 0))), S(fmt_int(c.get("closed", 0)), "green"),
        S(fmt_int(c.get("evicted", 0)), "yellow"), S(fmt_int(c.get("stalled", 0)), "magenta"),
        S(fmt_int(c.get("rejected_ip", 0) + c.get("rejected_net", 0)), "red")))

    # Space: header (6) + blank/heading/table header (3 per section) + footer (1)
    free = max(8, height - len(lines) - 2)
    lower_rows = max(4, min(12, free // 3))
    session_rows = max(3, free - lower_rows - 6)

    sessions = sorted(snap["sessions"], key=lambda s: s["start_ts"])[:session_rows]
    w("")
    shown = "showing %d of %s" % (len(sessions), fmt_int(active))
    if snap["sessions_truncated"]:
        shown += " (snapshot capped)"
    w(heading("CURRENT SESSIONS", "longest held first, " + shown))
    rows = []
    for i, s in enumerate(sessions, 1):
        held = max(0.0, now - s["start_ts"])
        g = geo.lookup(s["ip"])
        rows.append([S(str(i), "grey"), ip_text(s["ip"]), dur_style(held, fmt_dur(held)),
                     S(fmt_clock(s["start_ts"], local), "grey"), fmt_int(s["bytes"]), geo_label(g),
                     asn_label(g, max(10, width - 100))])
    if rows:
        lines.extend(clip(x, width) for x in table(["#", "IP", "Held", "Since", "Bytes", "Location", "Network"],
                                                   rows, "rlrlrll").split("\n"))
    else:
        w(S("  No clients trapped right now.", "grey"))

    top_rows = []
    biggest = max([n for _, n in snap["top"]] or [1])
    for ip, n in snap["top"][:lower_rows]:
        g = geo.lookup(ip)
        top_rows.append([ip_text(ip), pad(str(n), 3, "r") + " " + bar(n, biggest, 8, "cyan"), geo_label(g)])
    top_block = [heading("TOP ACTIVE SOURCES")] + (
        table(["IP", "Sessions", "Location"], top_rows, "lll").split("\n") if top_rows else [S("  none", "grey")])

    recent_rows = []
    for e in reversed(snap["recent"][-lower_rows:]):
        recent_rows.append([S(fmt_clock(e["ts"], local), "grey"), ip_text(e["ip"]),
                            S(e["result"], *RESULT_STYLE[e["result"]]),
                            dur_style(e["dur"], fmt_dur(e["dur"])) if not e["result"].startswith("rejected") else S("-", "grey")])
    recent_block = [heading("RECENT EVENTS", "newest first")] + (
        table(["Time", "IP", "Result", "Held"], recent_rows, "lllr").split("\n") if recent_rows else [S("  none yet", "grey")])

    w("")
    left_width = max(vlen(x) for x in top_block)
    if width >= left_width + 4 + max(vlen(x) for x in recent_block):
        lines.extend(side_by_side(top_block, recent_block, left_width))
    else:
        lines.extend(top_block)
        w("")
        lines.extend(recent_block)
    return "\n".join(clip(x, width) for x in lines[:max(1, height - 1)])


class Terminal(object):
    """Full-screen mode with cbreak input; restored on exit, even after errors."""

    def __init__(self):
        self.fd = None
        self.saved = None

    def __enter__(self):
        sys.stdout.write("\x1b[?1049h\x1b[?25l")  # alternate screen, hide cursor
        sys.stdout.flush()
        if sys.stdin.isatty():
            import termios
            import tty
            self.fd = sys.stdin.fileno()
            self.saved = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
        return self

    def __exit__(self, *exc):
        if self.saved is not None:
            import termios
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)
        sys.stdout.write("\x1b[0m\x1b[?25h\x1b[?1049l")
        sys.stdout.flush()

    def wait_key(self, timeout):
        """Return a pressed key or None after timeout."""
        if self.fd is None:
            time.sleep(timeout)
            return None
        import select
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if ready:
            return os.read(self.fd, 1).decode("ascii", "ignore")
        return None


def live_loop(live_path, geo, local, interval, once):
    request = live_path + ".request"

    def frame():
        touch_request(request)
        snap = parse_live(read_json_file(live_path, 16 * 1048576))
        stale = None
        if snap is None:
            stale = "no live data yet"
        elif time.time() - snap["updated_ts"] > max(5.0, interval * 3):
            stale = "data is %s old (service stopped?)" % fmt_dur(time.time() - snap["updated_ts"])
        return snap, stale

    if once:
        snap, stale = frame()
        if snap is None:
            time.sleep(1.5)  # first request: give the service a moment to write
            snap, stale = frame()
        size = shutil.get_terminal_size((120, 50))
        print(render_live(snap, geo, local, size.columns, 10 ** 6, interval, stale))
        return
    with Terminal() as term:
        while True:
            snap, stale = frame()
            size = shutil.get_terminal_size((120, 40))
            screen = render_live(snap, geo, local, size.columns, size.lines, interval, stale)
            sys.stdout.write("\x1b[H" + screen.replace("\n", "\x1b[K\n") + "\x1b[K\x1b[J")
            sys.stdout.flush()
            key = term.wait_key(interval)
            if key in ("q", "Q", "\x1b"):
                return


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Reports, live view, raw-log export and IP geolocation for limitlessh %s." % VERSION,
        epilog="Examples:\n"
               "  limitlessh-report                     last 7 days\n"
               "  limitlessh-report --live              live sessions, refreshes every 2s (q to quit)\n"
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
    p.add_argument("--ascii", action="store_true",
                   help="plain ASCII bars and lines (automatic when the terminal is not UTF-8; "
                        "or set LIMITLESSH_ASCII=1)")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                   help="colour output (default: auto; NO_COLOR disables)")
    out = p.add_mutually_exclusive_group()
    out.add_argument("--live", action="store_true", help="live view of current sessions, auto-refreshing")
    out.add_argument("--json", action="store_true", help="print the report as JSON")
    out.add_argument("--csv", metavar="FILE", help="export enriched raw records as CSV ('-' for stdout)")
    out.add_argument("--jsonl", metavar="FILE", help="export enriched raw records as JSON lines ('-' for stdout)")
    out.add_argument("--ip", metavar="ADDRESS", help="show details and history for one IP")
    out.add_argument("--lookup", nargs="+", metavar="ADDRESS", help="geolocate addresses and exit")
    out.add_argument("--update-geo", action="store_true", help="download or refresh DB-IP Lite databases")
    p.add_argument("--interval", type=float, default=2.0, help="refresh interval for --live in seconds (default: 2)")
    p.add_argument("--once", action="store_true", help="with --live: print one frame and exit")
    p.add_argument("--limit", type=int, default=50, help="events shown with --ip (default: 50)")
    p.add_argument("--no-geo", action="store_true", help="skip geolocation")
    p.add_argument("--geo-edition", choices=("city", "country"), default="city",
                   help="DB-IP edition for --update-geo: city (~250 MB) or country (~10 MB) (default: city)")
    p.add_argument("--log", default=DEFAULT_LOG, help="connection log (default: %s)" % DEFAULT_LOG)
    p.add_argument("--stats", default=DEFAULT_STATS, help="stats file (default: %s)" % DEFAULT_STATS)
    p.add_argument("--live-file", default=DEFAULT_LIVE, help="live snapshot file (default: %s)" % DEFAULT_LIVE)
    p.add_argument("--geo-dir", default=DEFAULT_GEO_DIR, help="geolocation databases (default: %s)" % DEFAULT_GEO_DIR)
    p.add_argument("-q", "--quiet", action="store_true", help="less output from --update-geo")
    p.add_argument("-V", "--version", action="version", version="%s %s" % (PROG, VERSION))
    args = p.parse_args(argv)
    if not 1 <= args.top <= 1000:
        p.error("--top must be between 1 and 1000")
    if not 1 <= args.limit <= 100000:
        p.error("--limit must be between 1 and 100000")
    if not 0.5 <= args.interval <= 3600:
        p.error("--interval must be between 0.5 and 3600 seconds")
    return args


def open_output(path):
    """Open an export file. Refuse symlinks and non-regular files, so running as
    root in a shared directory can't be turned into overwriting another file."""
    if path == "-":
        return sys.stdout, False
    flags = (os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as e:
        raise ReportError("cannot write %s: %s (symlinks are refused)" % (path, e.strerror or e))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise ReportError("refusing to write %s: not a plain file" % path)
    os.ftruncate(fd, 0)
    return os.fdopen(fd, "w", encoding="utf-8", newline=""), True


def main(argv=None):
    global S, G
    args = parse_args(sys.argv[1:] if argv is None else argv)
    S = Style(color_mode(args.color))
    G = dict(GLYPHS_ASCII if use_ascii(args.ascii) else GLYPHS_UNICODE)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # never crash on a terminal's encoding
        except (AttributeError, ValueError):
            pass
    try:
        if args.update_geo:
            update_geo(args.geo_dir, args.geo_edition, quiet=args.quiet)
            return 0

        geo = NoGeo() if args.no_geo else Geo(args.geo_dir)
        local = not args.utc

        if args.live:
            if not sys.stdout.isatty():
                args.once = True
            live_loop(args.live_file, geo, local, args.interval, args.once)
            return 0

        if args.lookup:
            rows = []
            for a in args.lookup:
                try:
                    ip = str(ipaddress.ip_address(a.strip()))
                except ValueError:
                    raise ReportError("not an IP address: %r" % a)
                g = geo.lookup(ip)
                place = clean(", ".join(p for p in (g["city"], g["region"], g["country"]) if p) or "-", 48)
                rows.append([ip_text(ip), S(place, "cyan"), asn_label(g, 44)])
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
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
