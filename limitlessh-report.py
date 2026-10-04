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
