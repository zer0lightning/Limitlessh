#!/usr/bin/env python3
"""Tests for connection logging, stats and limitlessh-report.

Run: python3 test_reporting.py

Geolocation tests use MaxMind's public test databases. Fetch them with:
    git clone --depth 1 https://github.com/maxmind/MaxMind-DB.git tests/MaxMind-DB
or point MAXMIND_TEST_DATA at an existing MaxMind-DB/test-data directory.
They are skipped if the data isn't found.
"""

import asyncio
import datetime
import functools
import gzip
import http.server
import importlib.util
import io
import ipaddress
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
DAEMON = os.path.join(HERE, "limitlessh.py")
REPORT = os.path.join(HERE, "limitlessh-report.py")
sys.path.insert(0, HERE)
import limitlessh  # noqa: E402

_spec = importlib.util.spec_from_file_location("limitlessh_report", REPORT)
rep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rep)

TEST_DATA = os.environ.get("MAXMIND_TEST_DATA") or next(
    (p for p in (os.path.join(HERE, "tests", "MaxMind-DB", "test-data"),
                 "/tmp/claude-0/MaxMind-DB/test-data") if os.path.isdir(p)), None)
needs_data = unittest.skipUnless(TEST_DATA, "MaxMind test data not found (see module docstring)")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def ts(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def line(t, ip, dur, result, sent=None):
    return json.dumps({"ts": ts(t), "ip": ip, "dur": dur,
                       "bytes": int(dur * 2) if sent is None else sent, "result": result}) + "\n"


def cfg(**overrides):
    c = limitlessh.Config({})
    for k, v in overrides.items():
        setattr(c, k, v)
    return c


# ---------------------------------------------------------------------------
# Daemon: connection log and stats file
# ---------------------------------------------------------------------------

class EventLogTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "connections.log")
        self.loop = asyncio.new_event_loop()

    def tearDown(self):
        self.loop.close()

    def make(self, **kw):
        c = cfg(log_file=self.path, **kw)
        ev = limitlessh.EventLog(c, self.loop)
        ev.configure(c)
        return ev

    def lines(self, path=None):
        with open(path or self.path) as f:
            return [json.loads(x) for x in f]

    def test_rate_cap_counts_suppressed(self):
        ev = self.make(log_rate=100)
        now = int(time.time())
        while int(time.time()) != now:  # start at a second boundary-ish
            now = int(time.time())
        for i in range(500):
            ev.record({"ts": "x", "ip": "192.0.2.1", "n": i})
        written_now = 100
        time.sleep(1.05)
        ev.flush()
        ev.shutdown()
        recs = self.lines()
        normal = [r for r in recs if "n" in r]
        suppressed = sum(r.get("suppressed", 0) for r in recs)
        # Writes may straddle a second boundary, so allow up to two windows
        self.assertGreaterEqual(len(normal), written_now)
        self.assertLessEqual(len(normal), 2 * written_now)
        self.assertEqual(len(normal) + suppressed, 500)
        self.assertEqual(ev.total_suppressed, suppressed)

    def test_rotation_compression_and_pruning(self):
        ev = self.make(log_max_size=0.01, log_max_files=3, log_rate=10 ** 6)  # ~10 KiB per file
        for i in range(2000):
            ev.record({"ts": ts(time.time()), "ip": "192.0.2.%d" % (i % 250), "dur": 1.0,
                       "bytes": 1, "result": "closed", "pad": "x" * 40})
            if i % 300 == 0:
                time.sleep(1.01)  # distinct rotation timestamps
        ev.shutdown()
        rotated = sorted(f for f in os.listdir(self.dir) if f.startswith("connections-"))
        self.assertTrue(rotated, "expected rotated files")
        self.assertTrue(all(f.endswith(".log.gz") for f in rotated), rotated)
        self.assertLessEqual(len(rotated), 3, rotated)
        with gzip.open(os.path.join(self.dir, rotated[-1]), "rt") as f:
            self.assertTrue(json.loads(f.readline())["ip"].startswith("192.0.2."))
        self.assertLess(os.path.getsize(self.path), 64 * 1024)

    def test_retention_days(self):
        old = os.path.join(self.dir, "connections-20200101T000000Z.log.gz")
        with gzip.open(old, "wt") as f:
            f.write("{}\n")
        os.utime(old, (time.time() - 100 * 86400,) * 2)
        recent = os.path.join(self.dir, "connections-20990101T000000Z.log.gz")
        with gzip.open(recent, "wt") as f:
            f.write("{}\n")
        ev = self.make(log_retention_days=90)
        ev.shutdown()  # waits for housekeeping started by configure()
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(recent))

    def test_unwritable_log_does_not_crash(self):
        bad = cfg(log_file="/proc/limitlessh-cannot-write/connections.log")
        ev = limitlessh.EventLog(bad, self.loop)
        ev.configure(bad)
        for i in range(10):
            ev.record({"ts": "x", "ip": "192.0.2.1"})
        ev.flush()
        ev.shutdown()


class DaemonLoggingTests(unittest.TestCase):
    def run_daemon(self, d, *extra):
        port = free_port()
        p = subprocess.Popen([sys.executable, DAEMON, "--bind", "127.0.0.1", "--port", str(port),
                              "--delay", "0.2", "--per-ip", "2",
                              "--log-file", os.path.join(d, "connections.log"),
                              "--stats-file", os.path.join(d, "stats.json")] + list(extra),
                             stderr=subprocess.DEVNULL)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        return p, port

    def test_log_records_and_lifetime_stats_survive_restart(self):
        d = tempfile.mkdtemp()
        for run in range(2):
            p, port = self.run_daemon(d)
            socks = [socket.create_connection(("127.0.0.1", port)) for _ in range(3)]  # 3rd rejected
            time.sleep(0.8)
            for s in socks:
                s.close()
            time.sleep(0.5)
            p.send_signal(signal.SIGTERM)
            self.assertEqual(p.wait(10), 0)
        recs = [json.loads(x) for x in open(os.path.join(d, "connections.log"))]
        results = [r.get("result") for r in recs if "result" in r]
        self.assertIn("closed", results)
        self.assertIn("rejected-ip", results)
        self.assertEqual(sum(1 for r in recs if r.get("event") == "start"), 2)
        for r in recs:
            if "result" in r:
                self.assertEqual(set(r), {"ts", "ip", "dur", "bytes", "result"})
        stats = json.load(open(os.path.join(d, "stats.json")))
        life = stats["lifetime"]["counters"]
        # 1 health-check connection + 2 trapped per run, 1 rejected per run
        self.assertGreaterEqual(life["accepted"], 4)
        self.assertGreaterEqual(life["rejected_ip"], 2)
        self.assertLess(stats["lifetime"]["since_ts"], stats["started_ts"])

    def test_tampered_stats_file_is_ignored(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "stats.json"), "w") as f:
            json.dump({"lifetime": {"counters": {"accepted": -5, "wasted": "lots", "sent": 1e300,
                                                 "closed": True, "stalled": 7},
                                    "since_ts": 9e18, "peak_active": "x"}}, f)
        p, port = self.run_daemon(d)
        p.send_signal(signal.SIGTERM)
        p.wait(10)
        life = json.load(open(os.path.join(d, "stats.json")))["lifetime"]
        self.assertEqual(life["counters"]["stalled"], 7)       # valid value kept
        self.assertLess(life["counters"]["accepted"], 10)      # negative dropped
        self.assertEqual(life["counters"]["sent"], 0)          # absurd value dropped
        self.assertLess(life["since_ts"], time.time() + 1)     # future timestamp dropped

    def test_garbage_stats_file_is_ignored(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "stats.json"), "w") as f:
            f.write("{not json")
        p, port = self.run_daemon(d)
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)


# ---------------------------------------------------------------------------
# limitlessh-report: MMDB reader
# ---------------------------------------------------------------------------

@needs_data
class MMDBTests(unittest.TestCase):
    def test_matches_reference_values(self):
        with rep.MMDB(os.path.join(TEST_DATA, "MaxMind-DB-test-decoder.mmdb")) as db:
            rec = db.lookup(ipaddress.ip_address("1.1.1.1"))
        self.assertEqual(rec["utf8_string"], "unicode! ☯ - ♫")
        self.assertEqual(rec["uint128"], 1 << 120)
        self.assertEqual(rec["int32"], -268435456)
        self.assertEqual(rec["array"], [1, 2, 3])
        self.assertAlmostEqual(rec["double"], 42.123456)
        self.assertEqual(rec["map"]["mapX"]["arrayX"], [7, 8, 9])
        self.assertIs(rec["boolean"], True)

    def test_record_sizes_and_ipv4_in_ipv6(self):
        for bits in (24, 28, 32):
            for v in (4, 6):
                with rep.MMDB(os.path.join(TEST_DATA, "MaxMind-DB-test-ipv%d-%d.mmdb" % (v, bits))) as db:
                    addr = "1.1.1.1" if v == 4 else "::1:ffff:ffff"
                    self.assertEqual(db.lookup(ipaddress.ip_address(addr)), {"ip": addr})
        with rep.MMDB(os.path.join(TEST_DATA, "MaxMind-DB-test-mixed-24.mmdb")) as db:
            self.assertEqual(db.lookup(ipaddress.ip_address("1.1.1.1")), {"ip": "::1.1.1.1"})

    def test_hostile_files_fail_cleanly(self):
        hostile = ["MaxMind-DB-test-payload-amplification-dos.mmdb",
                   "MaxMind-DB-test-payload-amplification-dos-string.mmdb",
                   "MaxMind-DB-test-payload-amplification-dos-worst-case.mmdb",
                   "MaxMind-DB-test-pointer-decoder-dos.mmdb",
                   "MaxMind-DB-test-decoder-value-limit-over.mmdb",
                   "MaxMind-DB-test-decoder-payload-limit-over.mmdb",
                   "MaxMind-DB-test-metadata-payload-limit.mmdb",
                   "GeoIP2-City-Test-Invalid-Node-Count.mmdb"]
        for name in hostile:
            path = os.path.join(TEST_DATA, name)
            if not os.path.exists(path):
                continue
            t0 = time.time()
            with self.assertRaises(rep.MMDBError, msg=name):
                with rep.MMDB(path) as db:
                    for i in range(256):
                        db.lookup(ipaddress.ip_address((i * 2654435761) % 2 ** 32))
                    db.lookup(ipaddress.ip_address("::"))
            self.assertLess(time.time() - t0, 10, name)

    def test_not_an_mmdb(self):
        with tempfile.NamedTemporaryFile(suffix=".mmdb") as f:
            f.write(os.urandom(4096))
            f.flush()
            with self.assertRaises(rep.MMDBError):
                rep.MMDB(f.name)

    def test_against_reference_library_if_installed(self):
        try:
            import maxminddb
        except ImportError:
            self.skipTest("maxminddb not installed")
        for name in ("GeoLite2-City-Test.mmdb", "GeoLite2-ASN-Test.mmdb", "GeoIP2-ISP-Test.mmdb"):
            path = os.path.join(TEST_DATA, name)
            ref = maxminddb.open_database(path)
            with rep.MMDB(path) as mine:
                for net, rec in ref:
                    self.assertEqual(mine.lookup(net.network_address), rec, "%s %s" % (name, net))


@needs_data
class GeoTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.symlink(os.path.join(TEST_DATA, "GeoLite2-City-Test.mmdb"), os.path.join(self.dir, "GeoLite2-City.mmdb"))
        os.symlink(os.path.join(TEST_DATA, "GeoLite2-ASN-Test.mmdb"), os.path.join(self.dir, "GeoLite2-ASN.mmdb"))
        self.geo = rep.Geo(self.dir)

    def test_city_and_asn(self):
        g = self.geo.lookup("81.2.69.160")
        self.assertEqual((g["country_code"], g["city"], g["region"]), ("GB", "London", "England"))
        self.assertIsInstance(g["latitude"], float)
        g = self.geo.lookup("1.128.0.0")
        self.assertEqual((g["asn"], g["org"]), (1221, "Telstra Pty Ltd"))

    def test_private_and_garbage(self):
        self.assertEqual(self.geo.lookup("10.0.0.1")["country"], "(private/reserved)")
        self.assertEqual(self.geo.lookup("not-an-ip"), rep.Geo.EMPTY)

    def test_dbip_preferred_order_and_fallback(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "GeoLite2-City.mmdb"), "wb") as f:
            f.write(b"corrupt" * 100)
        os.symlink(os.path.join(TEST_DATA, "GeoLite2-Country-Test.mmdb"), os.path.join(d, "dbip-country-lite.mmdb"))
        with redirect_stdout(io.StringIO()):
            geo = rep.Geo(d, warn=False)
        self.assertTrue(geo.loc_path.endswith("dbip-country-lite.mmdb"))
        self.assertTrue(geo.uses_dbip())


# ---------------------------------------------------------------------------
# limitlessh-report: reading logs and reporting
# ---------------------------------------------------------------------------

class ReportTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "connections.log")
        now = time.time()
        self.now = now
        rotated = os.path.join(self.dir, "connections-%s.log.gz"
                               % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now - 20 * 86400)))
        with gzip.open(rotated, "wt") as f:
            f.write(line(now - 25 * 86400, "198.51.100.7", 100, "closed"))
        with open(self.log, "w") as f:
            f.write('{"ts":"%s","event":"start","version":"1.1.0"}\n' % ts(now - 3 * 86400))
            f.write(line(now - 2 * 86400, "198.51.100.7", 3600, "closed"))
            f.write(line(now - 2 * 86400 + 60, "198.51.100.7", 0, "rejected-ip"))
            f.write(line(now - 86400, "203.0.113.9", 7200.5, "evicted"))
            f.write(line(now - 3600, "2001:db8::1", 30, "stalled"))
            f.write('{"ts":"%s","suppressed":12}\n' % ts(now - 3600))
            f.write("this is not json\n")
            f.write("x" * 50000 + "\n")
            f.write(line(now - 60, "999.1.1.1", 5, "closed"))                      # invalid ip
            f.write(line(now - 60, "192.0.2.1", 5, "pwned"))                       # unknown result
            f.write(json.dumps({"ts": ts(now - 60), "ip": "192.0.2.1", "dur": -5, "bytes": 1,
                                "result": "closed"}) + "\n")                       # negative duration
            f.write("[1,2,3]\n")

    def report(self, since="7d"):
        stats = rep.LogStats()
        r = rep.Report(rep.NoGeo(), top=5)
        s = rep.parse_when(since, time.time())
        for rec in rep.read_records(self.log, s, time.time(), stats):
            r.add(rec)
        return r, stats, s

    def test_counts_and_validation(self):
        r, stats, since = self.report("7d")
        self.assertEqual(r.trapped, 3)
        self.assertEqual(r.rejected, 1)
        self.assertEqual(len(r.ips), 3)
        self.assertAlmostEqual(r.wasted, 3600 + 7200.5 + 30)
        self.assertEqual(stats.suppressed, 12)
        self.assertEqual(stats.starts, 1)
        self.assertEqual(stats.invalid, 6)
        self.assertEqual(r.longest[0]["ip"], "203.0.113.9")
        self.assertEqual(rep.new_ip_count(self.log, r, since), 2)  # 198.51.100.7 seen 25 days ago

    def test_since_all_reads_rotated(self):
        r, _, _ = self.report("all")
        self.assertEqual(r.trapped, 4)

    def test_rotated_files_skipped_by_name_when_too_old(self):
        stats = rep.LogStats()
        list(rep.read_records(self.log, self.now - 86400, self.now, stats))
        self.assertEqual(stats.files, 1)

    def run_cli(self, *args):
        p = subprocess.run([sys.executable, REPORT, "--log", self.log, "--stats", "/nonexistent",
                            "--geo-dir", "/nonexistent"] + list(args), capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr

    def test_cli_text_json_ip_csv(self):
        rc, out, err = self.run_cli()
        self.assertEqual(rc, 0, err)
        self.assertIn("Connections trapped", out)
        self.assertIn("203.0.113.9", out)
        rc, out, _ = self.run_cli("--json")
        data = json.loads(out)
        self.assertEqual(data["overview"]["trapped"], 3)
        self.assertEqual(data["results"]["evicted"], 1)
        rc, out, _ = self.run_cli("--ip", "198.51.100.7", "--since", "all")
        self.assertIn("Trapped    2 connections", out)
        self.assertIn("Rejected   1", out)
        csv_path = os.path.join(self.dir, "out.csv")
        rc, _, err = self.run_cli("--csv", csv_path, "--since", "all")
        self.assertEqual(rc, 0, err)
        rows = open(csv_path).read().splitlines()
        self.assertEqual(len(rows), 6)  # header + 5 records
        self.assertEqual(oct(os.stat(csv_path).st_mode & 0o777), "0o600")

    def test_cli_errors(self):
        self.assertEqual(self.run_cli("--since", "banana")[0], 1)
        self.assertEqual(self.run_cli("--ip", "nope")[0], 1)
        p = subprocess.run([sys.executable, REPORT, "--log", "/nonexistent.log"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn("no connection log", p.stderr)

    def test_output_sanitising(self):
        self.assertEqual(rep.clean("A\x1b[2J\x1b]0;t\x07B‮C"), "A[2J]0;tBC")
        self.assertEqual(rep.csv_cell('=HYPERLINK("x")'), '\'=HYPERLINK("x")')
        self.assertEqual(rep.csv_cell("@cmd"), "'@cmd")
        self.assertEqual(rep.csv_cell("-12.5"), "-12.5")
        self.assertEqual(rep.csv_cell("+1 Org"), "'+1 Org")


# ---------------------------------------------------------------------------
# limitlessh-report: geo database updater
# ---------------------------------------------------------------------------

@needs_data
class UpdaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv_dir = tempfile.mkdtemp()
        month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
        for edition, src in (("city", "GeoLite2-City-Test.mmdb"), ("asn", "GeoLite2-ASN-Test.mmdb"),
                             ("country", "GeoLite2-ASN-Test.mmdb")):  # wrong type on purpose
            with open(os.path.join(TEST_DATA, src), "rb") as f, \
                    gzip.open(os.path.join(cls.srv_dir, "dbip-%s-lite-%s.mmdb.gz" % (edition, month)), "wb") as g:
                g.write(f.read())
        with gzip.open(os.path.join(cls.srv_dir, "bomb.gz"), "wb") as g:
            g.write(b"\0" * 3000000)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=cls.srv_dir)
        handler.log_message = lambda *a: None
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.geo_dir = tempfile.mkdtemp()
        self.saved = (rep.DBIP_URL, rep.VERIFY_PROBES, rep.MAX_DATABASE_BYTES)
        rep.VERIFY_PROBES = ("81.2.69.160", "1.128.0.0")
        rep.DBIP_URL = "http://127.0.0.1:%d/dbip-{edition}-lite-{month}.mmdb.gz" % self.port

    def tearDown(self):
        rep.DBIP_URL, rep.VERIFY_PROBES, rep.MAX_DATABASE_BYTES = self.saved

    def files(self):
        return sorted(os.listdir(self.geo_dir))

    def test_installs_and_records_source(self):
        rep.update_geo(self.geo_dir, "city", quiet=True)
        self.assertEqual(self.files(), ["dbip-asn-lite.mmdb", "dbip-city-lite.mmdb", "source.json"])
        self.assertEqual(rep.Geo(self.geo_dir).lookup("81.2.69.160")["city"], "London")
        info = json.load(open(os.path.join(self.geo_dir, "source.json")))
        self.assertEqual(len(info["databases"]["city"]["sha256_gz"]), 64)

    def test_wrong_type_refused_and_existing_kept(self):
        rep.update_geo(self.geo_dir, "city", quiet=True)
        before = self.files()
        with self.assertRaises(rep.ReportError) as cm:
            rep.update_geo(self.geo_dir, "country", quiet=True)
        self.assertIn("expected country", str(cm.exception))
        self.assertEqual(self.files(), before)

    def test_decompression_bomb_refused(self):
        rep.DBIP_URL = "http://127.0.0.1:%d/bomb.gz?{edition}{month}" % self.port
        rep.MAX_DATABASE_BYTES = 1000000
        with self.assertRaises(rep.ReportError) as cm:
            rep.update_geo(self.geo_dir, "city", quiet=True)
        self.assertIn("exceeds", str(cm.exception))
        self.assertEqual(self.files(), [])  # no temp files left behind

    def test_missing_months(self):
        rep.DBIP_URL = "http://127.0.0.1:%d/nope-{edition}-{month}.gz" % self.port
        with self.assertRaises(rep.ReportError) as cm:
            rep.update_geo(self.geo_dir, "city", quiet=True)
        self.assertEqual(str(cm.exception).count("HTTP 404"), 2)


# ---------------------------------------------------------------------------
# Live view
# ---------------------------------------------------------------------------

class LiveSnapshotTests(unittest.TestCase):
    def test_written_only_while_requested_and_capped(self):
        d = tempfile.mkdtemp()
        live = os.path.join(d, "live.json")
        port = free_port()
        p = subprocess.Popen([sys.executable, DAEMON, "--bind", "127.0.0.1", "--port", str(port), "--delay", "0.3",
                              "--per-ip", "100", "--live-file", live, "--live-max", "10"], stderr=subprocess.DEVNULL)
        try:
            time.sleep(1)
            socks = [socket.create_connection(("127.0.0.1", port)) for _ in range(15)]
            time.sleep(1.5)
            self.assertFalse(os.path.exists(live), "no snapshot without a request")
            rep.touch_request(live + ".request")
            time.sleep(1.5)
            snap = rep.parse_live(rep.read_json_file(live, 1 << 20))
            self.assertEqual(snap["active"], 15)
            self.assertEqual(len(snap["sessions"]), 10)
            self.assertEqual(snap["sessions_truncated"], 5)
            self.assertEqual(snap["accepts_per_min"], 15)
            starts = [s["start_ts"] for s in snap["sessions"]]
            self.assertEqual(starts, sorted(starts), "oldest first")
            # A stale request stops further writes
            old = time.time() - 60
            os.utime(live + ".request", (old, old))
            time.sleep(1.2)
            mtime = os.path.getmtime(live)
            time.sleep(2.2)
            self.assertEqual(os.path.getmtime(live), mtime)
            for s in socks:
                s.close()
        finally:
            p.send_signal(signal.SIGTERM)
            p.wait(10)


class LiveSafetyTests(unittest.TestCase):
    """The report runs as root against a directory owned by the service user."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_touch_creates_plain_file(self):
        path = os.path.join(self.dir, "live.json.request")
        rep.touch_request(path)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

    def test_touch_refuses_symlink(self):
        victim = os.path.join(self.dir, "victim")
        link = os.path.join(self.dir, "live.json.request")
        os.symlink(victim, link)
        with self.assertRaises(rep.ReportError):
            rep.touch_request(link)
        self.assertFalse(os.path.exists(victim), "must not create the symlink target")

    def test_touch_refuses_fifo_and_hardlink(self):
        fifo = os.path.join(self.dir, "fifo.request")
        os.mkfifo(fifo)
        t0 = time.time()
        with self.assertRaises(rep.ReportError):
            rep.touch_request(fifo)
        self.assertLess(time.time() - t0, 2, "must not block on a FIFO")
        target = os.path.join(self.dir, "precious")
        open(target, "w").close()
        old = time.time() - 1000
        os.utime(target, (old, old))
        link = os.path.join(self.dir, "hard.request")
        os.link(target, link)
        with self.assertRaises(rep.ReportError):
            rep.touch_request(link)
        self.assertAlmostEqual(os.path.getmtime(target), old, delta=1)

    def test_read_refuses_symlink_and_oversize(self):
        real = os.path.join(self.dir, "real.json")
        with open(real, "w") as f:
            json.dump({"a": 1}, f)
        link = os.path.join(self.dir, "link.json")
        os.symlink(real, link)
        self.assertEqual(rep.read_json_file(real, 1000), {"a": 1})
        self.assertIsNone(rep.read_json_file(link, 1000))
        self.assertIsNone(rep.read_json_file(real, 3))
        self.assertIsNone(rep.read_json_file(os.path.join(self.dir, "missing"), 1000))

    def test_log_symlinks_ignored(self):
        log = os.path.join(self.dir, "connections.log")
        secret = os.path.join(self.dir, "secret")
        open(secret, "w").write("root:x:0:0\n")
        os.symlink(secret, log)
        os.symlink(secret, os.path.join(self.dir, "connections-20260101T000000Z.log"))
        self.assertEqual(rep.log_files(log), [])

    def test_parse_live_drops_bad_entries(self):
        raw = {"updated_ts": time.time(), "active": "lots", "max_clients": 10,
               "sessions": [{"ip": "203.0.113.5", "start_ts": time.time() - 60, "bytes": 5},
                            {"ip": "\x1b[2Jevil", "start_ts": time.time() - 60, "bytes": 5}, "junk"],
               "recent": [{"ts": time.time(), "ip": "203.0.113.5", "result": "pwned"},
                          {"ts": time.time(), "ip": "203.0.113.5", "result": "closed", "dur": 3}],
               "top_active_ips": [["203.0.113.5", 2], ["bad", 1], "junk"]}
        snap = rep.parse_live(raw)
        self.assertEqual(snap["active"], 0)
        self.assertEqual([s["ip"] for s in snap["sessions"]], ["203.0.113.5"])
        self.assertEqual(len(snap["recent"]), 1)
        self.assertEqual(snap["top"], [("203.0.113.5", 2)])
        self.assertIsNone(rep.parse_live(None))


class OutputTests(unittest.TestCase):
    def tearDown(self):
        rep.S = rep.Style(False)

    def test_colour_does_not_break_widths(self):
        rep.S = rep.Style(True)
        now = time.time()
        snap = rep.parse_live({
            "updated_ts": now, "started_ts": now - 100, "active": 3, "max_clients": 10, "networks": 2,
            "sessions": [{"ip": "203.0.113.%d" % i, "start_ts": now - i * 1000, "bytes": i} for i in range(1, 40)],
            "recent": [{"ts": now, "ip": "198.51.100.1", "result": r, "dur": 5} for r in rep.RESULTS],
            "top_active_ips": [["203.0.113.1", 3]]})
        for width, height in ((80, 24), (140, 50), (200, 60)):
            screen = rep.render_live(snap, rep.NoGeo(), True, width, height, 2)
            lines = screen.split("\n")
            self.assertLessEqual(len(lines), height)
            self.assertLessEqual(max(rep.vlen(x) for x in lines), width)
            self.assertNotIn("\x1b", rep._ANSI.sub("", screen))

    def test_clip_and_table(self):
        rep.S = rep.Style(True)
        s = rep.S("abcdef", "red") + "ghij"
        self.assertEqual(rep.vlen(rep.clip(s, 4)), 4)
        self.assertEqual(rep._ANSI.sub("", rep.clip(s, 8)), "abcdefgh")
        t = rep.table(["A", "B"], [[rep.S("x", "red"), "yy"], ["zzz", rep.S("w", "green")]], "lr")
        widths = {rep.vlen(x.rstrip()) for x in t.split("\n")[2:]}
        self.assertEqual(len(widths), 1, t)

    def test_colour_mode(self):
        old = os.environ.get("NO_COLOR")
        try:
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(rep.color_mode("auto"))
            self.assertTrue(rep.color_mode("always"))
            del os.environ["NO_COLOR"]
            self.assertFalse(rep.color_mode("never"))
        finally:
            if old is not None:
                os.environ["NO_COLOR"] = old

    def test_piped_output_has_no_escapes(self):
        p = subprocess.run([sys.executable, REPORT, "--lookup", "203.0.113.1", "--geo-dir", "/nonexistent"],
                           capture_output=True, text=True)
        self.assertNotIn("\x1b", p.stdout)
        p = subprocess.run([sys.executable, REPORT, "--lookup", "203.0.113.1", "--geo-dir", "/nonexistent",
                            "--color", "always"], capture_output=True, text=True)
        self.assertIn("\x1b[", p.stdout)

    def test_interactive_live_quits_and_restores_terminal(self):
        import pty
        d = tempfile.mkdtemp()
        live = os.path.join(d, "live.json")
        with open(live, "w") as f:
            json.dump({"updated_ts": time.time(), "active": 0, "max_clients": 10}, f)
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp(sys.executable, [sys.executable, REPORT, "--live", "--interval", "0.5",
                                       "--live-file", live, "--no-geo"])
        out = b""
        deadline = time.time() + 2
        while time.time() < deadline:
            r, _, _ = __import__("select").select([fd], [], [], 0.2)
            if r:
                out += os.read(fd, 65536)
        os.write(fd, b"q")
        status = None
        deadline = time.time() + 5
        while time.time() < deadline and status is None:
            try:
                r, _, _ = __import__("select").select([fd], [], [], 0.2)
                if r:
                    out += os.read(fd, 65536)
            except OSError:
                pass
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status = os.waitstatus_to_exitcode(st)
        if status is None:
            os.kill(pid, signal.SIGKILL)
        text = out.decode("utf-8", "replace")
        self.assertEqual(status, 0)
        self.assertIn("\x1b[?1049h", text)
        self.assertIn("\x1b[?25h\x1b[?1049l", text)
        self.assertGreaterEqual(text.count("\x1b[H"), 2, "should have refreshed")


# ---------------------------------------------------------------------------
# Regression tests for the 1.2.1 audit
# ---------------------------------------------------------------------------

class Audit121Tests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_nested_json_never_crashes(self):
        deep = os.path.join(self.dir, "deep.json")
        with open(deep, "w") as f:
            f.write("[" * 200000)
        self.assertIsNone(rep.read_json_file(deep, 1 << 20))
        with open(deep, "w") as f:
            f.write('{"lifetime":' + "[" * 200000 + "}")
        counters, _, _, _ = limitlessh.load_lifetime(deep, limitlessh.Tarpit.COUNTERS)
        self.assertEqual(counters["accepted"], 0)
        log = os.path.join(self.dir, "connections.log")
        with open(log, "w") as f:
            f.write("[" * 4000 + "\n" + "{" * 4000 + "\n")
        stats = rep.LogStats()
        self.assertEqual(list(rep.read_records(log, 0, time.time(), stats)), [])
        self.assertEqual(stats.invalid, 2)

    def test_export_refuses_symlink(self):
        victim = os.path.join(self.dir, "victim")
        with open(victim, "w") as f:
            f.write("precious\n")
        out = os.path.join(self.dir, "out.csv")
        os.symlink(victim, out)
        with self.assertRaises(rep.ReportError):
            rep.open_output(out)
        self.assertEqual(open(victim).read(), "precious\n")
        fifo = os.path.join(self.dir, "fifo.csv")
        os.mkfifo(fifo)
        with self.assertRaises(rep.ReportError):
            rep.open_output(fifo)
        fh, close = rep.open_output(os.path.join(self.dir, "ok.csv"))
        fh.write("x")
        fh.close()
        existing = os.path.join(self.dir, "existing.csv")
        with open(existing, "w") as f:
            f.write("old content that is long\n")
        fh, _ = rep.open_output(existing)
        fh.write("new\n")
        fh.close()
        self.assertEqual(open(existing).read(), "new\n", "existing file must be truncated")

    def test_fifo_log_and_geo_do_not_block(self):
        log = os.path.join(self.dir, "connections.log")
        os.mkfifo(log)
        os.mkfifo(os.path.join(self.dir, "connections-20260101T000000Z.log.gz"))
        t0 = time.time()
        self.assertEqual(list(rep.read_records(log, 0, time.time(), rep.LogStats())), [])
        self.assertLess(time.time() - t0, 2)
        fifo_db = os.path.join(self.dir, "GeoLite2-ASN.mmdb")
        os.mkfifo(fifo_db)
        with self.assertRaises(rep.MMDBError):
            rep.MMDB(fifo_db)
        self.assertLess(time.time() - t0, 3)

    def test_log_swapped_for_symlink_is_not_followed(self):
        log = os.path.join(self.dir, "connections.log")
        secret = os.path.join(self.dir, "secret")
        with open(secret, "w") as f:
            f.write(line(time.time(), "203.0.113.66", 1, "closed"))
        os.symlink(secret, log)
        self.assertIsNone(rep._open_log(log))

    def test_absurd_snapshot_values(self):
        snap = rep.parse_live({"updated_ts": 1e17, "started_ts": -5, "active": 1e300, "max_clients": -3,
                               "sessions": [{"ip": "203.0.113.1", "start_ts": -1e17, "bytes": 1e300},
                                            {"ip": "203.0.113.2", "start_ts": time.time() - 5, "bytes": -1}],
                               "recent": [{"ts": 9e18, "ip": "203.0.113.1", "result": "closed", "dur": 1}],
                               "session": {"counters": {"wasted": float("inf"), "accepted": 1e300}}})
        self.assertEqual(snap["updated_ts"], 0.0)
        self.assertEqual([s["ip"] for s in snap["sessions"]], ["203.0.113.2"])
        self.assertEqual(snap["sessions"][0]["bytes"], 0)
        self.assertEqual(snap["recent"], [])
        self.assertLessEqual(snap["active"], 1e12)
        for width in (60, 120):
            rep.render_live(snap, rep.NoGeo(), True, width, 30, 2, "stale")
        self.assertEqual(rep.fmt_clock(1e17, True), "-")

    def test_report_ip_table_is_capped(self):
        saved = rep.MAX_TRACKED_IPS
        rep.MAX_TRACKED_IPS = 100
        try:
            r = rep.Report(rep.NoGeo())
            for i in range(250):
                r.add({"t": 1.8e9 + i, "ip": "2001:db8::%x" % i, "dur": 2.0, "bytes": 1, "result": "closed"})
            self.assertEqual(len(r.ips), 100)
            self.assertEqual(r.untracked, 150)
            self.assertEqual(r.trapped, 250)
            self.assertAlmostEqual(r.wasted, 500.0)
        finally:
            rep.MAX_TRACKED_IPS = saved

    def test_updater_refuses_https_to_http_redirect(self):
        handler = rep._HttpsOnlyRedirects()
        req = __import__("urllib.request").request.Request("https://download.db-ip.com/free/x.gz")
        with self.assertRaises(rep.ReportError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://evil.example/x.gz")
        ok = handler.redirect_request(req, None, 302, "Found", {}, "https://cdn.example/x.gz")
        self.assertEqual(ok.full_url, "https://cdn.example/x.gz")

    def test_suppressed_events_are_cheap(self):
        loop = asyncio.new_event_loop()
        try:
            c = cfg(log_file=os.path.join(self.dir, "flood.log"), log_rate=1)
            ev = limitlessh.EventLog(c, loop)
            ev.configure(c)
            tp = limitlessh.Tarpit(c, loop, ev)
            t0 = time.perf_counter()
            for _ in range(50000):
                tp._event(1.8e9, "203.0.113.1", 0.0, 0, "rejected-ip")
            per_event = (time.perf_counter() - t0) / 50000
            ev.shutdown()
            self.assertLess(per_event, 10e-6)
            self.assertGreaterEqual(ev.total_suppressed, 49990)
            with open(c.log_file) as f:
                self.assertLessEqual(sum(1 for x in f if '"result"' in x), 5)
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Regression tests for the 1.2.3 audit
# ---------------------------------------------------------------------------

@needs_data
@unittest.skipUnless(os.geteuid() == 0, "needs root to test privilege dropping")
class Audit123Tests(unittest.TestCase):
    """Root running --update-geo inside a directory owned by another user."""
    OTHER_UID = 65534

    @classmethod
    def setUpClass(cls):
        cls.srv_dir = tempfile.mkdtemp()
        month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
        city = open(os.path.join(TEST_DATA, "GeoLite2-City-Test.mmdb"), "rb").read()
        asn = open(os.path.join(TEST_DATA, "GeoLite2-ASN-Test.mmdb"), "rb").read()
        evil = city.replace(b"GeoLite2-City", b"\x1b]2;PWN\x07 City", 1)
        for name, data in (("city", city), ("asn", asn), ("evilcity", evil)):
            with gzip.open(os.path.join(cls.srv_dir, "dbip-%s-lite-%s.mmdb.gz" % (name, month)), "wb") as g:
                g.write(data)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=cls.srv_dir)
        handler.log_message = lambda *a: None
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        base = tempfile.mkdtemp()
        os.chmod(base, 0o755)
        self.geo = os.path.join(base, "geo")
        os.mkdir(self.geo)
        os.chown(self.geo, self.OTHER_UID, self.OTHER_UID)
        self.victim = os.path.join(base, "shadow")
        with open(self.victim, "w") as f:
            f.write("root:secret\n")
        os.chmod(self.victim, 0o600)

    def update_in_child(self, edition="city"):
        """Run update_geo in a child process (it may drop privileges); return (exit code, stdout)."""
        port = self.server.server_address[1]
        rd, wr = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(rd)
            os.dup2(wr, 1)
            rep.VERIFY_PROBES = ("81.2.69.160", "1.128.0.0")
            rep.DBIP_URL = "http://127.0.0.1:%d/dbip-{edition}-lite-{month}.mmdb.gz" % port
            try:
                rep.update_geo(self.geo, edition, quiet=False)
                code = 0
            except BaseException:
                code = 1
            sys.stdout.flush()
            os._exit(code)
        os.close(wr)
        out = b""
        while True:
            chunk = os.read(rd, 65536)
            if not chunk:
                break
            out += chunk
        os.close(rd)
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status), out.decode("utf-8", "replace")

    def test_planted_symlinks_do_not_reach_root_files(self):
        for name in (".source.json.tmp", "source.json", "dbip-city-lite.mmdb", "dbip-asn-lite.mmdb",
                     "dbip-country-lite.mmdb"):
            os.symlink(self.victim, os.path.join(self.geo, name))
        code, out = self.update_in_child()
        self.assertEqual(code, 0, out)
        self.assertIn("running as uid %d" % self.OTHER_UID, out)
        self.assertEqual(open(self.victim).read(), "root:secret\n")
        self.assertEqual(oct(os.stat(self.victim).st_mode & 0o777), "0o600")
        for name in ("dbip-city-lite.mmdb", "dbip-asn-lite.mmdb", "source.json"):
            st = os.lstat(os.path.join(self.geo, name))
            self.assertTrue(stat.S_ISREG(st.st_mode), name)
            self.assertEqual(st.st_uid, self.OTHER_UID, name)
        self.assertEqual(rep.Geo(self.geo).lookup("81.2.69.160")["city"], "London")

    def test_metadata_is_sanitised_before_printing(self):
        port = self.server.server_address[1]
        geo = tempfile.mkdtemp()
        saved = (rep.DBIP_URL, rep.VERIFY_PROBES)
        rep.VERIFY_PROBES = ("81.2.69.160", "1.128.0.0")
        month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
        os.rename(os.path.join(self.srv_dir, "dbip-evilcity-lite-%s.mmdb.gz" % month),
                  os.path.join(self.srv_dir, "evil-city-%s.gz" % month))
        try:
            rep.DBIP_URL = "http://127.0.0.1:%d/evil-{edition}-{month}.gz" % port
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    rep.update_geo(geo, "city", quiet=False)
                except rep.ReportError:
                    pass  # the ASN download is missing from this URL pattern
            self.assertIn("City", buf.getvalue())
            self.assertNotIn("\x1b", buf.getvalue())
        finally:
            rep.DBIP_URL, rep.VERIFY_PROBES = saved
            os.rename(os.path.join(self.srv_dir, "evil-city-%s.gz" % month),
                      os.path.join(self.srv_dir, "dbip-evilcity-lite-%s.mmdb.gz" % month))


class TarpitTempFileTests(unittest.TestCase):
    def test_open_new_never_follows_symlinks(self):
        d = tempfile.mkdtemp()
        victim = os.path.join(d, "victim")
        with open(victim, "w") as f:
            f.write("keep\n")
        tmp = os.path.join(d, "stats.json.tmp.1")
        os.symlink(victim, tmp)
        with limitlessh.open_new(tmp) as f:  # stale entry is removed, not followed
            f.write("new\n")
        self.assertEqual(open(victim).read(), "keep\n")
        self.assertFalse(os.path.islink(tmp))
        self.assertEqual(open(tmp).read(), "new\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
