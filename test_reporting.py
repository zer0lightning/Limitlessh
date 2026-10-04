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


if __name__ == "__main__":
    unittest.main(verbosity=2)
