#!/usr/bin/env python3
"""End-to-end tests for limitlessh. Run: python3 test_limitlessh.py"""

import os
import re
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DAEMON = os.path.join(HERE, "limitlessh.py")
sys.path.insert(0, HERE)
import limitlessh  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Daemon(object):
    def __init__(self, *args, activated=False, port=None):
        self.port = port or free_port()
        self.lines = []
        self.lock = threading.Lock()
        if activated:
            cmd = ["systemd-socket-activate", "-l", "127.0.0.1:%d" % self.port,
                   sys.executable, DAEMON] + list(args)
        else:
            cmd = [sys.executable, DAEMON, "--bind", "127.0.0.1", "--port", str(self.port)] + list(args)
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=self._reader, daemon=True).start()
        if not activated:
            self.wait_for("listening", 10)

    def _reader(self):
        for line in self.proc.stdout:
            with self.lock:
                self.lines.append(line.rstrip("\n"))

    def output(self):
        with self.lock:
            return "\n".join(self.lines)

    def wait_for(self, pattern, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if re.search(pattern, self.output()):
                return True
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        raise AssertionError("never saw %r in output:\n%s" % (pattern, self.output()))

    def connect(self, src="127.0.0.1"):
        s = socket.socket()
        s.bind((src, 0))
        s.connect(("127.0.0.1", self.port))
        return s

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc.stdout.close()
        return self.proc.returncode

    def rss_kib(self):
        with open("/proc/%d/status" % self.proc.pid) as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
        return 0


def closed_within(sock, timeout):
    """True if the server closes/resets the connection within timeout."""
    deadline = time.time() + timeout
    while True:
        left = deadline - time.time()
        if left <= 0:
            return False
        sock.settimeout(left)
        try:
            data = sock.recv(4096)
        except socket.timeout:
            return False
        except (ConnectionResetError, ConnectionAbortedError):
            return True
        if not data:
            return True


def read_lines(sock, count, timeout):
    buf = b""
    sock.settimeout(timeout)
    deadline = time.time() + timeout
    while buf.count(b"\r\n") < count and time.time() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


class TarpitTests(unittest.TestCase):
    def setUp(self):
        self.daemons = []
        self.socks = []

    def tearDown(self):
        for s in self.socks:
            s.close()
        for d in self.daemons:
            d.stop()

    def start(self, *args, **kw):
        d = Daemon(*args, **kw)
        self.daemons.append(d)
        return d

    def conn(self, d, src="127.0.0.1"):
        s = d.connect(src)
        self.socks.append(s)
        return s

    def test_banner_lines(self):
        d = self.start("--delay", "0.1", "--jitter", "0", "--max-line", "20")
        s = self.conn(d)
        data = read_lines(s, 15, 10)
        lines = data.split(b"\r\n")[:-1]
        self.assertGreaterEqual(len(lines), 15)
        for line in lines:
            self.assertFalse(line.startswith(b"SSH-"))
            self.assertTrue(3 <= len(line) <= 20, line)
            self.assertTrue(all(32 <= b < 127 for b in line), line)
        self.assertGreater(len(set(lines)), 10, "lines should be random")

    def test_per_ip_limit(self):
        d = self.start("--delay", "0.3", "--per-ip", "3", "--log-level", "debug")
        keep = [self.conn(d) for _ in range(3)]
        extra = self.conn(d)
        self.assertTrue(closed_within(extra, 3), "4th connection from one IP should be closed")
        for s in keep:
            self.assertFalse(closed_within(s, 0.8), "first 3 should stay open")
        d.wait_for("reject 127.0.0.1: per-ip limit")

    def test_per_net_limit(self):
        d = self.start("--delay", "0.3", "--per-ip", "2", "--per-net", "3")
        a = [self.conn(d, "127.0.0.1"), self.conn(d, "127.0.0.1")]
        b1 = self.conn(d, "127.0.0.2")
        b2 = self.conn(d, "127.0.0.2")       # same /24, 4th in network -> rejected
        other = self.conn(d, "127.0.1.1")    # different /24 -> fine
        self.assertTrue(closed_within(b2, 3))
        for s in a + [b1, other]:
            self.assertFalse(closed_within(s, 0.8))

    def test_eviction_targets_busiest_network(self):
        d = self.start("--delay", "0.3", "--max-clients", "4", "--per-ip", "100", "--per-net", "100")
        a = [self.conn(d, "127.1.0.1") for _ in range(3)]
        time.sleep(0.2)
        b = self.conn(d, "127.2.0.1")
        time.sleep(0.2)
        c = self.conn(d, "127.3.0.1")        # server full: oldest from busiest net (A) goes
        self.assertTrue(closed_within(a[0], 3), "oldest client of busiest network should be evicted")
        for s in a[1:] + [b, c]:
            self.assertFalse(closed_within(s, 0.8))

    def test_full_server_keeps_accepting(self):
        # With endlessh, a full server stops accepting. Here new clients keep
        # getting trapped and the listen queue never fills.
        d = self.start("--delay", "0.3", "--max-clients", "5", "--per-ip", "100", "--per-net", "100")
        for i in range(40):
            self.conn(d, "127.9.%d.1" % i)
        newest = self.conn(d, "127.10.0.1")
        data = read_lines(newest, 1, 5)
        self.assertIn(b"\r\n", data, "newest client should still receive banner lines")

    def test_max_lifetime(self):
        d = self.start("--delay", "0.2", "--max-lifetime", "1")
        s = self.conn(d)
        t0 = time.time()
        self.assertTrue(closed_within(s, 5))
        self.assertGreater(time.time() - t0, 0.8)

    def test_client_data_is_never_read(self):
        d = self.start("--delay", "0.5")
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)  # so "sent" ~ server-side buffering
        s.connect(("127.0.0.1", d.port))
        self.socks.append(s)
        s.setblocking(False)
        sent = 0
        chunk = b"A" * 65536
        deadline = time.time() + 3
        while time.time() < deadline:
            try:
                sent += s.send(chunk)
            except BlockingIOError:
                time.sleep(0.05)
        rss_before = d.rss_kib()
        # Everything we managed to push is only in kernel buffers; it stays small
        self.assertLess(sent, 512 * 1024, "server should not be draining client data (sent %d)" % sent)
        self.assertLess(d.rss_kib() - rss_before, 1024)

    def test_stalled_client_is_dropped(self):
        # Unit-level: the protocol drops a client as soon as writes back up.
        import asyncio

        class FakeTransport(object):
            def __init__(self):
                self.aborted = False
            def get_extra_info(self, key):
                return ("10.0.0.1", 1234) if key == "peername" else None
            def pause_reading(self):
                pass
            def set_write_buffer_limits(self, high=None):
                pass
            def abort(self):
                self.aborted = True
            def is_closing(self):
                return self.aborted

        loop = asyncio.new_event_loop()
        try:
            tp = limitlessh.Tarpit(limitlessh.Config({}), loop)
            proto = limitlessh.TarpitProtocol(tp)
            t = FakeTransport()
            proto.connection_made(t)
            self.assertEqual(len(tp.clients), 1)
            proto.pause_writing()
            self.assertTrue(t.aborted)
            self.assertEqual(len(tp.clients), 0)
            self.assertEqual(tp.totals["stalled"], 1)
            proto.connection_lost(None)        # late callback must not double count
            self.assertEqual(tp.totals["closed"], 1)
        finally:
            loop.close()

    def test_source_table_is_bounded(self):
        # Regression: rotating source addresses (easy with IPv6) must not
        # grow the per-window source table without limit.
        import asyncio

        class T(object):
            def __init__(self, ip):
                self.ip, self.aborted = ip, False
            def get_extra_info(self, key):
                return (self.ip, 1) if key == "peername" else None
            def pause_reading(self):
                pass
            def set_write_buffer_limits(self, high=None):
                pass
            def abort(self):
                self.aborted = True
            def is_closing(self):
                return self.aborted

        loop = asyncio.new_event_loop()
        try:
            tp = limitlessh.Tarpit(limitlessh.Config({"max-clients": 50, "per-net": 1}), loop)
            n = limitlessh.MAX_TRACKED_SOURCES + 5000
            for i in range(n):
                limitlessh.TarpitProtocol(tp).connection_made(T("2001:db8:%x:%x::1" % (i >> 16, i & 0xffff)))
            self.assertEqual(len(tp.window_sources), limitlessh.MAX_TRACKED_SOURCES)
            self.assertEqual(tp.window_untracked, 5000)
            self.assertLessEqual(len(tp.clients), 50)
        finally:
            loop.close()

    def test_kernel_receive_buffer_is_small(self):
        # Regression: buffers must be small from the handshake, or a client
        # can park ~32 KiB per connection in kernel memory.
        d = self.start("--delay", "5", "--per-ip", "100")
        socks = [self.conn(d) for _ in range(10)]
        time.sleep(0.3)
        for s in socks:
            s.setblocking(False)
            deadline = time.time() + 0.3
            while time.time() < deadline:
                try:
                    s.send(b"A" * 65536)
                except BlockingIOError:
                    break
        time.sleep(0.5)
        queued = []
        with open("/proc/net/tcp") as f:
            for line in f.read().splitlines()[1:]:
                fields = line.split()
                if fields[1].endswith(":%04X" % d.port) and fields[3] == "01":
                    queued.append(int(fields[4].split(":")[1], 16))
        self.assertEqual(len(queued), 10)
        self.assertLess(max(queued), 8192, "server-side receive queues: %s" % queued)

    def test_signals_summary_reload_shutdown(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write("delay = 0.2\nper-ip = 8\n")
            path = f.name
        try:
            d = self.start("--config", path)
            socks = [self.conn(d) for _ in range(5)]
            time.sleep(0.5)
            d.proc.send_signal(signal.SIGUSR1)
            d.wait_for(r"summary: active=5")
            with open(path, "w") as f:
                f.write("delay = 0.2\nper-ip = 2\n")
            d.proc.send_signal(signal.SIGHUP)
            d.wait_for(r"reloaded .* per-ip=2")
            closed = sum(closed_within(s, 1.5) for s in socks)
            self.assertEqual(closed, 3, "reload should trim clients over the new per-ip limit")
            with open(path, "w") as f:
                f.write("delay = banana\n")
            d.proc.send_signal(signal.SIGHUP)
            d.wait_for(r"reload failed, keeping current settings")
            self.assertEqual(d.stop(), 0)
            self.assertIn("SIGTERM received", d.output())
        finally:
            os.unlink(path)

    def test_periodic_summary(self):
        d = self.start("--delay", "0.2", "--summary-interval", "1", "--top", "2")
        self.conn(d)
        self.conn(d, "127.0.0.5")
        d.wait_for(r"summary: active=2 .* top: 127\.0\.0\.\d+\(1\), 127\.0\.0\.\d+\(1\)", 5)

    def test_socket_activation(self):
        port = free_port()
        d = self.start("--delay", "0.2", activated=True, port=port)
        time.sleep(0.5)
        s = self.conn(d)                     # systemd-socket-activate starts the daemon now
        data = read_lines(s, 2, 10)
        self.assertGreaterEqual(data.count(b"\r\n"), 2)
        d.wait_for("via systemd")

    def test_config_file_errors(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write("# comment\nmax_clients 100\nbogus = 1\n")
            path = f.name
        try:
            r = subprocess.run([sys.executable, DAEMON, "-f", path, "--check-config"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertIn(":3: unknown option 'bogus'", r.stderr)
            with open(path, "w") as f:
                f.write("max_clients 100\nlog-level 2\n")
            r = subprocess.run([sys.executable, DAEMON, "-f", path, "--check-config", "--delay", "3"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertRegex(r.stdout, r"max-clients\s+100")
            self.assertRegex(r.stdout, r"log-level\s+debug")
            self.assertRegex(r.stdout, r"delay\s+3.0")
        finally:
            os.unlink(path)

    def test_load_thousands_of_clients(self):
        n = 3000
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard < n + 200:
            self.skipTest("file limit too low for load test")
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, n * 2 + 500), hard))
        d = self.start("--delay", "1", "--max-clients", str(n), "--per-ip", "8",
                       "--per-net", str(n), "--summary-interval", "0")
        base = d.rss_kib()
        for i in range(n):
            # 8 clients per source IP across 127.20.x.y
            ip = "127.20.%d.%d" % (i // 8 // 250, (i // 8) % 250 + 1)
            self.conn(d, ip)
        time.sleep(3)
        alive = 0
        for s in self.socks[-n:]:
            s.settimeout(0.01)
            try:
                if s.recv(4096):
                    alive += 1
            except socket.timeout:
                alive += 1
            except OSError:
                pass
        rss = d.rss_kib()
        d.proc.send_signal(signal.SIGUSR1)
        d.wait_for(r"summary: active=%d" % n)
        print("\n    load: %d clients alive, RSS %d KiB -> %d KiB (%.1f KiB/client)"
              % (alive, base, rss, (rss - base) / float(n)), file=sys.stderr)
        self.assertEqual(alive, n)
        self.assertLess(rss - base, 64 * 1024, "should use well under 64 MiB for %d clients" % n)


if __name__ == "__main__":
    unittest.main(verbosity=2)
