# limitlessh

Hardened SSH tarpit inspired by [endlessh]. Holds scanners on port 22 with an endless random banner, while your real sshd runs elsewhere.

```
scanner ──► :22   limitlessh   random line … 10s … random line … (forever)
you     ──► :2200 sshd
```

## Comparison with endlessh

| | endlessh | limitlessh |
|---|---|---|
| Per-IP limit | none | default 8 |
| Per-network limit (/24, /64) | none | default 32 |
| When full | stops accepting | drops oldest client of the busiest network, keeps accepting |
| Client stops reading | held | dropped |
| Vanished client | held until TCP timeout (~15 min) | freed via `TCP_USER_TIMEOUT` |
| Max hold time | none | optional `max-lifetime` |
| Logging | one line per connect/disconnect | summary every 10 min; rotated, rate-capped JSON connection log |
| Reports | none | `limitlessh-report`: top IPs, countries, ASNs/ISPs, durations, daily/hourly activity, CSV/JSON export |
| Geolocation | none | country, region, city, ASN, organisation (offline, DB-IP Lite or MaxMind GeoLite2) |
| Port 22 binding | needs `CAP_NET_BIND_SERVICE` | systemd socket activation, no capabilities |
| Network access | full | none (`PrivateNetwork=yes`) |
| `systemd-analyze security` | 4.2 (hardened unit) | 0.4 |
| Language | C | Python 3, stdlib only |
| Last upstream commit | April 2021 | — |

## Behaviour

- Client data is never read: reading is paused, and `SO_RCVBUF`/`SO_SNDBUF` (1 KiB/2 KiB) are set on the listening socket so the TCP window is small from the handshake (≤1.1 KiB queued per client).
- Every connection is accepted; those over a limit are closed immediately, so the listen backlog never fills.
- Eviction picks the oldest client of the network with the most clients, in O(1).
- Banner lines: 3–`max-line` printable ASCII bytes plus CRLF, never starting with `SSH-`. Delay jittered ±30%.
- A client is dropped once 1 KiB of output is queued (it has stopped reading).
- Per-window source statistics are capped at 10,000 addresses; further sources are counted, not stored.
- Connection log: one JSON line per connection, capped at `log-rate` lines/s (extra events counted, not written), rotated at `log-max-size`, gzip-compressed on a background thread, pruned by count and age.
- Lifetime stats are saved to `stats-file` every minute and survive restarts.
- Memory: ~4 KiB per client (3,000 clients ≈ 12 MB). Measured flood cost while full: ~90 µs CPU per connection at 8,000 conn/s.

## Requirements

- Ubuntu 22.04+ (systemd ≥ 247)
- Python ≥ 3.8
- root

## Install

Keep an existing SSH session open until login on the new port is confirmed.

```bash
wget https://raw.githubusercontent.com/zer0lightning/limitlessh/main/install-limitlessh.sh
chmod +x install-limitlessh.sh
less install-limitlessh.sh              # review before running as root
./install-limitlessh.sh --print-units   # optional: show generated files, no root
sudo ./install-limitlessh.sh            # sshd -> 2200, limitlessh -> 22
```

The installer also downloads the geolocation databases (DB-IP Lite city + ASN, ~275 MB on disk) and enables a monthly update timer. Use `--geo-edition country` (~35 MB) or `--no-geo` on small disks.

Then, from a new terminal:

```bash
ssh -p 2200 user@server
journalctl -u limitlessh -f
sudo limitlessh-report          # once some connections have been logged
```

Open the new SSH port in any cloud firewall or security group; the installer only manages `ufw`.

### Installer options

| Option | Default | |
|---|---|---|
| `-p, --port PORT` | `22` | tarpit port |
| `-s, --ssh-port PORT` | `2200` | new sshd port |
| `--no-ssh-move` | | don't touch sshd; fail if it holds the tarpit port |
| `-d, --delay SEC` | `10` | seconds between lines |
| `-l, --max-line N` | `32` | max line length (3–253) |
| `-c, --max-clients N` | `4096` | global limit |
| `-i, --per-ip N` | `8` | per-IP limit |
| `-n, --per-net N` | `32` | per-/24 (IPv4) or /64 (IPv6) limit |
| `-t, --max-lifetime SEC` | `0` | drop after SEC seconds; 0 = never |
| `--summary-interval SEC` | `600` | 0 = off |
| `-v, --log-level LEVEL` | `info` | `debug`, `info`, `warning`, `error` |
| `--log-retention-days N` | `90` | delete rotated connection logs after N days; 0 = by count only |
| `--no-connection-log` | | don't record connections (no reports) |
| `--geo-edition E` | `city` | `city` (~250 MB) or `country` (~10 MB), plus ASN (~25 MB) |
| `--no-geo` | | don't download geolocation databases |
| `-y, --yes` | | no confirmation prompts |
| `--print-units` | | print config and units, exit |
| `-u, --uninstall` | | remove limitlessh; logs, stats and geo data are kept |
| `--purge` | | with `--uninstall`: also delete logs, stats and geo data |
| `-h, --help` / `-V, --version` | | |

Environment variables (`PORT`, `SSH_PORT`, `DELAY`, `MAX_LINE`, `MAX_CLIENTS`, `PER_IP`, `PER_NET`, `MAX_LIFETIME`, `SUMMARY_INTERVAL`, `LOG_LEVEL`, `LOG_RETENTION_DAYS`, `GEO_EDITION`) set defaults; flags override them.

```bash
sudo ./install-limitlessh.sh -s 4822                  # sshd -> 4822
sudo ./install-limitlessh.sh -p 2222 --no-ssh-move    # tarpit on 2222, sshd unchanged
sudo ./install-limitlessh.sh -c 10000 -i 4 -t 86400
```

Re-running upgrades in place. If endlessh holds the tarpit port, the installer offers to stop and disable it.

### Installed files

| Path | |
|---|---|
| `/usr/local/lib/limitlessh/limitlessh.py` | tarpit |
| `/usr/local/lib/limitlessh/limitlessh-report.py` | report tool, linked as `/usr/local/bin/limitlessh-report` |
| `/etc/limitlessh/limitlessh.conf` | config |
| `/etc/systemd/system/limitlessh.socket` | listening port (`ListenStream=`) |
| `/etc/systemd/system/limitlessh.service` | sandboxed tarpit service |
| `/etc/systemd/system/limitlessh-geoupdate.{service,timer}` | monthly geo database update |
| `/var/log/limitlessh/connections*.log[.gz]` | connection log (root-readable only) |
| `/var/lib/limitlessh/stats.json` | live and lifetime stats |
| `/var/lib/limitlessh-geo/*.mmdb` | geolocation databases |

## SSH port move

When sshd holds the tarpit port, the installer:

1. Backs up `/etc/ssh` to `/root/limitlessh-ssh-backup-<timestamp>/`.
2. Allows the new port in `ufw`.
3. Comments out all `Port` lines in `sshd_config` and `sshd_config.d/*.conf`, adds `Port <new>` before any `Match` block.
4. Validates with `sshd -t`.
5. If `ssh.socket` is in use (Ubuntu 22.10+), writes `/etc/systemd/system/ssh.socket.d/10-limitlessh-port.conf`.
6. Confirms sshd listens on the new port and the old port is free.

Any failure restores the backup.

## Configuration

`/etc/limitlessh/limitlessh.conf` (`key = value` or `key value`, `#` comments):

```ini
delay            = 10
max-line         = 32
max-clients      = 4096
per-ip           = 8
per-net          = 32
ipv4-prefix      = 24
ipv6-prefix      = 64
max-lifetime     = 0
summary-interval = 600
log-level        = info

log-file           = /var/log/limitlessh/connections.log   # omit to disable
log-max-size       = 20       # MiB per file before rotation
log-max-files      = 50       # rotated .gz files kept
log-retention-days = 90       # 0 = keep by count only
log-rate           = 200      # max log lines per second
stats-file         = /var/lib/limitlessh/stats.json
stats-interval     = 60
```

`sudo systemctl reload limitlessh` applies changes without dropping clients. Invalid values are rejected and the current settings kept. Lowered limits trim existing clients.

Port changes: re-run the installer with `-p`, or edit `ListenStream=` in the socket unit, then:

```bash
sudo systemctl daemon-reload && sudo systemctl restart limitlessh.socket limitlessh
```

The installer sets `LimitNOFILE=` (max-clients + 256) and `MemoryMax=` (max-clients × 16 KiB + 64 MiB, min 128 MiB). If `max-clients` is raised by hand, raise these too; otherwise limitlessh lowers `max-clients` to fit and logs a warning.

## Operation

| | |
|---|---|
| Logs | `journalctl -u limitlessh -f` |
| Stats now | `sudo systemctl kill -s USR1 limitlessh` |
| Reload | `sudo systemctl reload limitlessh` |
| Status | `systemctl status limitlessh.socket limitlessh` |

Summary line:

```
summary: active=1873 networks=1204 peak=1902 | last 10m: new=412 closed=389
rejected=57 (per-ip 51, per-net 6) evicted=0 stalled=3 expired=0 |
total: accepted=91204 attacker-time=38d4h sent=2.1MiB | top: 203.0.113.7(31), …
```

`attacker-time` is the cumulative time clients spent connected.

## Reports

```bash
sudo limitlessh-report                         # last 7 days
sudo limitlessh-report --since 24h --top 20
sudo limitlessh-report --since 2026-09-01 --until 2026-10-01
sudo limitlessh-report --ip 203.0.113.7        # history and location of one IP
sudo limitlessh-report --lookup 1.2.3.4 5.6.7.8
sudo limitlessh-report --since 30d --csv connections.csv   # raw records + geolocation
sudo limitlessh-report --since all --jsonl -               # same, JSON lines
sudo limitlessh-report --json > report.json                # full report as JSON
```

Report sections: live status and lifetime totals; overview (trapped, rejected, unique IPs and networks, new IPs, attacker time, average and longest hold); how connections ended; time-held distribution; top IPs by attacker time and by connections; top countries; top ASNs/ISPs; longest sessions; daily totals; hour-of-day activity. Times are local unless `--utc`.

```
TOP IPs BY ATTACKER TIME
  IP             Trapped  Rejected     Time  Location       Network
  ─────────────  ───────  ────────  ───────  ─────────────  ────────────────────────────
  203.0.113.7        117        11  25d 19h  Frankfurt, DE  AS64500 Example Hosting GmbH
  198.51.100.22      107        13  21h 43m  Singapore, SG  AS64501 Example Cloud Pte
```

CSV/JSONL columns: `time_utc, ip, result, duration_s, bytes, country_code, country, region, city, latitude, longitude, asn, org`. Export files are created with mode 0600.

### Connection log format

One JSON object per line:

```json
{"ts":"2026-10-04T07:26:01Z","ip":"203.0.113.7","dur":5321.4,"bytes":11210,"result":"closed"}
{"ts":"2026-10-04T07:26:02Z","ip":"203.0.113.7","dur":0.0,"bytes":0,"result":"rejected-ip"}
{"ts":"2026-10-04T07:26:03Z","suppressed":1840}
{"ts":"2026-10-04T07:20:00Z","event":"start","version":"1.1.0"}
```

`ts` is the connection start (UTC). `result`: `closed` (client left), `evicted`, `stalled`, `expired`, `shutdown`, `rejected-ip`, `rejected-net`. `suppressed` lines count events dropped by the rate cap.

### Geolocation

Lookups run in `limitlessh-report`, offline, against `.mmdb` files in `/var/lib/limitlessh-geo`. The tarpit itself has no network access and does no lookups.

- Default source: [DB-IP Lite](https://db-ip.com/db/lite.php) city + ASN, CC BY 4.0, downloaded by `limitlessh-geoupdate.timer` on the 5th of each month. Manual update: `sudo systemctl start limitlessh-geoupdate`.
- "ISP" is the ASN organisation name. MaxMind's paid `GeoIP2-ISP.mmdb` is used if present.
- MaxMind GeoLite2 (free account required): place `GeoLite2-City.mmdb` and/or `GeoLite2-ASN.mmdb` in the geo directory; they take precedence over DB-IP files.
- Downloads are verified before replacing existing files: HTTPS, size limits (400 MiB compressed, 1.5 GiB decompressed), database type, build date, and test lookups.
- The `.mmdb` reader is bounds-checked and enforces the MaxMind DB spec's per-lookup limits (65,536 values, 2 MiB payload), so corrupt or hostile files raise an error instead of hanging or exhausting memory.

### Privacy

IP addresses are personal data under GDPR, PIPEDA and similar laws. Logs are readable by root only and deleted after `log-retention-days` (default 90). Disable recording with `--no-connection-log` or by removing `log-file` from the config.

## Sandbox

The service runs under:

- `DynamicUser=yes`, `PrivateUsers=yes`, empty `CapabilityBoundingSet=`, `NoNewPrivileges=yes`
- `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` — the listening socket is passed in by systemd
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectProc=invisible`
- `ProtectKernelTunables/Modules/Logs=yes`, `ProtectClock=yes`, `ProtectControlGroups=yes`, `RestrictNamespaces=yes`, `MemoryDenyWriteExecute=yes`
- `SystemCallFilter=@system-service ~@privileged @resources`
- `MemoryMax=`, `TasksMax=16`, `LimitNOFILE=`, `CPUWeight=20`
- Writable paths: only `StateDirectory=limitlessh` and `LogsDirectory=limitlessh` (mode 0700)
- Socket unit: `ReceiveBuffer=1024`, `SendBuffer=2048`

The geo updater runs separately as its own `DynamicUser` with the same filesystem, kernel and syscall restrictions, network limited to `AF_INET`/`AF_INET6`, write access only to `/var/lib/limitlessh-geo`, `MemoryMax=512M`, idle I/O priority.

```bash
systemd-analyze security limitlessh.service             # 0.4
systemd-analyze security limitlessh-geoupdate.service   # 1.3
```

A tarpit does not secure sshd. Also use key-only auth (`PasswordAuthentication no`), `PermitRootLogin no`, updates, and optionally fail2ban or CrowdSec on the real port.

## Running without systemd

```bash
python3 limitlessh.py --port 2222
python3 limitlessh.py --bind 127.0.0.1 --port 2222 --log-level debug
python3 limitlessh.py --config limitlessh.conf --check-config
python3 limitlessh.py --help
```

Default bind is `::` (IPv4 and IPv6). Ports below 1024 need root or `CAP_NET_BIND_SERVICE`.

| Signal | |
|---|---|
| `SIGHUP` | reload config |
| `SIGUSR1` | log stats |
| `SIGTERM`, `SIGINT` | shut down, log final summary |

## Uninstall

```bash
sudo ./install-limitlessh.sh --uninstall
```

Removes units, programs and config, and the `ufw` rule unless the port is 22. Logs, stats and geo databases are kept unless `--purge` is given. sshd is not changed. To restore it:

```bash
sudo cp -a /root/limitlessh-ssh-backup-<timestamp>/ssh/. /etc/ssh/
sudo rm -f /etc/systemd/system/ssh.socket.d/10-limitlessh-port.conf
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket 2>/dev/null; sudo systemctl restart ssh
```

Allow port 22 in the firewall before logging out.

## Development

| File | |
|---|---|
| `limitlessh.py` | tarpit |
| `limitlessh-report.py` | reports, export, geolocation, geo updater |
| `install-limitlessh.template.sh` | installer template |
| `build.py` | embeds both programs into the template |
| `install-limitlessh.sh` | generated installer |
| `test_limitlessh.py` | tarpit tests |
| `test_reporting.py` | logging, stats, report, `.mmdb` reader and updater tests |

```bash
python3 build.py              # regenerate install-limitlessh.sh
python3 test_limitlessh.py    # Linux; uses 127.x.y.z source addresses
git clone --depth 1 https://github.com/maxmind/MaxMind-DB.git tests/MaxMind-DB
python3 test_reporting.py     # geo tests use MaxMind's test databases
```

Tests cover banner format, bounded source statistics, kernel receive buffer size, per-IP/per-network limits, eviction, accepting while full, max lifetime, unread client data, stalled clients, signals and reload, summaries, socket activation (needs `systemd-socket-activate`), config errors, and 3,000 concurrent clients. `test_reporting.py` covers log rate cap, rotation, compression, retention, unwritable logs, stats persistence and tampered stats files, `.mmdb` decoding against MaxMind's reference reader, hostile `.mmdb` files (payload amplification, pointer loops, over-limit records), report counts and input validation, output sanitising, and updater refusal of wrong-type databases, decompression bombs and missing files.

## Limitations

- The installer targets Ubuntu with systemd.
- Lines before the SSH version string are allowed by RFC 4253 but uncommon, so the tarpit is detectable.
- Scanners with short connect timeouts disconnect quickly.
- Per-network limits group a /24 or /64; tune `per-net`, `ipv4-prefix` and `ipv6-prefix` for large NATs.
- Geolocation accuracy is limited, especially at city level; ASN organisation names are not always the retail ISP.
- Under sustained floods the log rate cap drops per-connection detail (counts stay exact in stats); count-based pruning can then shorten history before `log-retention-days`.
- An attacker controlling many /64s (e.g. a /48) can fill all slots and cause continuous eviction. Impact is limited to the tarpit; lower `ipv6-prefix` (e.g. 48) to group them.

## Changelog

**1.1.0** — reporting and geolocation
- Connection log: JSON lines, rate cap, size rotation, gzip, pruning by count and age.
- Lifetime stats file, persisted across restarts.
- `limitlessh-report`: reports, per-IP history, CSV/JSONL/JSON export, offline geolocation (country, region, city, ASN, organisation).
- Built-in `.mmdb` reader (stdlib only) with spec resource limits.
- `limitlessh-geoupdate` service and monthly timer for DB-IP Lite.
- Installer: `--log-retention-days`, `--no-connection-log`, `--geo-edition`, `--no-geo`, `--uninstall --purge`.

**1.0.1** — security fixes
- Per-window source table was unbounded; rotating source addresses could exhaust memory and get the service killed. Now capped at 10,000.
- Kernel buffers were shrunk after `accept()`, too late to affect the TCP window; clients could queue ~32 KiB each in kernel memory. Now set on the listener and in the socket unit.
- Installer: digit counts capped so bash arithmetic can't wrap out-of-range values (e.g. port `18446744073709551638` → 22).
- Installer: `--log-level` validated; a newline could inject config lines.
- Installer: port owners identified by executable path / unit state instead of process name, which any local user can spoof.
- Installer: program written via `mktemp` in a root-owned, non-symlinked directory.
- Service: `CPUWeight=20` so a connection flood yields CPU to sshd.
- `JOURNAL_STREAM` verified against stderr before using journal priority prefixes.

**1.0.0** — initial release

## Credits

Based on the idea of [endlessh](https://github.com/skeeto/endlessh) by Chris Wellons ([write-up](https://nullprogram.com/blog/2019/03/22/)). Independent implementation; no shared code.

IP geolocation by [DB-IP](https://db-ip.com), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The databases are downloaded at install time and are not included in this repository.

## License

See [LICENSE](LICENSE).
