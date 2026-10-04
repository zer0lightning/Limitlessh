# Limitlessh
![Limitlessh](./assets/banner.jpg)
Hardened SSH tarpit inspired by [endlessh]. Holds scanners on port 22 with an endless random banner, while the real sshd runs on another port.

```
scanner -> :22    limitlessh   random line, 10 s, random line, ... (forever)
admin   -> :2200  sshd
```

## Comparison with endlessh

| | endlessh | limitlessh |
|---|---|---|
| Per-IP limit | none | default 8 |
| Per-network limit (/24, /64) | none | default 32 |
| When full | stops accepting | evicts oldest client of the busiest network |
| Client stops reading | held | dropped |
| Vanished client | held until TCP timeout (~15 min) | freed via `TCP_USER_TIMEOUT` |
| Max hold time | none | optional `max-lifetime` |
| Logging | line per connect/disconnect | periodic summary; rotated, rate-capped JSON connection log |
| Reports | none | `limitlessh-report`: tables, live view, CSV/JSON export |
| Geolocation | none | country, region, city, ASN, organisation (offline) |
| Port 22 binding | `CAP_NET_BIND_SERVICE` | systemd socket activation, no capabilities |
| Network access | full | none (`PrivateNetwork=yes`) |
| `systemd-analyze security` | 4.2 (hardened unit) | 0.4 |
| Language | C | Python 3, stdlib only |

## Behaviour

- Client data is never read. `SO_RCVBUF`/`SO_SNDBUF` (1 KiB/2 KiB) are set on the listening socket, limiting queued data to ~1.1 KiB per client.
- Every connection is accepted; connections over a limit are closed immediately, so the listen backlog never fills.
- Eviction selects the oldest client of the network with the most clients, in O(1).
- Banner lines: 3 to `max-line` printable ASCII bytes plus CRLF, never starting with `SSH-`. Delay jittered ±30%.
- A client is dropped when 1 KiB of output is queued.
- Summary source statistics are capped at 10,000 addresses per window.
- Connection log: one JSON line per connection, capped at `log-rate` lines/s (excess counted, not written), rotated at `log-max-size`, gzip-compressed on a background thread, pruned by count and age.
- Lifetime stats are written to `stats-file` every `stats-interval` seconds and persist across restarts.
- Memory: ~4 KiB per client (3,000 clients ≈ 12 MB). Flood cost while full: ~90 µs CPU per connection at 8,000 conn/s.

## Requirements

- Ubuntu 22.04+ (systemd ≥ 247)
- Python ≥ 3.8
- root

## Install

Keep an existing SSH session open until login on the new port works.

```bash
wget https://raw.githubusercontent.com/<your-user>/limitlessh/main/install-limitlessh.sh
chmod +x install-limitlessh.sh
./install-limitlessh.sh --print-units   # show generated config and units (no root)
sudo ./install-limitlessh.sh            # sshd -> 2200, limitlessh -> 22
```

The installer also downloads DB-IP Lite city + ASN databases (~275 MB) and enables a monthly update timer. `--geo-edition country` uses ~35 MB; `--no-geo` skips the download.

From a new terminal:

```bash
ssh -p 2200 user@server
sudo limitlessh-report --live
```

Open the new SSH port in any cloud firewall or security group; the installer manages only `ufw`.

### Installer options

| Option | Default | |
|---|---|---|
| `-p, --port PORT` | `22` | tarpit port |
| `-s, --ssh-port PORT` | `2200` | new sshd port |
| `--no-ssh-move` | | leave sshd unchanged; fail if it holds the tarpit port |
| `-d, --delay SEC` | `10` | seconds between lines |
| `-l, --max-line N` | `32` | max line length (3–253) |
| `-c, --max-clients N` | `4096` | global limit |
| `-i, --per-ip N` | `8` | per-IP limit |
| `-n, --per-net N` | `32` | per-/24 (IPv4) or /64 (IPv6) limit |
| `-t, --max-lifetime SEC` | `0` | drop after SEC seconds; 0 = never |
| `--summary-interval SEC` | `600` | 0 = off |
| `-v, --log-level LEVEL` | `info` | `debug`, `info`, `warning`, `error` |
| `--log-retention-days N` | `90` | 0 = prune by count only |
| `--no-connection-log` | | disable the connection log (no reports) |
| `--geo-edition E` | `city` | `city` (~250 MB) or `country` (~10 MB), plus ASN (~25 MB) |
| `--no-geo` | | skip geolocation databases |
| `-y, --yes` | | no confirmation prompts |
| `--print-units` | | print config and units, exit |
| `-u, --uninstall` | | remove limitlessh; keep logs, stats, geo data |
| `--purge` | | with `--uninstall`: also delete logs, stats, geo data |
| `-h, --help` / `-V, --version` | | |

Environment variables `PORT`, `SSH_PORT`, `DELAY`, `MAX_LINE`, `MAX_CLIENTS`, `PER_IP`, `PER_NET`, `MAX_LIFETIME`, `SUMMARY_INTERVAL`, `LOG_LEVEL`, `LOG_RETENTION_DAYS`, `GEO_EDITION` set defaults; flags override them.

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
| `/usr/local/lib/limitlessh/limitlessh-report.py` | report tool; linked as `/usr/local/bin/limitlessh-report` |
| `/etc/limitlessh/limitlessh.conf` | config |
| `/etc/systemd/system/limitlessh.socket` | listening port (`ListenStream=`) |
| `/etc/systemd/system/limitlessh.service` | tarpit service |
| `/etc/systemd/system/limitlessh-geoupdate.{service,timer}` | monthly geo update |
| `/var/log/limitlessh/connections*.log[.gz]` | connection log, root-readable only |
| `/var/lib/limitlessh/stats.json` | lifetime stats |
| `/var/lib/limitlessh/live.json` | current sessions, written only during `--live` |
| `/var/lib/limitlessh-geo/*.mmdb` | geolocation databases |

## SSH port move

When sshd holds the tarpit port, the installer:

1. Backs up `/etc/ssh` to `/root/limitlessh-ssh-backup-<timestamp>/`.
2. Allows the new port in `ufw`.
3. Comments out all `Port` lines in `sshd_config` and `sshd_config.d/*.conf`; adds `Port <new>` before any `Match` block.
4. Validates with `sshd -t`.
5. If `ssh.socket` is in use (Ubuntu 22.10+), writes `/etc/systemd/system/ssh.socket.d/10-limitlessh-port.conf`.
6. Verifies sshd listens on the new port and the old port is free.

Any failure restores the backup.

## Configuration

`/etc/limitlessh/limitlessh.conf` (`key = value` or `key value`, `#` comments):

```ini
delay              = 10
max-line           = 32
max-clients        = 4096
per-ip             = 8
per-net            = 32
ipv4-prefix        = 24
ipv6-prefix        = 64
max-lifetime       = 0
summary-interval   = 600
log-level          = info
log-file           = /var/log/limitlessh/connections.log   # omit to disable
log-max-size       = 20      # MiB per file
log-max-files      = 50      # rotated .gz files kept
log-retention-days = 90      # 0 = prune by count only
log-rate           = 200     # lines per second
stats-file         = /var/lib/limitlessh/stats.json
stats-interval     = 60
live-file          = /var/lib/limitlessh/live.json         # omit to disable --live
live-max           = 2000    # sessions per live snapshot
```

`sudo systemctl reload limitlessh` applies changes without dropping clients. Invalid values are rejected and the current settings kept. Lowered limits trim existing clients.

To change the port, re-run the installer with `-p`, or edit `ListenStream=` in the socket unit and run:

```bash
sudo systemctl daemon-reload && sudo systemctl restart limitlessh.socket limitlessh
```

The installer sets `LimitNOFILE=` (max-clients + 256) and `MemoryMax=` (max-clients × 16 KiB + 64 MiB, min 128 MiB). If `max-clients` is raised manually without raising these, limitlessh lowers `max-clients` to fit and logs a warning.

## Operation

| | |
|---|---|
| Service log | `journalctl -u limitlessh -f` |
| Stats to log | `sudo systemctl kill -s USR1 limitlessh` |
| Reload | `sudo systemctl reload limitlessh` |
| Status | `systemctl status limitlessh.socket limitlessh` |

Summary line format:

```
summary: active=1873 networks=1204 peak=1902 | last 10m: new=412 closed=389
rejected=57 (per-ip 51, per-net 6) evicted=0 stalled=3 expired=0 |
total: accepted=91204 attacker-time=38d4h sent=2.1MiB | top: 203.0.113.7(31), ...
```

`attacker-time` is the cumulative time clients spent connected.

## Reports

```bash
sudo limitlessh-report --live                  # live view, every 2 s, q to quit
sudo limitlessh-report --live --interval 1
sudo limitlessh-report                         # last 7 days
sudo limitlessh-report --since 24h --top 20
sudo limitlessh-report --since 2026-09-01 --until 2026-10-01
sudo limitlessh-report --ip 203.0.113.7        # history and location of one IP
sudo limitlessh-report --lookup 192.0.2.1 198.51.100.2
sudo limitlessh-report --since 30d --csv connections.csv
sudo limitlessh-report --since all --jsonl -
sudo limitlessh-report --json > report.json
```

Report sections: live status and lifetime totals; overview (trapped, rejected, unique IPs and networks, new IPs, attacker time, average and longest hold); outcomes; hold-time distribution; top IPs by attacker time and by connections; top countries; top ASNs; longest sessions; daily totals; hour of day. Times are local unless `--utc`.

Output:

- Colour on terminals; `--color never|always`; `NO_COLOR` disables.
- Bars and table rules use block characters on UTF-8 terminals; plain ASCII with `--ascii`, `LIMITLESSH_ASCII=1`, or automatically on non-UTF-8 terminals. ASCII mode transliterates place names.
- Piped output has no escape codes.

CSV/JSONL columns: `time_utc, ip, result, duration_s, bytes, country_code, country, region, city, latitude, longitude, asn, org`. Export files are created with mode 0600.

### Live view

`--live` redraws every `--interval` seconds (default 2) until `q`:

- active clients vs `max-clients`, networks, trapped and rejected per minute
- attacker time: held now, this run, lifetime; counts by outcome
- current sessions, longest held first: IP, held, start, bytes, location, network
- top active source IPs; recent events

When piped or with `--once`, a single frame is printed.

`--live` touches `/var/lib/limitlessh/live.json.request`. While that file is under 15 s old, the tarpit writes `live.json` once per second (at most `live-max` sessions). The report opens these files with `O_NOFOLLOW`, rejects non-regular and multiply-linked files, and validates every field.

### Connection log format

```json
{"ts":"2026-10-04T07:26:01Z","ip":"203.0.113.7","dur":5321.4,"bytes":11210,"result":"closed"}
{"ts":"2026-10-04T07:26:02Z","ip":"203.0.113.7","dur":0.0,"bytes":0,"result":"rejected-ip"}
{"ts":"2026-10-04T07:26:03Z","suppressed":1840}
{"ts":"2026-10-04T07:20:00Z","event":"start","version":"1.2.2"}
```

- `ts`: connection start, UTC.
- `result`: `closed` (client disconnected), `evicted`, `stalled`, `expired`, `shutdown`, `rejected-ip`, `rejected-net`.
- `suppressed`: events dropped by the rate cap.

### Geolocation

Lookups run offline in `limitlessh-report` against `.mmdb` files in `/var/lib/limitlessh-geo`. The tarpit performs no lookups.

- Default source: [DB-IP Lite](https://db-ip.com/db/lite.php) city + ASN (CC BY 4.0), updated by `limitlessh-geoupdate.timer` on the 5th of each month. Manual update: `sudo systemctl start limitlessh-geoupdate`.
- The ISP column is the ASN organisation. `GeoIP2-ISP.mmdb` is used if present.
- `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` placed in the geo directory take precedence over DB-IP files.
- Downloads are verified before replacement: HTTPS only (including redirects), size limits (400 MiB compressed, 1.5 GiB decompressed), database type, build date, test lookups.
- The `.mmdb` reader is bounds-checked and enforces the MaxMind DB spec per-lookup limits (65,536 values, 2 MiB payload).

### Privacy

IP addresses are personal data under GDPR, PIPEDA and similar laws. Logs are root-readable only and deleted after `log-retention-days`. Disable with `--no-connection-log` or by removing `log-file`.

## Sandbox

Tarpit service:

- `DynamicUser=yes`, `PrivateUsers=yes`, empty `CapabilityBoundingSet=`, `NoNewPrivileges=yes`
- `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`; the listening socket is passed by systemd
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectProc=invisible`
- `ProtectKernelTunables/Modules/Logs=yes`, `ProtectClock=yes`, `ProtectControlGroups=yes`, `RestrictNamespaces=yes`, `MemoryDenyWriteExecute=yes`
- `SystemCallFilter=@system-service ~@privileged @resources`
- `MemoryMax=`, `TasksMax=16`, `LimitNOFILE=`, `CPUWeight=20`
- Writable: `StateDirectory=limitlessh`, `LogsDirectory=limitlessh` (0700)
- Socket unit: `ReceiveBuffer=1024`, `SendBuffer=2048`

Geo updater: separate `DynamicUser`, same filesystem, kernel and syscall restrictions; `AF_INET`/`AF_INET6` only; writable `/var/lib/limitlessh-geo`; `MemoryMax=512M`; idle I/O priority.

```bash
systemd-analyze security limitlessh.service             # 0.4
systemd-analyze security limitlessh-geoupdate.service   # 1.3
```

## Running without systemd

```bash
python3 limitlessh.py --port 2222
python3 limitlessh.py --bind 127.0.0.1 --port 2222 --log-level debug
python3 limitlessh.py --config limitlessh.conf --check-config
python3 limitlessh.py --help
```

Default bind is `::` (IPv4 and IPv6). Ports below 1024 require root or `CAP_NET_BIND_SERVICE`.

| Signal | |
|---|---|
| `SIGHUP` | reload config |
| `SIGUSR1` | log stats |
| `SIGTERM`, `SIGINT` | shut down, log final summary |

## Uninstall

```bash
sudo ./install-limitlessh.sh --uninstall
```

Removes units, programs, config, and the `ufw` rule (unless the port is 22). Logs, stats and geo data are kept unless `--purge` is given. sshd is not changed; to restore it:

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
| `test_reporting.py` | logging, stats, report, `.mmdb` reader, updater, live view tests |

```bash
python3 build.py              # regenerate install-limitlessh.sh
python3 test_limitlessh.py    # Linux; uses 127.x.y.z source addresses
git clone --depth 1 https://github.com/maxmind/MaxMind-DB.git tests/MaxMind-DB
python3 test_reporting.py     # geo tests need MaxMind test databases
```

`test_limitlessh.py`: banner format, limits, eviction, accepting while full, max lifetime, unread client data, stalled clients, signals and reload, summaries, socket activation (needs `systemd-socket-activate`), config errors, 3,000 concurrent clients, kernel buffer size, bounded statistics.

`test_reporting.py`: log rate cap, rotation, retention, stats persistence and tampering, `.mmdb` decoding against the reference reader, hostile `.mmdb` files, report counts and validation, output sanitising, updater refusal cases, live snapshots, symlink/FIFO/hard-link refusal, colour and width handling, interactive `--live` in a pseudo-terminal, audit regressions.

## Limitations

- The installer targets Ubuntu with systemd.
- Lines before the SSH version string are permitted by RFC 4253 but uncommon; the tarpit is detectable.
- Scanners with short connect timeouts disconnect quickly.
- The tarpit does not protect the real sshd.
- Per-network limits group a /24 or /64; adjust `per-net`, `ipv4-prefix`, `ipv6-prefix` for large NATs.
- Clients from many /64s (e.g. a /48) can fill all slots and cause continuous eviction; set `ipv6-prefix = 48` to group them.
- Geolocation is approximate, especially city level; ASN organisations are not always the retail ISP.
- Under sustained floods the log rate cap drops per-connection records (stats counts remain exact), and count-based pruning can shorten history before `log-retention-days`.

## Changelog

**1.2.2**
- Report: removed status dot, heading markers, arrows and middle dots; status is a `LIVE`/`STALE` label.
- Report: `--ascii` / `LIMITLESSH_ASCII=1`, automatic on non-UTF-8 terminals; output never fails on terminal encoding.

**1.2.1** (security)
- Report: `--csv`/`--jsonl` refuse symlinked and non-regular targets (planted symlink caused root to overwrite its target).
- Report: logs opened with `O_NOFOLLOW`/`O_NONBLOCK` (FIFO hung the report; check-then-open race followed swapped symlinks).
- Report: geo databases must be regular files.
- Report, tarpit: deeply nested JSON in log, live or stats files no longer raises `RecursionError`.
- Report: live snapshot fields range-checked (out-of-range timestamps crashed `--live`).
- Report: per-IP tables capped at 500,000 addresses; totals exact.
- Geo updater: HTTPS-to-HTTP redirects refused.
- Tarpit: rate-capped events skip formatting (18 µs to ~2 µs each).
- Tarpit: stats/live write failures logged at most once per minute.

**1.2.0**
- `limitlessh-report --live`.
- Coloured output, width-correct tables, `--color`, `NO_COLOR`.
- Tarpit: `live-file`, `live-max`; snapshots only while requested.
- Report: service-owned files opened without following symlinks.
- Tarpit: accepts connections only after signal handlers are installed.

**1.1.0**
- Connection log with rate cap, rotation, gzip, pruning.
- Lifetime stats file.
- `limitlessh-report`: reports, per-IP history, CSV/JSONL/JSON export, offline geolocation.
- Stdlib `.mmdb` reader with spec resource limits.
- `limitlessh-geoupdate` service and monthly timer.
- Installer: `--log-retention-days`, `--no-connection-log`, `--geo-edition`, `--no-geo`, `--uninstall --purge`.

**1.0.1** (security)
- Per-window source table capped at 10,000 (unbounded growth from rotating source addresses).
- Kernel buffers set on the listener and socket unit (setting after `accept()` allowed ~32 KiB queued per client).
- Installer: digit counts capped (bash arithmetic wrapped `18446744073709551638` to 22).
- Installer: `--log-level` validated (newline injected config lines).
- Installer: port owners identified by executable path or unit state, not process name.
- Installer: program written via `mktemp` in a root-owned, non-symlinked directory.
- Service: `CPUWeight=20`.
- `JOURNAL_STREAM` verified against stderr.

**1.0.0**
- Initial release.

## Credits

Based on [endlessh](https://github.com/skeeto/endlessh) by Chris Wellons ([write-up](https://nullprogram.com/blog/2019/03/22/)). Independent implementation; no shared code.

IP geolocation by [DB-IP](https://db-ip.com), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Databases are downloaded at install time and are not included in this repository.

## License

See [LICENSE](LICENSE).
