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
| Logging | one line per connect/disconnect | summary every 10 min; per-connection at `debug` |
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

Then, from a new terminal:

```bash
ssh -p 2200 user@server
journalctl -u limitlessh -f
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
| `-y, --yes` | | no confirmation prompts |
| `--print-units` | | print config and units, exit |
| `-u, --uninstall` | | remove limitlessh |
| `-h, --help` / `-V, --version` | | |

Environment variables (`PORT`, `SSH_PORT`, `DELAY`, `MAX_LINE`, `MAX_CLIENTS`, `PER_IP`, `PER_NET`, `MAX_LIFETIME`, `SUMMARY_INTERVAL`, `LOG_LEVEL`) set defaults; flags override them.

```bash
sudo ./install-limitlessh.sh -s 4822                  # sshd -> 4822
sudo ./install-limitlessh.sh -p 2222 --no-ssh-move    # tarpit on 2222, sshd unchanged
sudo ./install-limitlessh.sh -c 10000 -i 4 -t 86400
```

Re-running upgrades in place. If endlessh holds the tarpit port, the installer offers to stop and disable it.

### Installed files

| Path | |
|---|---|
| `/usr/local/lib/limitlessh/limitlessh.py` | program |
| `/etc/limitlessh/limitlessh.conf` | config |
| `/etc/systemd/system/limitlessh.socket` | listening port (`ListenStream=`) |
| `/etc/systemd/system/limitlessh.service` | sandboxed service |

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

## Sandbox

The service runs under:

- `DynamicUser=yes`, `PrivateUsers=yes`, empty `CapabilityBoundingSet=`, `NoNewPrivileges=yes`
- `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX` — the listening socket is passed in by systemd
- `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectProc=invisible`
- `ProtectKernelTunables/Modules/Logs=yes`, `ProtectClock=yes`, `ProtectControlGroups=yes`, `RestrictNamespaces=yes`, `MemoryDenyWriteExecute=yes`
- `SystemCallFilter=@system-service ~@privileged @resources`
- `MemoryMax=`, `TasksMax=16`, `LimitNOFILE=`, `CPUWeight=20`
- Socket unit: `ReceiveBuffer=1024`, `SendBuffer=2048`

```bash
systemd-analyze security limitlessh.service
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

Removes units, program and config, and the `ufw` rule unless the port is 22. sshd is not changed. To restore it:

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
| `limitlessh.py` | program |
| `install-limitlessh.template.sh` | installer template |
| `build.py` | embeds `limitlessh.py` into the template |
| `install-limitlessh.sh` | generated installer |
| `test_limitlessh.py` | tests |

```bash
python3 build.py              # regenerate install-limitlessh.sh
python3 test_limitlessh.py    # Linux; uses 127.x.y.z source addresses
```

Tests cover banner format, bounded source statistics, kernel receive buffer size, per-IP/per-network limits, eviction, accepting while full, max lifetime, unread client data, stalled clients, signals and reload, summaries, socket activation (needs `systemd-socket-activate`), config errors, and 3,000 concurrent clients.

## Limitations

- The installer targets Ubuntu with systemd.
- Lines before the SSH version string are allowed by RFC 4253 but uncommon, so the tarpit is detectable.
- Scanners with short connect timeouts disconnect quickly.
- Per-network limits group a /24 or /64; tune `per-net`, `ipv4-prefix` and `ipv6-prefix` for large NATs.
- An attacker controlling many /64s (e.g. a /48) can fill all slots and cause continuous eviction. Impact is limited to the tarpit; lower `ipv6-prefix` (e.g. 48) to group them.

## Changelog

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

## License

See [LICENSE](LICENSE).
