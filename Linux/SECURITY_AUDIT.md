# ProxyBridge for Linux — pre-release security assessment (2026-10-20)

Scope: everything under `Linux/` as of commit 5f307c2 on `dev`: the eBPF program and its loader, the userspace relay
(SOCKS5/HTTP/UDP), the DNS tap, the rule engine, `/proc` scanning, the `.pbprofile` parser, the CLI, the GTK GUI, the
"start at boot" systemd unit, `setup.sh`, `build.sh` and the GitHub workflows. Four independent code reviews, one per area,
plus a 4-minute mutation fuzz of the profile parser (3.1 million inputs under ASan/UBSan, no crash) and `readelf`
checks of the shipped binaries.

Threat model: the engine runs as root on a desktop or shared host. Untrusted inputs are the proxy server's bytes, DNS
answers, the contents of `/proc` for other users' processes, other local users' processes (which may try to bypass their
own rules, hijack another process's flow, or exhaust the daemon), imported profile files, the update feed, and the
command line / environment.

**Result:** no memory-safety bug was found in any parser (SOCKS5, HTTP CONNECT, DNS decompression, UDP SOCKS header,
JSON). All findings concern trust between local processes, what the root daemon accepts from remote text, and the
boot service. Everything below marked *fixed* was fixed in the commit that follows this document; three design
limitations are documented in the README instead.

## Findings and fixes

### 1. Boot service could run a user-writable binary as root — medium, fixed
`gui/gui_boot.c`. The unit's `ExecStart` pointed at the `ProxyBridge` binary next to the running GUI. The README
encourages `sudo ./ProxyBridgeGUI` from the extracted tarball, so ticking "Start at Boot" from `~/Downloads/pb/`
produced a root service that executes `~/Downloads/pb/ProxyBridge` (and loads `libproxybridge.so` from the same
directory via `$ORIGIN`) at every boot. Anything that later gains write access to that user account owns root at boot.
**Fix:** the GUI accepts the binary only when it and every directory above it belong to root and are writable by root
only (`boot_path_trusted`), otherwise it refuses with "install ProxyBridge with setup.sh". Unit test added.

### 2. Boot service loaded the profile by *name* — medium, fixed
`gui/gui_boot.c`, `profile/pb_profile.c` (`pbp_resolve`). The unit contained `--profile "<name>"`. A name containing
`/` (typed, or carried in an imported file's `"Name"`) is a relative path, resolved against the service's working
directory `/`, so a profile named `tmp/.w.pbprofile` made the root CLI load `/tmp/.w.pbprofile` at boot — a file any
local user can create, redirecting all matching traffic to their proxy. **Fix:** the unit now carries the absolute path
of the stored profile file; `boot_unit_text` refuses relative paths.

### 3. `--profile name.pbprofile` shadowed by a file in the current directory — low, fixed
`pbp_resolve` tried a bare name ending in `.pbprofile` as a relative path first. `sudo ProxyBridge --profile Work.pbprofile`
run from `/tmp` loaded an attacker's `/tmp/Work.pbprofile` instead of the GUI profile. **Fix:** anything without `/` is a
profile name; a file in the current directory needs `./`.

### 4. Systemd unit ran unconfined — low, fixed
The unit had only `Type=simple`/`Restart=on-failure`. **Fix:** `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome=read-only`, `PrivateTmp`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectClock`, `RestrictSUIDSGID`,
`LockPersonality`, `RestrictRealtime`. (Root and the eBPF capabilities are still needed; a capability bounding set was
not added without a real boot test.)

### 5. Uninstall left an enabled root service behind — low, fixed
The README's uninstall steps did not remove `/etc/systemd/system/proxybridge.service`. **Fix:** `setup.sh --uninstall
[--purge]` and README steps that disable and remove the unit.

### 6. Any local process could send UDP through another process's flow — medium, fixed
`src/pb_relay.c` (`udp_dgram`), `src/bpf/proxybridge.bpf.c` (`udp_flow_addr`). Redirected UDP is addressed to a
loopback "flow address" (127.x.y.z) that the relay maps back to the real destination. The relay never checked who sent
the datagram, and the address is a deterministic hash that is also visible in `/proc/net/udp`. A process whose own
traffic is BLOCKed could send to a flow address used by an allowed process and have its payload relayed through the
proxy with the configured credentials, logged as the victim. **Fix:** every flow address is now per process (pid in the
hash), and for each new client port the relay verifies through `/proc/net/udp{,6}` and `/proc/<pid>/fd` that the sender
holds a UDP socket on that port and is still the same executable (`pb_core_udp_sender_ok`); other senders are dropped.
Relay unit test added (impostor gets nothing, owner keeps working).

### 7. UDP session table exhaustion by one process — medium, fixed
1024 sessions total; one process sending from 1024 source ports filled the table, starving everyone else's UDP.
**Fix:** one process may hold at most a quarter of the table (together with fix 6, a process can only use its own flows).

### 8. Flow-address probe exhaustion borrowed another flow's address — low, fixed
In the eBPF program, when all 8 probed slots were occupied by other live flows, the loop fell through and returned the
last computed address — another flow's — so the datagram would have been delivered to another process's destination.
**Fix:** the send is refused (EPERM) instead.

### 9. Userspace decisions trusted a possibly reused PID — high (plausible), fixed
`src/ProxyBridge.c` (`pb_core_decide`). Flows the kernel cannot decide itself (long host lists, domain rules) are
decided by the relay later. It identified the program by reading `/proc/<pid>/exe` *first* and only fell back to the
executable identity the kernel had captured at `connect()`. If the process exited and its PID was reused before the
relay ran, the rule was evaluated against the new program. **Fix:** the kernel-captured identity (device + inode) is
preferred; `/proc` is the fallback.

### 10. DNS tap learned from unrelated answer records — medium, fixed
`src/pb_dns.c`. Every A record and every CNAME in a response was attached to every address in it, regardless of the
question. A response `q.example A 1.1.1.1; allowed.corp A 6.6.6.6; victim.bank CNAME …` taught the engine that all
three names belong to both addresses, which steers domain rules and, with "send domain to proxy", the host name the
proxy is asked to connect to. **Fix:** only the question name, CNAME targets chained from it, and A records owned by
those names are used. Unit test added.

### 11. SOCKS5 UDP ASSOCIATE relay address pointed at this host — low, fixed
A remote proxy could answer `BND.ADDR = 127.0.0.1:<port>`, making the root relay send application payloads to local
services. **Fix:** a loopback relay address is accepted only when the proxy itself is on loopback.

### 12. Exponential glob in log filters — high, fixed
`profile/pb_profile.c` (`ci_glob`). The filter matcher backtracked exponentially on patterns with many `*`. A filter
`*a*a*a*…*b` from an imported profile took 8 s *per connection event* while holding the engine's callback lock — one
crafted profile froze logging and the GUI. **Fix:** linear single-backtrack glob (the engine's own algorithm); timing
test added.

### 13. Control characters from profiles and the update feed reached the terminal — medium, fixed
The JSON parser accepted raw bytes 0x01–0x1F and `\u001b`, `\n`, `\u0007` etc. in any string. A proxy `Host` or `Name`
with `ESC]0;…BEL` set the operator's terminal title; a newline forged extra log lines; the update feed's `version`
field was printed raw (a MITM could inject escape sequences into the root operator's terminal). **Fix:** profiles with
control characters in any field are rejected; the feed `version` must be a plain version string (≤ 32 chars of
`[0-9A-Za-z.+-]`); the engine replaces control characters in anything it hands to the log and connection callbacks
(executable names, DNS names).

### 14. JSON parser leniency that diverges from Windows/.NET — low, fixed
`"Port": 1080e1` was read as 1080 (Windows reads 10800); `8.9` as 8; duplicate keys took the first value (Windows
takes the last), so a file could look different to a reviewer on Windows than what Linux applied. **Fix:** non-integral
numbers and duplicate keys (case-insensitive) are rejected.

### 15. Proxy Id wrap — low, fixed
`"Id": 4294967295` made the next auto-assigned id 0, which means "default proxy" everywhere. **Fix:** ids ≥ 2^31 are
rejected.

### 16. Double `close()` in profile writing — low, fixed
On a failed `rename`, the descriptor was closed twice; in the multithreaded GUI that can close an unrelated,
freshly reused descriptor. Fixed.

### 17. curl argument handling — low, fixed
The feed URL (overridable through `PROXYBRIDGE_UPDATE_FEED` in the CLI, test hook in the GUI) was passed to curl
without `--`, and any protocol was allowed. **Fix:** `--proto =https,file -- <url>`; the environment override is
ignored when running set-uid (`AT_SECURE`); `PROXYBRIDGE_CONFIG_DIR` uses `secure_getenv`.

### 18. GUI update check — low, fixed
The GUI parsed the feed with `strstr` and could hand any https URL to the browser, which runs as root. **Fix:** the GUI
uses the same strict parser and version comparison as the CLI, and only opens pages under `github.com/InterceptSuite/`
or `interceptsuite.com`.

### 19. Exported profiles unreadable by the user who exported them — low, fixed
Exports are written as root with mode 0600, so under `sudo` the invoking user cannot open their own export. **Fix:**
when started through `sudo`/`pkexec` and the destination directory belongs to the invoking user, the file is handed to
that user.

### 20. Release integrity — low, fixed
Release tarballs had no checksum, and the version from the manual `tag` input was interpolated into a shell script
(template-injection pattern; mitigated by the actor check). **Fix:** a `.sha256` file is published with each tarball and
the version is passed through `env`.

### 21. Smaller relay items — fixed
- Credentials copied onto worker stacks (`ab[]`, `cred[]`, `enc[]`, request buffer) are wiped with `explicit_bzero`.
- The "no original destination for client" log (triggered by anyone connecting to the relay port) is rate-limited.
- `teardown()` now takes the data-thread mutex while freeing connection lists that `pb_relay_flows()` may be walking.
- `setup.sh` installs with `install -o root -g root -m 0755` (a pre-existing file's owner is never kept) and creates
  `/etc/proxybridge` 0700.

## Documented design limitations (README → Security model)

- **Fail-open on exit.** The kernel removes the eBPF programs when ProxyBridge stops or crashes; from then on
  `BLOCK` rules no longer block and nothing is proxied. ProxyBridge is a routing tool, not a firewall.
- **Local-proxy exemption by listening port.** A process that listens on the configured proxy address and port is
  treated as the proxy and its connections go direct. While that port is free (proxy not running), any local process
  that binds it is exempted. Point rules at running proxies, or at a proxy on another host, on shared machines.
- **DNS tap mappings are per address, not per process.** A process's own DNS answers (now bailiwick-checked) still
  teach the engine name→address pairs that domain rules of other processes match by address.
- Running out of `exe2class` map space (16384 distinct executables) degrades unknown programs to the slower userspace
  decision path; decisions stay correct.

## Verified as solid
SOCKS5 greeting/auth/reply and HTTP CONNECT parsers (bounded, status checked before address), DNS name decompression
(hop limit, pointer bounds), UDP SOCKS header parsing, TCP-DNS framing, fd lifecycle in every relay error path,
handshake deadlines and worker-pool shedding, relay sockets bound to loopback only (UDP additionally to `lo` with an
`IP_PKTINFO` 127/8 filter), fail-closed on handshake failure, missing proxy and BLOCK; cgroup v2 root attach with
`ALLOW_MULTI`, v4-mapped v6 handling, implicit-direct consistency between kernel and userspace, first-match rule
ordering (covered by the 4800-case differential test); JSON nesting depth and node limits, surrogate handling,
file/proxy/rule/filter limits enforced before allocation, atomic 0600 writes via `mkstemp`+`rename`, percent-encoded
profile file names (no traversal); GTK markup only through `g_markup_printf_escaped`, `%s` everywhere a dialog shows
data, systemd quoting with control-character rejection, `systemctl`/`curl` spawned with fixed argv; all three binaries
PIE, full RELRO, BIND_NOW, NX, stack protector, FORTIFY_SOURCE=3, CET; actions SHA-pinned; libbpf source fetch
checksum-verified.

## Tests added
`profile_test`: control characters, non-integral numbers, duplicate keys, Id range, glob timing bound, strict
`pbp_resolve`, feed version validation. `dns_test`: out-of-bailiwick records. `relay_test`: impostor UDP sender.
`boot_test`: absolute profile path, hardening directives, `boot_path_trusted`. `ui_test`: escape sequences in the feed,
foreign download host refused. `e2e_cli`: unchanged surface, still 48/48.
