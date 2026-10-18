# ProxyBridge macOS tests

Regression tests for the macOS app and system extension. They found the UDP association leak, the proxy
reply parsing bugs and the BLOCK-without-proxy bug, so run them before every release.

There are two kinds:

| | needs | time |
|---|---|---|
| **Logic tests** (`logic/run.sh`) | the Xcode command line tools | seconds |
| **End-to-end tests** (`pbtest.py`) | the app installed, the system extension approved, the test profile imported, internet | about 5 minutes (+2.5 with `--slow`) |

The end-to-end tests cannot run on a GitHub-hosted runner: macOS asks a person to approve the system extension
and the network configuration. Run them locally, or on a dedicated Mac where both are already approved.

## Logic tests

```
./logic/run.sh
```

Compiles `matcher_tests.swift` (rule matching: process, host, domain and port patterns) and `dnsmap_tests.swift`
(the IP to name map, the 5 minute name age, the safe-hostname check) against the real extension sources and runs them.

## End-to-end tests

One-time setup:

1. Install and start ProxyBridge, approve the system extension and the network configuration when macOS asks.
2. In the app, create a profile and import `pbtest.pbprofile` (Profiles menu, Import). It adds five test proxies
   on `127.0.0.1` (SOCKS5 1080, SOCKS5 1081 with auth, SOCKS5 1082 black hole, HTTP 8080, HTTP 8081 with auth;
   the credentials `pbtest` / `pbpass` are dummies) and ten rules. Make it the active profile.
3. Python 3 and a C compiler must be available (`xcode-select --install`).

Run:

```
python3 pbtest.py                  # functional replies hostnames stress dns leaks
python3 pbtest.py functional       # one suite
python3 pbtest.py --slow           # also the idle UDP reaper test (2.5 minutes)
sudo -v && python3 pbtest.py       # `sudo -v` first so `leaks` and the DNS cache flush can run without a prompt
```

The runner starts the test proxies (`servers.py`) and builds `pbudp.c` itself. Rules match on process name, so
the tests run `curl`, `nc`, `openssl` and the small `pbudp` tool, which is why the profile has rules for those.
If the rules are not active it stops with a message instead of failing every test.

| suite | checks |
|---|---|
| `functional` | rules route correctly: SOCKS5, HTTP, HTTP with auth, DIRECT, BLOCK, no rule, UDP through SOCKS5 (with and without auth), a stuck proxy handshake is cut after about 20 s |
| `replies` | a SOCKS5 reply in the longer IPv6 form followed immediately by a banner, an HTTP `200` with a banner glued to the headers, a `407` whose headers contain "200" |
| `hostnames` | the proxy receives host names or IPs according to its own "Let proxy resolve DNS" box (flushes the DNS cache first when sudo is available, so the extension sees a fresh answer for each name) |
| `stress` | three bursts of 300 UDP flows (all closed, memory flat), 300 parallel TCP connections (all succeed, none left open) |
| `dns` | 200 uncached lookups through the DNS proxy all return the right answer |
| `idle` | 40 idle UDP flows are reaped after about 2 minutes while the app still holds the sockets |
| `leaks` | `leaks` on the extension reports 0 (the extension is a root process, so this needs sudo) |
| `cli` | the command line mode (`ProxyBridge --cli`): version and error handling, a profile piped in over standard input redirects traffic, a BLOCK rule works, a second CLI is refused, Ctrl+C clears everything. **Not in the default set:** quit the app first, and the build installed in `/Applications` must include the CLI |

### Hostname suite with a box unticked

`hostnames` expects every proxy to have "Let proxy resolve DNS (send hostname)" ticked (the default). To check that
the setting is per proxy, untick it on some proxies in the app and tell the runner which, by port:

```
python3 pbtest.py hostnames:off1080,8080
```

Those proxies must then receive IPs while the others still receive names.

## Not automated

- **BLOCK without any proxy configured.** Create an empty profile (new profiles start empty) with rules
  `openssl`, any host, any port, protocol BOTH, BLOCK and `nc`, any host, any port, UDP, BLOCK. With no proxies at all,
  `openssl s_client -connect example.net:443` must fail and `nc -u <ntp ip> 123` must get no reply.
- **Rule updates without a gap** (editing rules while traffic runs) and the **update download** need the GUI.
- **A client that half-closes** (`printf ... | nc`) cannot get a reply through a transparent proxy flow on macOS, the
  system closes the flow itself. That is a platform limit, so the tests keep stdin open.

## Notes

- `leaks` freezes the extension for several seconds while it scans, so it runs last. Names the system resolver
  answers from its cache (no DNS packet) are unknown to the extension and go to the proxy as IPs, that is the
  designed fallback. The `hostnames` suite flushes the cache first when sudo works.
- The tests need the internet (example.com, example.net, example.org, www.iana.org, www.apple.com, neverssl.com,
  `time.apple.com` for NTP and `sslip.io` for DNS). Set `PB_NTP_IP` to use a different NTP server.
- `192.0.2.0/24` is a documentation range. The tests use it for addresses nothing answers, the test proxies
  answer for a few of them by themselves.
- Everything the proxies see is logged to `work/events.log` (ignored by git).
- The test rules redirect `curl`, `nc`, `openssl` and `pbudp` traffic. Switch back to your normal profile afterwards.
