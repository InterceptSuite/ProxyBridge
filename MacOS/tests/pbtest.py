#!/usr/bin/env python3
"""ProxyBridge macOS end-to-end tests. Run on a Mac that has the app installed, the system extension
approved and the pbtest.pbprofile imported (see README.md). The runner starts the local test proxies
(servers.py) itself and builds pbudp.c when needed.

  python3 pbtest.py                     the default set: functional replies hostnames stress dns leaks
  python3 pbtest.py functional stress   only those suites
  python3 pbtest.py --slow              the default set plus the 2.5 minute idle-UDP test
  python3 pbtest.py hostnames:off1080,8080
                                        hostname suite when the "Let proxy resolve DNS" box is unticked on
                                        the proxies with those ports (plain "hostnames" = all ticked)

suites: functional  rule routing, SOCKS5/HTTP/auth, DIRECT, BLOCK, UDP, stuck-handshake cut
        replies     SOCKS5 reply in IPv6 form + banner, HTTP 200 + banner, 407 with "200" in the headers
        hostnames   proxies receive host names (option on) or IPs (option off), per proxy
        stress      300 parallel TCP connections, three bursts of 300 UDP flows (memory must stay flat)
        dns         200 uncached DNS lookups through the DNS proxy
        idle        40 idle UDP flows must be reaped after ~2 minutes (slow)
        leaks       `leaks` on the extension must report 0 (needs `sudo -v` first, or SUDO_ASKPASS)
        cli         the command line mode: runs pbtest.pbprofile through `ProxyBridge --cli` from /Applications,
                    traffic must be redirected, Ctrl+C must clear everything. Not in the default set: the app
                    must be QUIT and the installed build must have the CLI
Environment: PB_NTP_IP (default: time.apple.com resolved once), PB_EVENTS (event log path)."""
import atexit, concurrent.futures as cf, json, os, random, signal, socket, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "work")
os.makedirs(WORK, exist_ok=True)
LOG = os.environ.setdefault("PB_EVENTS", os.path.join(WORK, "events.log"))
PBUDP = os.path.join(WORK, "pbudp")
EXT = "com.interceptsuite.ProxyBridge.extension"
NTP_PAYLOAD = b"\x1b" + b"\0" * 47
results = []
_servers = None


# ---------------------------------------------------------------- plumbing
def events(since):
    out = []
    try:
        for line in open(LOG):
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e["t"] >= since:
                out.append(e)
    except FileNotFoundError:
        pass
    return out


def hits(evs, kind, proxy=None, port=None):
    return [e for e in evs if e["kind"] == kind and (proxy is None or e.get("proxy") == proxy)
            and (port is None or e.get("port") == port)]


def ext_pid():
    r = subprocess.run(["pgrep", "-f", EXT], capture_output=True, text=True)
    pids = [int(p) for p in r.stdout.split() if p]
    return pids[0] if pids else None


def snap():
    """(rss MB, %cpu) of the extension, or None."""
    pid = ext_pid()
    if not pid:
        return None
    r = subprocess.run(["ps", "-o", "rss=,%cpu=", "-p", str(pid)], capture_output=True, text=True).stdout.split()
    return (int(r[0]) / 1024.0, float(r[1])) if len(r) == 2 else None


def run(cmd, timeout=30, inp=None):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, input=inp)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, b"", b"timeout"


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS " if ok else "FAIL ") + name + ("  - " + detail if detail else ""), flush=True)


def port_open(port):
    try:
        socket.create_connection(("127.0.0.1", port), 0.5).close()
        return True
    except OSError:
        return False


def start_servers():
    global _servers
    if port_open(1080):
        print("note: something already listens on 1080, assuming the test proxies are running "
              f"(their event log must be {LOG})")
        return
    # servers.py prints asyncio shutdown noise when it is stopped, keep that out of the test output
    _servers = subprocess.Popen([sys.executable, os.path.join(HERE, "servers.py")], stdout=subprocess.DEVNULL,
                                stderr=open(os.path.join(WORK, "servers.err"), "w"), env=os.environ)
    atexit.register(lambda: _servers and _servers.terminate())
    for _ in range(50):
        if port_open(1080) and port_open(8081):
            return
        time.sleep(0.1)
    sys.exit("test proxies did not start")


def build_pbudp():
    src = os.path.join(HERE, "pbudp.c")
    if not os.path.exists(PBUDP) or os.path.getmtime(PBUDP) < os.path.getmtime(src):
        subprocess.run(["cc", "-O2", "-o", PBUDP, src], check=True)


def sudo_prefix():
    """['sudo','-n'] after `sudo -v` in this terminal, ['sudo','-A'] when SUDO_ASKPASS is set, else None.
    Nothing here reads or stores a password itself."""
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
        return ["sudo", "-n"]
    if os.environ.get("SUDO_ASKPASS"):
        return ["sudo", "-A"]
    return None


def flush_dns_cache():
    """Make the system resolver ask again, so the extension sees a fresh DNS answer for every name the
    hostname tests use. Without sudo the tests still run, but a name the resolver served from its cache
    (no DNS packet, so nothing for the extension to learn) is sent to the proxy as an IP."""
    sudo = sudo_prefix()
    if not sudo:
        print("note: no sudo, DNS cache not flushed (hostname checks can fall back to IPs if the resolver answers from cache)")
        return
    subprocess.run(sudo + ["dscacheutil", "-flushcache"], capture_output=True)
    subprocess.run(sudo + ["killall", "-HUP", "mDNSResponder"], capture_output=True)
    time.sleep(2)


def ntp_ip():
    return os.environ.get("PB_NTP_IP") or socket.gethostbyname("time.apple.com")


def preflight():
    """A request that the first test rule must send through SOCKS5 1080, so a missing setup is obvious."""
    t0 = time.time()
    run(["curl", "-s", "-o", "/dev/null", "-m", "15", "https://example.com"], 20)
    time.sleep(1)
    if ext_pid() is None:
        sys.exit("The ProxyBridge extension is not running. Start the app and approve the system extension.")
    if not hits(events(t0), "connect", "socks1080", 443):
        sys.exit("The test rules are not active: curl to example.com did not reach SOCKS5 1080.\n"
                 "Import pbtest.pbprofile (Profiles menu, Import) and make it the active profile, see README.md.")


def scenario(name, cmd, expect, timeout=30, inp=None, client_ok=None):
    """expect = (event kind, proxy, port): the proxy must have seen it, or proxy None = nothing proxied."""
    t0 = time.time()
    rc, out, err = run(cmd, timeout, inp)
    time.sleep(1.0)
    evs = events(t0)
    kind, proxy, port = expect
    if proxy is None:
        proxied = [e for e in evs if e["kind"] in ("connect", "udp_assoc_open")]
        ok, detail = not proxied, ("went direct" if not proxied else f"unexpectedly proxied: {proxied[0]}")
    else:
        seen = hits(evs, kind, proxy, port)
        ok = bool(seen)
        detail = f"{kind} on {proxy}" + (f":{port}" if port else "") + (" seen" if ok else " NOT seen")
    if client_ok is not None:
        good = client_ok(rc, out, err)
        detail += f"; client {'ok' if good else 'FAILED'} rc={rc}"
        ok = ok and good
    check(name, ok, detail)


HTTP_OK = lambda rc, o, e: rc == 0 and o.strip() in (b"200", b"301", b"302", b"404")
CURL = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "25"]


# ---------------------------------------------------------------- suites
def functional():
    print("\n== functional ==")
    scenario("T1 curl example.com -> SOCKS5 1080 (domain rule)", CURL + ["https://example.com"], ("connect", "socks1080", 443), client_ok=HTTP_OK)
    scenario("T2 curl example.net -> HTTP+auth 8081", CURL + ["http://example.net"], ("connect", "http8081", 80), client_ok=HTTP_OK)
    scenario("T3 curl example.org -> HTTP 8080", CURL + ["http://example.org"], ("connect", "http8080", 80), client_ok=HTTP_OK)
    scenario("T4 curl www.iana.org -> DIRECT", CURL + ["https://www.iana.org"], ("connect", None, None), client_ok=HTTP_OK)
    scenario("T5 curl www.apple.com -> no rule, direct", CURL + ["https://www.apple.com"], ("connect", None, None), client_ok=HTTP_OK)
    # stdin is kept open: a client that half-closes after sending cannot get a reply through a
    # transparent proxy flow on macOS (the OS closes the flow), that is a platform limit
    scenario("T6 nc -> SOCKS5+auth 1081 (process rule)",
             ["bash", "-c", "(printf 'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n'; sleep 3) | nc -w 6 example.com 80"],
             ("connect", "socks1081", 80), timeout=20, client_ok=lambda rc, o, e: b"HTTP/1." in o)
    scenario("T7 openssl -> BLOCK", ["openssl", "s_client", "-connect", "example.net:443"], ("connect", None, None),
             timeout=15, inp=b"", client_ok=lambda rc, o, e: b"BEGIN CERTIFICATE" not in o)
    ip = ntp_ip()
    scenario("T8 pbudp NTP -> SOCKS5 1080 UDP associate", [PBUDP, "ntp", ip], ("udp_assoc_open", "socks1080", None),
             client_ok=lambda rc, o, e: o.strip() == b"48")
    scenario("T9 nc -u NTP -> SOCKS5+auth 1081 UDP associate", ["nc", "-u", "-w", "4", ip, "123"], ("udp_assoc_open", "socks1081", None),
             inp=NTP_PAYLOAD, client_ok=lambda rc, o, e: len(o) == 48)
    t0 = time.time()
    run(["curl", "-s", "-o", "/dev/null", "-m", "45", "http://neverssl.com"], 60)
    evs = events(t0)
    acc = hits(evs, "accept", "socks1082")
    closed = [e for e in evs if e["kind"] in ("closed_by_peer", "tcp_closed") and e.get("proxy") == "socks1082"]
    if acc and closed:
        dt = closed[0]["t"] - acc[0]["t"]
        check("T10 stuck proxy handshake is cut after ~20s", 15 <= dt <= 30, f"dropped after {dt:.1f}s")
    else:
        check("T10 stuck proxy handshake is cut after ~20s", False, f"accept={bool(acc)} closed={bool(closed)}")


def replies():
    print("\n== reply parsing ==")
    def banner(name, ip, port, proxy, want):
        t0 = time.time()
        p = subprocess.run(["bash", "-c", f"(sleep 2) | nc -w 4 {ip} {port}"], capture_output=True, timeout=20)
        seen = bool(hits(events(t0), "connect", proxy, port))
        check(name, seen and p.stdout == want, f"{proxy} connect={seen}; client got {p.stdout[:40]!r}")
    banner("B2 SOCKS5 reply in IPv6 form + immediate banner", "192.0.2.10", 80, "socks1081", b"SSH-2.0-pbtest\r\n")
    banner("B1 HTTP 200 with a banner glued to the headers", "192.0.2.20", 22, "http8080", b"SSH-2.0-pbtest\r\n")
    banner("B1 HTTP 407 with '200' in its headers is not success", "192.0.2.21", 22, "http8080", b"")


def hostnames(mode="on"):
    print(f"\n== hostnames (mode={mode}) ==")
    flush_dns_cache()
    off = set(mode[3:].split(",")) if mode.startswith("off") else set()
    def dest_of(proxy, port, cmd):
        t0 = time.time()
        run(cmd, 40)
        time.sleep(1.0)
        h = hits(events(t0), "connect", proxy, port)
        return h[-1]["dest"] if h else None
    def expect(name, proxy, port, cmd, host, want_name):
        got = dest_of(proxy, port, cmd)
        if want_name:
            check(name, got == host, f"{proxy} received {got!r} (want the name {host!r})")
        else:
            check(name, bool(got) and got != host and got.replace(".", "").isdigit(), f"{proxy} received {got!r} (want an IP)")
    c = ["curl", "-s", "-o", "/dev/null", "-m", "25"]
    expect("D1 example.com via SOCKS5 1080", "socks1080", 443, c + ["https://example.com"], "example.com", "1080" not in off)
    expect("D2 example.org via HTTP 8080", "http8080", 80, c + ["http://example.org"], "example.org", "8080" not in off)
    expect("D3 example.net via HTTP+auth 8081", "http8081", 80, c + ["http://example.net"], "example.net", "8081" not in off)
    got = dest_of("socks1081", 80, ["bash", "-c", "(sleep 2) | nc -w 3 192.0.2.10 80"])
    check("D4 address with no DNS record is sent as an IP", got == "192.0.2.10", f"socks1081 received {got!r}")


def stress():
    print("\n== stress ==")
    subprocess.run([PBUDP, "flood", "300", "2"], capture_output=True)        # warm-up
    time.sleep(8)
    for i in (1, 2, 3):
        base = snap(); t0 = time.time()
        subprocess.run([PBUDP, "flood", "300", "3"], capture_output=True, timeout=120)
        time.sleep(8)
        evs = events(t0)
        opened, closed = len(hits(evs, "udp_assoc_open", "socks1080")), len(hits(evs, "udp_assoc_close", "socks1080"))
        after = snap()
        check(f"S2.{i} 300 UDP flows opened and closed, memory flat", opened >= 295 and closed >= 295 and after[0] - base[0] < 8,
              f"opened={opened} closed={closed} RSS {base[0]:.1f}->{after[0]:.1f}MB")
    base = snap(); peak = [0.0]; stop = threading.Event()
    def sampler():
        while not stop.is_set():
            s = snap(); peak[0] = max(peak[0], s[1] if s else 0); time.sleep(0.3)
    th = threading.Thread(target=sampler); th.start(); t0 = time.time()
    sc = "curl -s -o /dev/null -m 20 -w '%{http_code}\\n' https://example.com"
    p = subprocess.run(["bash", "-c", f"seq 300 | xargs -P 30 -I{{}} {sc}"], capture_output=True, text=True, timeout=400)
    stop.set(); th.join()
    n = sum(x.startswith(("2", "3")) for x in p.stdout.split()); time.sleep(8); after = snap()
    closed = [e for e in events(t0) if e["kind"] == "tcp_closed" and e["proxy"] == "socks1080"]
    check("S1 300 parallel TCP flows", n >= 295 and bool(closed) and closed[-1]["active"] == 0,
          f"{n}/300 ok, peak CPU {peak[0]:.0f}%, RSS {base[0]:.1f}->{after[0]:.1f}MB, proxy-side open at end={closed[-1]['active'] if closed else None}")


def dns():
    print("\n== dns ==")
    def look(i):
        name = f"10-{random.randint(1, 250)}-{random.randint(1, 250)}-{i % 250 + 1}.sslip.io"   # sslip.io answers any such name
        try:
            return socket.gethostbyname(name) == name.replace(".sslip.io", "").replace("-", ".")
        except OSError:
            return False
    base = snap()
    with cf.ThreadPoolExecutor(8) as ex:
        res = list(ex.map(look, range(200)))
    time.sleep(3)
    check("D5 200 uncached DNS lookups (8 parallel) all correct", sum(res) >= 198, f"{sum(res)}/200 correct, extension {base} -> {snap()}")


def idle():
    print("\n== idle UDP reaper (about 2.5 minutes) ==")
    t0 = time.time()
    proc = subprocess.Popen([PBUDP, "flood", "40", "170"], stdout=subprocess.DEVNULL)   # 40 flows held open and silent
    time.sleep(6)
    opened = len(hits(events(t0), "udp_assoc_open", "socks1080"))
    first = None
    while time.time() - t0 < 150:
        c = hits(events(t0), "udp_assoc_close", "socks1080")
        if len(c) >= opened - 1:
            first = c[0]["t"] - t0
            break
        time.sleep(2)
    proc.terminate()
    c = hits(events(t0), "udp_assoc_close", "socks1080")
    check("S3 idle UDP flows are reaped while the app still holds the sockets", opened >= 38 and len(c) >= opened - 1,
          f"opened={opened} reaped={len(c)}" + (f", first at ~{first:.0f}s" if first else ""))


def leaks():
    print("\n== leaks ==")
    sudo = sudo_prefix()
    if not sudo:
        print("SKIP leaks: run `sudo -v` first (or set SUDO_ASKPASS) so sudo does not prompt")
        return
    # leaks freezes the extension for several seconds while it scans, so this suite runs last
    out = subprocess.run(sudo + ["leaks", str(ext_pid())], capture_output=True, text=True).stdout
    line = next((l for l in out.splitlines() if "leaks for" in l), "")
    check("L1 leaks reports 0 leaks in the extension", " 0 leaks for 0 total leaked bytes" in line, line.strip() or "no result")


def cli():
    print("\n== command line mode ==")
    app = "/Applications/ProxyBridge.app/Contents/MacOS/ProxyBridge"
    if not os.path.exists(app):
        print("SKIP cli: /Applications/ProxyBridge.app is not installed"); return
    if subprocess.run(["pgrep", "-x", "ProxyBridge"], capture_output=True).returncode == 0:
        print("SKIP cli: quit the ProxyBridge app first, the CLI refuses to run next to it"); return
    v = subprocess.run([app, "--cli", "--version"], capture_output=True, text=True)
    check("C1 --version", v.returncode == 0 and v.stdout.startswith("ProxyBridge CLI "), v.stdout.strip() or v.stderr.strip())
    bad = subprocess.run([app, "--cli", "--bogus"], capture_output=True, text=True)
    check("C2 unknown option exits with 2 and a message", bad.returncode == 2 and "Unknown option" in bad.stderr, f"exit {bad.returncode}")
    profile = open(os.path.join(HERE, "pbtest.pbprofile")).read()
    proc = subprocess.Popen([app, "--cli", "--profile", "-", "--verbose", "3"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    proc.stdin.write(profile); proc.stdin.close()
    lines, ready = [], False
    t_end = time.time() + 120          # the first run can wait for the extension to be approved
    while time.time() < t_end and proc.poll() is None:
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.rstrip())
        if "Redirecting traffic" in line:
            ready = True; break
    check("C3 profile applied and redirecting", ready, " | ".join(lines[-4:]))
    if not ready:
        proc.terminate(); return
    time.sleep(2)
    scenario("C4 curl example.com goes through SOCKS5 1080 while the CLI runs", CURL + ["https://example.com"], ("connect", "socks1080", 443), client_ok=HTTP_OK)
    scenario("C5 BLOCK rule is enforced (openssl)", ["openssl", "s_client", "-connect", "example.net:443"], ("connect", None, None), timeout=15, inp=b"",
             client_ok=lambda rc, o, e: b"BEGIN CERTIFICATE" not in o)
    second = subprocess.run([app, "--cli", "--profile", "-"], input=profile, capture_output=True, text=True, timeout=30)
    check("C6 a second CLI is refused", second.returncode != 0 and "already running" in second.stderr, second.stderr.strip()[:80])
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=20); out = proc.stdout.read()
    except subprocess.TimeoutExpired:
        proc.kill(); out = ""
    check("C7 Ctrl+C stops it cleanly", proc.returncode == 0 and "Rules cleared" in "\n".join(lines) + out, f"exit {proc.returncode}")
    time.sleep(1)
    scenario("C8 after Ctrl+C curl example.com is no longer redirected", CURL + ["https://example.com"], ("connect", None, None), client_ok=HTTP_OK)


SUITES = {"cli": cli, "functional": functional, "replies": replies, "hostnames": hostnames, "stress": stress, "dns": dns, "idle": idle, "leaks": leaks}
DEFAULT = ["functional", "replies", "hostnames", "stress", "dns", "leaks"]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "-h" in sys.argv or "--help" in sys.argv:
        print(__doc__); return 0
    wanted = args or DEFAULT[:]
    if "--slow" in sys.argv and "idle" not in wanted:
        wanted.append("idle")
    for w in wanted:
        if w.split(":")[0] not in SUITES:
            sys.exit(f"unknown suite {w!r}, see --help")
    build_pbudp()
    start_servers()
    # every suite but `cli` needs the test rules already active (imported in the app). `cli` activates them itself
    if any(w.split(":")[0] != "cli" for w in wanted):
        preflight()
    print("extension:", ext_pid(), snap())
    for w in wanted:
        name, _, arg = w.partition(":")
        SUITES[name](arg) if arg else SUITES[name]()
    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)}/{len(results)} passed")
    for n, _, d in bad:
        print("  FAILED:", n, "-", d)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
