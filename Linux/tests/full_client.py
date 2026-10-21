#!/usr/bin/env python3
"""Client side of the full end-to-end suite (tests/e2e_full.sh). The client never knows whether ProxyBridge is running: the very
same scenarios run with the engine off and on, and the suite compares the results.

usage: full_client.py <scenario> [<scenario> ...]
  tcp     http get from two origins, 200 parallel and 400 sequential connections, request latency, a big download and a big upload
          with checksums
  udp     one socket to several destinations, connected socket, datagram sizes 1..59904 bytes, bound source port, 300 concurrent
          sockets, a 3000 datagrams/s stream (loss), round-trip time
  dns     real DNS packets (A query, NXDOMAIN, 200 parallel queries, queries over TCP, queries per second)
  quic    QUIC long-header packets (RFC 9000 Version Negotiation): the datagram shape of HTTP/3, 1200 bytes, connection ids mirrored
  load    500 parallel TCP connections, 1000 concurrent UDP sockets (LOAD_UDP), 20000 small UDP datagrams back to back
  churn   what a resolver does: a new UDP socket per lookup, CHURN_N (700) times in a row
  newflow latency of the first datagram of brand-new UDP flows (echo and DNS port)
  udpblock  one datagram that a BLOCK rule must stop: no reply may arrive

Output: "RESULT ok|BAD <name> | <detail>", "METRIC <name> <value>", "INFO <text>". Environment: DL_MB (default 100), UL_MB (50),
STREAM_N (6000), the origin addresses are fixed (see tests/nexus_origins.py and tests/full_quic_server.py).
"""
import concurrent.futures as cf
import hashlib, os, random, socket, struct, sys, threading, time

O1, O2, DNSIP = "10.77.1.1", "10.77.1.2", "10.77.1.53"
BLOCK = bytes((i * 7 + 13) & 255 for i in range(1 << 20))
DL_MB = int(os.environ.get("DL_MB", "100"))
UL_MB = int(os.environ.get("UL_MB", "50"))
STREAM_N = int(os.environ.get("STREAM_N", "6000"))
# Every proxied UDP socket holds one TCP control connection to the proxy until its session expires. Stock Nexus Proxy resets
# connections beyond 500 per source address (tests/e2e_full.sh raises that in its private copy); ProxyBridge itself allows 2048
# UDP sessions per process.
LOAD_UDP = int(os.environ.get("LOAD_UDP", "1000"))


def res(name, ok, detail=""):
    print("RESULT", "ok" if ok else "BAD", name, "|", detail, flush=True)      # the suite compares names, not details


def metric(name, value):
    print("METRIC", name, value, flush=True)


def info(text):
    print("INFO", text, flush=True)


def pattern_sha(mb):
    h = hashlib.sha256()
    for _ in range(mb):
        h.update(BLOCK)
    return h.hexdigest()


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


# ------------------------------------------------------------------ TCP
def http_get(ip, port, path="/", timeout=15):
    s = socket.create_connection((ip, port), timeout=timeout)
    try:
        s.sendall(("GET %s HTTP/1.0\r\nHost: x\r\n\r\n" % path).encode())
        data = b""
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
        return data.split(b"\r\n\r\n", 1)[-1]
    finally:
        s.close()


def tcp():
    res("tcp: origin 1 answers", http_get(O1, 18700) == b"origin-1\n")
    res("tcp: origin 2 answers", http_get(O2, 18700) == b"origin-2\n")

    def one(_):
        try:
            return http_get(O1, 18700) == b"origin-1\n"
        except OSError:
            return False
    with cf.ThreadPoolExecutor(64) as ex:
        okc = sum(ex.map(one, range(200)))
    res("tcp: 200 parallel connections", okc == 200, "%d/200" % okc)
    t0 = time.perf_counter()
    okc = sum(one(i) for i in range(400))
    res("tcp: 400 sequential connect/request/close cycles", okc == 400, "%d/400" % okc)
    metric("tcp_cycles_per_s", round(400 / (time.perf_counter() - t0)))
    lat = []
    for _ in range(200):
        t = time.perf_counter()
        http_get(O1, 18700)
        lat.append((time.perf_counter() - t) * 1000)
    metric("tcp_request_p50_ms", round(pct(lat, .5), 2))
    metric("tcp_request_p99_ms", round(pct(lat, .99), 2))

    # big download with a checksum of the received stream
    s = socket.create_connection((O1, 18700), timeout=60)
    s.sendall(("GET /big?mb=%d HTTP/1.0\r\n\r\n" % DL_MB).encode())
    t0 = time.perf_counter()
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(65536)
    head, _, rest = buf.partition(b"\r\n\r\n")
    h = hashlib.sha256(rest)
    got = len(rest)
    while True:
        d = s.recv(1 << 20)
        if not d:
            break
        h.update(d)
        got += len(d)
    dt = time.perf_counter() - t0
    s.close()
    res("tcp: %d MB download, checksum identical" % DL_MB, got == DL_MB << 20 and h.hexdigest() == pattern_sha(DL_MB), "%d bytes" % got)
    metric("tcp_download_MBps", round(DL_MB / dt))

    # big upload; the origin answers with the sha256 of what it received
    s = socket.create_connection((O2, 18700), timeout=60)
    s.sendall(("POST /upload HTTP/1.0\r\nContent-Length: %d\r\n\r\n" % (UL_MB << 20)).encode())
    t0 = time.perf_counter()
    for _ in range(UL_MB):
        s.sendall(BLOCK)
    dt = time.perf_counter() - t0
    ans = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        ans += d
    s.close()
    res("tcp: %d MB upload, origin received identical bytes" % UL_MB, ans.split(b"\r\n\r\n", 1)[-1].decode() == pattern_sha(UL_MB))
    metric("tcp_upload_MBps", round(UL_MB / dt))


# ------------------------------------------------------------------ UDP
def usock(t=4.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(t)
    return s


def udp():
    s = usock()
    for dst, tag in (((O1, 18710), b"U1:"), ((O2, 18710), b"U2:"), ((O1, 18710), b"U1:")):
        try:
            s.sendto(b"hello", dst)
            d, a = s.recvfrom(100)
            res("udp: one socket, destination %s:%d" % dst, d == tag + b"hello" and a == dst, "from %s:%d" % a)
        except OSError as e:
            res("udp: one socket, destination %s:%d" % dst, False, str(e))
    c = usock()
    c.connect((O1, 18711))
    try:
        c.send(b"conn")
        d = c.recv(100)
        res("udp: connected socket, peer address restored", d == b"U3:conn" and c.getpeername() == (O1, 18711), "peer %s:%d" % c.getpeername())
    except OSError as e:
        res("udp: connected socket, peer address restored", False, str(e))
    for n in (1, 100, 1200, 1472, 8000, 30000, 59904):
        b = usock(8)
        payload = bytes((i * 31 + n) & 255 for i in range(n))
        try:
            b.sendto(payload, (O1, 18710))
            d, a = b.recvfrom(70000)
            res("udp: datagram of %d bytes" % n, d == b"U1:" + payload)
        except OSError as e:
            res("udp: datagram of %d bytes" % n, False, str(e))
    port = random.randint(41000, 49000)
    b = usock()
    b.bind(("0.0.0.0", port))
    try:
        b.sendto(b"bound", (O1, 18710))
        d, a = b.recvfrom(100)
        res("udp: socket bound to a chosen source port gets the reply", d == b"U1:bound" and b.getsockname()[1] == port, "port %d" % port)
    except OSError as e:
        res("udp: socket bound to a chosen source port", False, str(e))

    def one(i):
        k = usock(8)
        dst = (("10.77.1.%d" % (1 + i % 2)), 18710)
        try:
            k.sendto(b"n%d" % i, dst)
            d, a = k.recvfrom(100)
            return d.endswith(b"n%d" % i) and a == dst
        except OSError:
            return False
        finally:
            k.close()
    with cf.ThreadPoolExecutor(32) as ex:
        okc = sum(ex.map(one, range(300)))
    res("udp: 300 concurrent sockets across two destinations (99% or better)", okc >= 297, "%d/300" % okc)   # UDP is lossy by nature

    # sustained stream, replies counted while still sending
    q = usock(1)
    q.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    got, stop = set(), threading.Event()

    def rx():
        q.settimeout(0.2)
        while not stop.is_set():
            try:
                d, _ = q.recvfrom(2000)
                got.add(int.from_bytes(d[3:7], "big"))
            except socket.timeout:
                pass
    th = threading.Thread(target=rx, daemon=True)
    th.start()
    t0 = time.perf_counter()
    for i in range(STREAM_N):
        q.sendto(i.to_bytes(4, "big") + b"x" * 996, (O1, 18710))
        while time.perf_counter() < t0 + (i + 1) / 3000.0:
            time.sleep(0)
    sent_for = time.perf_counter() - t0
    time.sleep(2)
    stop.set()
    th.join()
    loss = 100.0 * (STREAM_N - len(got)) / STREAM_N
    res("udp: stream of %d datagrams at 3000/s, loss <= 1%%" % STREAM_N, loss <= 1.0, "%.2f%% lost" % loss)
    metric("udp_stream_loss_pct", round(loss, 2))
    metric("udp_stream_send_pps", round(STREAM_N / sent_for))

    # fire and forget: one datagram per socket, the socket is closed at once. The engine looks at the sender only after the datagram
    # arrived, by then the socket is gone: the datagram must still be delivered.
    tag = os.urandom(4).hex()
    for i in range(50):
        k = usock()
        k.sendto(("FF:%s:%d" % (tag, i)).encode(), (O1, 4434))
        k.close()
    time.sleep(1.5)
    q2 = usock(3)
    try:
        q2.sendto(("COUNT:%s" % tag).encode(), (O1, 4434))
        got_ff = int(q2.recvfrom(100)[0])
    except (OSError, ValueError):
        got_ff = -1
    res("udp: 50 fire-and-forget datagrams (socket closed right after sending) all arrive", got_ff == 50, "%d/50" % got_ff)

    rtt = []
    r = usock(2)
    for _ in range(1000):
        t = time.perf_counter()
        r.sendto(b"p", (O1, 18710))
        r.recvfrom(100)
        rtt.append((time.perf_counter() - t) * 1e6)
    metric("udp_rtt_p50_us", round(pct(rtt, .5)))
    metric("udp_rtt_p99_us", round(pct(rtt, .99)))
    res("udp: 1000 round trips", True)


# ------------------------------------------------------------------ DNS
def dns_query(name, qtype=1, txid=None):
    txid = random.randint(0, 65535) if txid is None else txid
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return txid, q + b"\0" + struct.pack("!HH", qtype, 1)


def skip_name(m, off):
    while True:
        l = m[off]
        if l == 0:
            return off + 1
        if l & 0xC0 == 0xC0:
            return off + 2
        off += 1 + l


def dns_answer(m, txid):
    """(rcode, [ipv4 strings]) of a response, or None when it is not the answer to txid."""
    if len(m) < 12 or struct.unpack("!H", m[:2])[0] != txid:
        return None
    flags, qd, an = struct.unpack("!HHH", m[2:8])
    off = 12
    for _ in range(qd):
        off = skip_name(m, off) + 4
    ips = []
    for _ in range(an):
        off = skip_name(m, off)
        t, _, _, rl = struct.unpack("!HHIH", m[off:off + 10])
        off += 10
        if t == 1 and rl == 4:
            ips.append(socket.inet_ntoa(m[off:off + 4]))
        off += rl
    return flags & 0xF, ips


def dns_udp(name, timeout=4):
    txid, q = dns_query(name)
    s = usock(timeout)
    try:
        s.sendto(q, (DNSIP, 53))
        m, _ = s.recvfrom(4096)
        return dns_answer(m, txid)
    except OSError:
        return None
    finally:
        s.close()


def dns_tcp(name):
    txid, q = dns_query(name)
    s = socket.create_connection((DNSIP, 53), timeout=5)
    try:
        s.sendall(struct.pack("!H", len(q)) + q)
        n = struct.unpack("!H", s.recv(2))[0]
        m = b""
        while len(m) < n:
            m += s.recv(n - len(m))
        return dns_answer(m, txid)
    except OSError:
        return None
    finally:
        s.close()


def dns():
    r = dns_udp("app.example.test")
    res("dns: UDP A query app.example.test", r == (0, ["10.77.1.5"]), str(r))
    r = dns_udp("svc.corp.test")
    res("dns: UDP A query svc.corp.test", r == (0, ["10.77.1.6"]), str(r))
    r = dns_udp("does-not-exist.test")
    res("dns: UDP NXDOMAIN", r is not None and r[0] == 3, str(r))
    with cf.ThreadPoolExecutor(32) as ex:
        okc = sum(1 for x in ex.map(lambda i: dns_udp("app.example.test"), range(200)) if x == (0, ["10.77.1.5"]))
    res("dns: 200 parallel UDP queries (99% or better: a resolver retries)", okc >= 198, "%d/200" % okc)
    okc = sum(1 for _ in range(20) if dns_tcp("svc.corp.test") == (0, ["10.77.1.6"]))
    res("dns: 20 queries over TCP", okc == 20, "%d/20" % okc)
    lat, lost = [], 0
    for _ in range(500):
        t = time.perf_counter()
        if dns_udp("app.example.test", timeout=2) != (0, ["10.77.1.5"]):
            lost += 1
        lat.append((time.perf_counter() - t) * 1000)
    res("dns: 500 sequential UDP queries, none lost", lost == 0, "%d lost" % lost)
    metric("dns_udp_qps", round(500 / (sum(lat) / 1000)))
    metric("dns_udp_p99_ms", round(pct(lat, .99), 2))


# ------------------------------------------------------------------ QUIC-shaped UDP
def quic_initial(version=0x1a2a3a4a, size=1200):
    dcid, scid = os.urandom(8), os.urandom(8)
    pkt = bytes([0xC3]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00"
    body = os.urandom(size - len(pkt) - 2)
    pkt += struct.pack("!H", 0x4000 | len(body)) + body
    return dcid, scid, pkt


def vn_ok(reply, dcid, scid):
    if len(reply) < 7 or not reply[0] & 0x80 or struct.unpack("!I", reply[1:5])[0] != 0:
        return False
    dl = reply[5]
    if reply[6:6 + dl] != scid:                      # the reply's DCID is the client's SCID
        return False
    sl = reply[6 + dl]
    if reply[7 + dl:7 + dl + sl] != dcid:            # ... and its SCID is the client's DCID
        return False
    tail = reply[7 + dl + sl:]
    return len(tail) >= 4 and len(tail) % 4 == 0 and struct.pack("!I", 1) in [tail[i:i + 4] for i in range(0, len(tail), 4)]


def quic_once(dst, timeout=5):
    dcid, scid, pkt = quic_initial()
    s = usock(timeout)
    try:
        s.sendto(pkt, dst)
        d, a = s.recvfrom(2000)
        return a == dst and vn_ok(d, dcid, scid)
    except OSError:
        return False
    finally:
        s.close()


def quic():
    res("quic: 1200-byte Initial with an unknown version -> Version Negotiation", quic_once((O1, 4433)))
    res("quic: same to a second server", quic_once((O2, 4433)))
    with cf.ThreadPoolExecutor(32) as ex:
        okc = sum(ex.map(lambda i: quic_once((("10.77.1.%d" % (1 + i % 2)), 4433)), range(100)))
    res("quic: 100 parallel handshakes (Version Negotiation each, 99% or better)", okc >= 99, "%d/100" % okc)
    s = usock()
    okc = 0
    for i in range(20):                                # one socket, many packets, both servers: 5-tuple stays stable
        dcid, scid, pkt = quic_initial()
        s.sendto(pkt, (("10.77.1.%d" % (1 + i % 2)), 4433))
        try:
            d, _ = s.recvfrom(2000)
            okc += vn_ok(d, dcid, scid)
        except OSError:
            pass
    res("quic: one socket, 20 packets to two servers", okc == 20, "%d/20" % okc)
    s.sendto(b"not quic at all", (O1, 4433))
    try:
        d, _ = s.recvfrom(100)
        res("quic: a non-QUIC datagram reaches the server unchanged", d == b"NOTQUIC" + b"not quic", d[:20].decode("latin1"))
    except OSError as e:
        res("quic: a non-QUIC datagram reaches the server unchanged", False, str(e))
    dcid, scid, pkt = quic_initial(version=1)
    s.sendto(pkt, (O2, 4433))
    try:
        d, _ = s.recvfrom(100)
        res("quic: a version 1 Initial reaches the server unchanged", d.startswith(b"NOTQUIC") and d[7:] == pkt[:8])
    except OSError as e:
        res("quic: a version 1 Initial reaches the server unchanged", False, str(e))


# ------------------------------------------------------------------ load
def load():
    def one(_):
        try:
            return http_get(O1, 18700, timeout=30) == b"origin-1\n"
        except OSError:
            return False
    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(128) as ex:
        okc = sum(ex.map(one, range(500)))
    res("load: 500 TCP connections, 128 at a time", okc == 500, "%d/500 in %.1fs" % (okc, time.perf_counter() - t0))
    socks = []
    got = 0
    try:
        for i in range(LOAD_UDP):
            k = usock(10)
            socks.append(k)
            k.sendto(b"u%d" % i, ((("10.77.1.%d" % (1 + i % 2)), 18710)))
        for i, k in enumerate(socks):
            try:
                d, _ = k.recvfrom(100)
                got += d.endswith(b"u%d" % i)
            except OSError:
                pass
    finally:
        for k in socks:
            k.close()
    res("load: %d UDP sockets open at once, each answered" % LOAD_UDP, got >= 0.99 * LOAD_UDP, "%d/%d" % (got, LOAD_UDP))
    # one socket sends small datagrams at a fixed rate; the answers are counted while it is still sending
    def burst(n, pps):
        q = usock(1)
        q.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        seen, stop = set(), threading.Event()

        def rx():
            q.settimeout(0.2)
            while not stop.is_set():
                try:
                    d, _ = q.recvfrom(2000)
                    seen.add(int.from_bytes(d[3:7], "big"))
                except socket.timeout:
                    pass
        th = threading.Thread(target=rx, daemon=True)
        th.start()
        t0 = time.perf_counter()
        for i in range(n):
            q.sendto(i.to_bytes(4, "big") + b"y" * 60, (O1, 18710))
            while time.perf_counter() < t0 + (i + 1) / pps:
                time.sleep(0)
        time.sleep(2)
        stop.set()
        th.join()
        q.close()
        return 100.0 * (n - len(seen)) / n
    for pps in (3000, 6000, 12000):
        loss = burst(10000, pps)
        metric("udp_burst_%d_pps_loss_pct" % pps, round(loss, 2))
        if pps == 3000:
            res("load: 10000 small UDP datagrams at 3000/s, loss <= 2%", loss <= 2.0, "%.2f%% lost" % loss)
        else:
            info("%d datagrams/s: %.2f%% lost (reported, not a pass/fail line: a single-threaded Node proxy saturates)" % (pps, loss))


def newflow():
    """Latency of the FIRST datagram of a brand-new UDP flow (new socket each time): for a proxied flow this includes the SOCKS5
    UDP ASSOCIATE. Echo port and DNS port are measured separately because port 53 takes its own path in the engine."""
    for label, dst, payload in (("echo", (O1, 18710), b"x"), ("dns", (DNSIP, 53), None)):
        lat, fails = [], 0
        for _ in range(60):
            s = usock(3)
            try:
                if payload is None:
                    txid, q = dns_query("app.example.test")
                    msg = q
                else:
                    msg = payload
                t = time.perf_counter()
                s.sendto(msg, dst)
                s.recvfrom(2000)
                lat.append((time.perf_counter() - t) * 1000)
            except OSError:
                fails += 1
            finally:
                s.close()
        if lat:
            metric("newflow_%s_p50_ms" % label, round(pct(lat, .5), 2))
            metric("newflow_%s_p99_ms" % label, round(pct(lat, .99), 2))
        res("newflow: first datagram of 60 new %s flows answered" % label, fails == 0, "%d lost" % fails)


def churn():
    """What a resolver does: a new UDP socket per lookup, one query, close. Every proxied UDP socket keeps a session (and a TCP
    control connection to the proxy) until it has been idle for the UDP idle timeout (60 s by default), so this piles up sessions."""
    n = int(os.environ.get("CHURN_N", "700"))
    lost, first_lost, t0 = 0, None, time.perf_counter()
    for i in range(n):
        if dns_udp("app.example.test", timeout=2) != (0, ["10.77.1.5"]):
            lost += 1
            first_lost = i if first_lost is None else first_lost
    dt = time.perf_counter() - t0
    res("churn: %d lookups, each on a new UDP socket" % n, lost == 0, "%d lost%s" % (lost, "" if first_lost is None else ", first at #%d" % first_lost))
    metric("churn_lookups_per_s", round(n / dt))


def udpblock():
    s = usock(2.5)
    try:
        s.sendto(b"should-not-arrive", (O1, 18710))
        s.recvfrom(100)
        res("udp blocked: nothing may come back", False, "a reply arrived")
    except (socket.timeout, OSError):
        res("udp blocked: nothing may come back", True)


SCENARIOS = {"tcp": tcp, "udp": udp, "dns": dns, "quic": quic, "load": load, "udpblock": udpblock, "newflow": newflow, "churn": churn}

if __name__ == "__main__":
    names = sys.argv[1:] or ["tcp", "udp", "dns", "quic"]
    for n in names:
        if n not in SCENARIOS:
            print("unknown scenario", n, file=sys.stderr)
            sys.exit(2)
    for n in names:
        try:
            SCENARIOS[n]()
        except Exception as e:                               # a crashed scenario is a failure, not a silent skip
            res("%s: scenario crashed" % n, False, "%s: %s" % (type(e).__name__, e))
