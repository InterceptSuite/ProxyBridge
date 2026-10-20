#!/usr/bin/env python3
"""Client side of the UDP tests (ProxyBridge redirects these sockets). One scenario per run, one RESULT line per check.

usage: udp_probe.py <scenario> [args]
  echo <ip> <port> <payload> [wait_s]     one datagram, prints RESULT REPLY <peer> <text> | RESULT NOREPLY
  seq <ip> <port> <p1> <p2> ...           datagrams one after the other (new association after the proxy dropped one), 1 s apart
  multi <base-ip> <n> <port>              ONE unconnected socket talks to n destinations; replies must come from the right peers
  connected <ip> <port>                   connect()ed socket: send/recv without addresses
  many <ip> <port> <n>                    n sockets at once, all must get their own reply
  sizes <ip> <port>                       payloads from 1 byte to 60000 bytes
  boundport <ip> <port>                   socket bound to a chosen local port; the reply must come back to it
  v6connected <ip6> <port>                connect()ed IPv6 socket
  v6unconnected <ip6> <port>              sendto() on an IPv6 socket: the kernel cannot redirect it, ProxyBridge fails it closed
  blocked <ip> <port>                     sendto() that a BLOCK rule must refuse
"""
import errno, random, select, socket, sys, time

def check(name, ok, detail=""):
    print("RESULT", "ok" if ok else "BAD", name, detail, flush=True)

def udp(family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(4)
    return s

sc = sys.argv[1]
a = sys.argv[2:]

if sc == "echo":
    s = udp(); wait = float(a[3]) if len(a) > 3 else 3
    s.settimeout(wait)
    try:
        s.sendto(a[2].encode(), (a[0], int(a[1])))
        d, peer = s.recvfrom(70000)
        print("RESULT REPLY %s:%d %s" % (peer[0], peer[1], d.decode("latin1")))
    except socket.timeout:
        print("RESULT NOREPLY")
    except OSError as e:
        print("RESULT ERROR", e.errno)
elif sc == "seq":
    s = udp(); s.settimeout(2.5)
    for p in a[2:]:
        try:
            s.sendto(p.encode(), (a[0], int(a[1])))
            d, peer = s.recvfrom(70000)
            print("RESULT REPLY %s:%d %s" % (peer[0], peer[1], d.decode("latin1")), flush=True)
        except socket.timeout:
            print("RESULT NOREPLY", flush=True)
        time.sleep(1)
elif sc == "multi":
    base, n, port = a[0], int(a[1]), int(a[2])
    s = udp()
    prefix = base.rsplit(".", 1)[0]; first = int(base.rsplit(".", 1)[1])
    dsts = ["%s.%d" % (prefix, first + i) for i in range(n)]
    for d in dsts:
        s.sendto(("to-" + d).encode(), (d, port))
    got = {}
    for _ in dsts:
        data, peer = s.recvfrom(2048)
        got[peer[0]] = data.decode()
    check("every destination answered from its own address", sorted(got) == sorted(dsts), str(sorted(got)))
    check("replies match their requests", all(got[d].endswith("to-" + d) and (" %s:%d " % (d, port)) in got[d] for d in dsts if d in got))
elif sc == "connected":
    s = udp(); s.connect((a[0], int(a[1])))
    s.send(b"conn-1"); d1 = s.recv(2048)
    s.send(b"conn-2"); d2 = s.recv(2048)
    check("connected socket gets both replies", d1.endswith(b"conn-1") and d2.endswith(b"conn-2"), d2.decode())
    check("getpeername shows the real destination", s.getpeername() == (a[0], int(a[1])), str(s.getpeername()))
elif sc == "many":
    n = int(a[2])
    socks = []
    for i in range(n):
        s = udp(); s.settimeout(8)
        s.sendto(b"s%d" % i, (a[0], int(a[1])))
        socks.append(s)
    good = 0
    for i, s in enumerate(socks):
        try:
            d, _ = s.recvfrom(2048)
            good += d.endswith(b"s%d" % i)
        except socket.timeout:
            pass
    check("%d sockets, each got its own reply" % n, good == n, "%d/%d" % (good, n))
elif sc == "sizes":
    s = udp(); s.settimeout(6)
    bad = []
    for size in (1, 100, 512, 1400, 1472, 4000, 9000, 30000, 60000):
        payload = bytes(random.Random(size).randrange(33, 126) for _ in range(size))
        try:
            s.sendto(payload, (a[0], int(a[1])))
            d, _ = s.recvfrom(70000)
            if not d.endswith(payload):
                bad.append(size)
        except (socket.timeout, OSError):
            bad.append(size)
    check("payloads of 1..60000 bytes survive the round trip", not bad, "failed sizes: %s" % bad)
elif sc == "boundport":
    s = udp(); s.bind(("0.0.0.0", 0)); port = s.getsockname()[1]
    s.sendto(b"bound", (a[0], int(a[1])))
    d, _ = s.recvfrom(2048)
    check("reply arrives on the bound port", d.endswith(b"bound") and s.getsockname()[1] == port, "port %d" % port)
elif sc == "v6connected":
    s = udp(socket.AF_INET6); s.connect((a[0], int(a[1])))
    s.send(b"six")
    d = s.recv(2048)
    check("connected IPv6 UDP goes through the proxy", d.endswith(b"six") and a[0].encode() in d, d.decode())
elif sc == "v6unconnected":
    s = udp(socket.AF_INET6)
    try:
        s.sendto(b"six", (a[0], int(a[1])))
        check("unconnected IPv6 sendto fails closed", False, "it was sent")
    except OSError as e:
        # EPERM from ProxyBridge's hook, or ENETUNREACH when the host has no IPv6 route and the kernel refuses first
        check("unconnected IPv6 sendto fails closed", e.errno in (errno.EPERM, errno.EACCES, errno.ENETUNREACH), "errno %s" % e.errno)
elif sc == "blocked":
    s = udp()
    try:
        s.sendto(b"x", (a[0], int(a[1])))
        check("BLOCK refuses sendto", False, "it was sent")
    except OSError as e:
        check("BLOCK refuses sendto", e.errno in (errno.EPERM, errno.EACCES), "errno %s" % e.errno)
else:
    sys.exit(__doc__)
