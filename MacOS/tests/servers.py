#!/usr/bin/env python3
"""Local proxies the ProxyBridge macOS tests talk to. Loopback only, logs every event as
one JSON line to $PB_EVENTS (default: work/events.log next to this file).

  socks5  127.0.0.1:1080  no auth      (TCP CONNECT + UDP ASSOCIATE)
  socks5  127.0.0.1:1081  user/pass    (pbtest / pbpass)
  socks5  127.0.0.1:1082  black hole   (accepts, never answers)
  http    127.0.0.1:8080  no auth      (CONNECT)
  http    127.0.0.1:8081  user/pass    (pbtest / pbpass)

Special destinations (documentation addresses, nothing is really contacted):
  192.0.2.10:80  via socks5 1081  reply uses the 22 byte IPv6 address form and a banner right behind it
  192.0.2.20:22  via http   8080  "200" reply with a banner glued to the headers
  192.0.2.21:22  via http   8080  407 whose headers contain "200" (must not count as success)
"""
import asyncio, base64, json, os, socket, struct, time

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.environ.get("PB_EVENTS", os.path.join(HERE, "work", "events.log"))
USER, PASS = "pbtest", "pbpass"
BANNER = b"SSH-2.0-pbtest\r\n"
active = {"tcp": 0, "udp_assoc": 0}


def ev(kind, **kw):
    kw.update(t=round(time.time(), 3), kind=kind)
    with open(LOG, "a") as f:
        f.write(json.dumps(kw) + "\n")


async def pipe(r, w):
    # on EOF only half-close the other side, both ends are closed once both directions end
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
        if w.can_write_eof():
            w.write_eof()
    except Exception:
        pass


async def splice(cr, cw, ur, uw):
    try:
        await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
    finally:
        for w in (cw, uw):
            try:
                w.close()
            except Exception:
                pass


# ---------------- SOCKS5 ----------------
class UDPRelay(asyncio.DatagramProtocol):
    def __init__(self, name):
        self.name, self.client, self.transport = name, None, None
        self.up, self.down = 0, 0

    def connection_made(self, t):
        self.transport = t

    def datagram_received(self, data, addr):
        if addr[0] == "127.0.0.1" and (self.client is None or addr == self.client) and len(data) > 10 and data[2] == 0:
            self.client = addr
            atyp = data[3]
            if atyp == 1:
                host, port, off = socket.inet_ntoa(data[4:8]), struct.unpack("!H", data[8:10])[0], 10
            elif atyp == 3:
                n = data[4]
                host, port, off = data[5:5 + n].decode(), struct.unpack("!H", data[5 + n:7 + n])[0], 7 + n
            elif atyp == 4:
                host, port, off = socket.inet_ntop(socket.AF_INET6, data[4:20]), struct.unpack("!H", data[20:22])[0], 22
            else:
                return
            self.up += 1
            if self.up == 1:
                ev("udp_pkt", proxy=self.name, dest=host, port=port)
            try:
                self.transport.sendto(data[off:], (host, port))
            except Exception:
                pass
        elif self.client:
            # a reply from a remote peer, wrap it and hand it back to the client
            self.down += 1
            hdr = b"\x00\x00\x00\x01" + socket.inet_aton(addr[0]) + struct.pack("!H", addr[1])
            self.transport.sendto(hdr + data, self.client)


async def socks_client(name, auth, blackhole, r, w):
    peer = w.get_extra_info("peername")
    ev("accept", proxy=name, src=peer[1])
    active["tcp"] += 1
    try:
        if blackhole:
            await r.read()
            ev("closed_by_peer", proxy=name, src=peer[1])
            return
        ver, n = await r.readexactly(2)
        methods = await r.readexactly(n)
        if auth:
            if 2 not in methods:
                w.write(b"\x05\xff")
                return
            w.write(b"\x05\x02")
            await w.drain()
            await r.readexactly(1)
            ul = (await r.readexactly(1))[0]; u = (await r.readexactly(ul)).decode()
            pl = (await r.readexactly(1))[0]; p = (await r.readexactly(pl)).decode()
            ok = (u, p) == (USER, PASS)
            w.write(b"\x01\x00" if ok else b"\x01\x01")
            await w.drain()
            ev("auth", proxy=name, ok=ok)
            if not ok:
                return
        else:
            w.write(b"\x05\x00")
            await w.drain()
        _, cmd, _, atyp = await r.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await r.readexactly(4))
        elif atyp == 3:
            host = (await r.readexactly((await r.readexactly(1))[0])).decode()
        else:
            host = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        port = struct.unpack("!H", await r.readexactly(2))[0]
        if cmd == 1 and (host, port) == ("192.0.2.10", 80):
            ev("connect", proxy=name, dest=host, port=port, special="ipv6-bnd+banner")
            w.write(b"\x05\x00\x00\x04" + b"\x00" * 16 + struct.pack("!H", 1080) + BANNER)
            await w.drain()
            await r.read()
            return
        if cmd == 1:
            ev("connect", proxy=name, dest=host, port=port)
            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            except Exception as e:
                ev("connect_failed", proxy=name, dest=host, port=port, err=str(e))
                w.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await w.drain()
            await splice(r, w, ur, uw)
        elif cmd == 3:
            relay = UDPRelay(name)
            # bound to all interfaces: a loopback-only socket can't send to the internet
            tr, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: relay, local_addr=("0.0.0.0", 0))
            bport = tr.get_extra_info("sockname")[1]
            active["udp_assoc"] += 1
            ev("udp_assoc_open", proxy=name, relay_port=bport, active=active["udp_assoc"])
            w.write(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", bport))
            await w.drain()
            await r.read()                       # the association lives as long as the control connection
            tr.close()
            active["udp_assoc"] -= 1
            ev("udp_assoc_close", proxy=name, up=relay.up, down=relay.down, active=active["udp_assoc"])
        else:
            w.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
    except Exception as e:
        ev("error", proxy=name, err=repr(e))
    finally:
        active["tcp"] -= 1
        ev("tcp_closed", proxy=name, src=peer[1], active=active["tcp"])
        try:
            w.close()
        except Exception:
            pass


# ---------------- HTTP CONNECT ----------------
async def http_client(name, auth, r, w):
    peer = w.get_extra_info("peername")
    ev("accept", proxy=name, src=peer[1])
    active["tcp"] += 1
    try:
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)
        lines = head.decode("latin1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
        if auth:
            exp = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
            ok = hdrs.get("proxy-authorization") == exp
            ev("auth", proxy=name, ok=ok)
            if not ok:
                w.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n")
                return
        if method != "CONNECT":
            w.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        host, port = target.rsplit(":", 1)
        host = host.strip("[]")
        ev("connect", proxy=name, dest=host, port=int(port))
        if (host, int(port)) == ("192.0.2.20", 22):
            w.write(b"HTTP/1.1 200 Connection established\r\n\r\n" + BANNER)
            await w.drain()
            await r.read()
            return
        if (host, int(port)) == ("192.0.2.21", 22):
            w.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 200\r\n\r\nSSH-2.0-should-not-arrive\r\n")
            await w.drain()
            await r.read()
            return
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 10)
        except Exception as e:
            ev("connect_failed", proxy=name, dest=host, port=int(port), err=str(e))
            w.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await w.drain()
        await splice(r, w, ur, uw)
    except Exception as e:
        ev("error", proxy=name, err=repr(e))
    finally:
        active["tcp"] -= 1
        ev("tcp_closed", proxy=name, src=peer[1], active=active["tcp"])
        try:
            w.close()
        except Exception:
            pass


async def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    open(LOG, "w").close()
    servers = [
        ("socks1080", 1080, lambda r, w: socks_client("socks1080", False, False, r, w)),
        ("socks1081", 1081, lambda r, w: socks_client("socks1081", True, False, r, w)),
        ("socks1082", 1082, lambda r, w: socks_client("socks1082", False, True, r, w)),
        ("http8080", 8080, lambda r, w: http_client("http8080", False, r, w)),
        ("http8081", 8081, lambda r, w: http_client("http8081", True, r, w)),
    ]
    started = [await asyncio.start_server(cb, "127.0.0.1", port) for _, port, cb in servers]
    print("proxies up:", ", ".join(f"{n}:{p}" for n, p, _ in servers), flush=True)
    await asyncio.gather(*(s.serve_forever() for s in started))


if __name__ == "__main__":
    asyncio.run(main())
