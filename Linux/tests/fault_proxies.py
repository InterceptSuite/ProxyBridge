#!/usr/bin/env python3
"""Misbehaving upstream proxies for ProxyBridge's fault tests (never use these for anything else).

usage: fault_proxies.py <logfile>      listens on 127.0.0.1; the behaviour is chosen by the port that is asked for.

SOCKS5 19100 - by the requested destination port:
  9001-9008 reply code 1-8                 9010 BND is a domain name       9011 BND is IPv6          9012 BND of unknown type
  9013 close after the request             9014 never answers (stall)      9015 SOCKS4-style reply   9016 data, then close
  9017 sends 4 MiB of a known pattern      9018 echo server                9019 close right after the greeting
SOCKS5 greeting variants: 19101 method 0x01 (GSSAPI)  19102 no acceptable method  19103 asks for a login and rejects every one
                          19104 asks for a login (clients without credentials)    19105 accepts any login, then works as 19100
                          19106 works for CONNECT but refuses UDP ASSOCIATE
HTTP CONNECT 19110 - by the requested destination port:
  9021 403   9022 407   9023 502   9024 503   9025 301   9026 200 plus early data   9027 not HTTP   9028 close, no reply
  9029 stall   9030 200 then close   9031 headers in two segments   9032 oversized header block
SOCKS5 UDP ASSOCIATE 19120-19127 (control ports, each relays echoes "UDP-U <dst> <payload>"):
  19120 BND.ADDR 0.0.0.0   19121 BND is a domain   19122 BND is ::1   19123 SPOOF* replies come from a stranger
  19124 malformed replies by payload prefix (FRAG, DOM, SHORT, ZERO, OK)   19125 refuses the association
  19126 closes the control connection after the first datagram   19127 swallows datagrams
"""
import asyncio, socket, struct, sys

LOG = open(sys.argv[1], "a", buffering=1)
PATTERN = bytes((i * 7 + 3) & 0xFF for i in range(65536))
PATTERN_TOTAL = 4 << 20


def log(*a):
    LOG.write(" ".join(str(x) for x in a) + "\n")


async def read_addr(reader):
    atyp = (await reader.readexactly(1))[0]
    if atyp == 1:
        raw = await reader.readexactly(4)
    elif atyp == 4:
        raw = await reader.readexactly(16)
    else:
        n = (await reader.readexactly(1))[0]
        raw = await reader.readexactly(n)
    return atyp, raw, struct.unpack("!H", await reader.readexactly(2))[0]


def reply(rep, atyp=1, addr=b"\0\0\0\0", port=0):
    if atyp == 3:
        return bytes([5, rep, 0, 3, len(addr)]) + addr + struct.pack("!H", port)
    return bytes([5, rep, 0, atyp]) + addr + struct.pack("!H", port)


async def serve_socks(reader, writer, greeting):
    try:
        ver, n = await reader.readexactly(2)
        methods = await reader.readexactly(n)
        if greeting == "gssapi":
            writer.write(b"\x05\x01"); await writer.drain(); return
        if greeting == "none":
            writer.write(b"\x05\xff"); await writer.drain(); return
        if greeting in ("reject", "login", "any"):
            writer.write(b"\x05\x02"); await writer.drain()
            v, ul = await reader.readexactly(2)
            await reader.readexactly(ul)
            pl = (await reader.readexactly(1))[0]
            await reader.readexactly(pl)
            ok = greeting == "any"
            writer.write(b"\x01" + (b"\x00" if ok else b"\x01")); await writer.drain()
            log("AUTH", greeting, "accepted" if ok else "rejected", "userlen", ul, "passlen", pl)
            if not ok:
                return
        else:
            writer.write(b"\x05\x00"); await writer.drain()
        try:
            _v, cmd, _r = await reader.readexactly(3)
        except asyncio.IncompleteReadError:
            return                                    # 9019: the client gave up or we are meant to close here
        atyp, raw, port = await read_addr(reader)
        log("TCP" if cmd == 1 else "CMD%d" % cmd, port, "atyp", atyp)
        if greeting == "noudp" and cmd != 1:
            writer.write(reply(7)); await writer.drain(); return
        if port == 9019:
            return
        if 9001 <= port <= 9008:
            writer.write(reply(port - 9000)); await writer.drain(); return
        if port == 9013:
            return
        if port == 9014:
            await asyncio.sleep(60); return
        if port == 9015:
            writer.write(b"\x04\x5a\0\0\0\0\0\0"); await writer.drain(); return
        if port == 9010:
            writer.write(reply(0, 3, b"bnd.example.test", 1080))
        elif port == 9011:
            writer.write(reply(0, 4, b"\0" * 15 + b"\x01", 1080))
        elif port == 9012:
            writer.write(b"\x05\x00\x00\x09junkjunk"); await writer.drain(); return
        else:
            writer.write(reply(0, 1, b"\x7f\0\0\x01", 0))
        await writer.drain()
        if port == 9016:
            writer.write(b"partial"); await writer.drain(); return
        if port == 9017:
            sent = 0
            while sent < PATTERN_TOTAL:
                writer.write(PATTERN); sent += len(PATTERN)
                await writer.drain()
            return
        if port == 9018:
            while True:
                d = await reader.read(65536)
                if not d:
                    return
                writer.write(d); await writer.drain()
        data = await reader.read(65536)
        writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n" if data.startswith(b"GET") else b"echo:" + data)
        await writer.drain()
    except Exception as e:
        log("ERR", repr(e))
    finally:
        writer.close()


async def serve_http(reader, writer):
    try:
        head = await reader.readuntil(b"\r\n\r\n")
        first = head.split(b"\r\n")[0].decode()
        port = int(first.split()[1].rsplit(":", 1)[1])
        log("HTTP", port)
        statuses = {9021: b"403 Forbidden", 9022: b"407 Proxy Authentication Required", 9023: b"502 Bad Gateway",
                    9024: b"503 Service Unavailable", 9025: b"301 Moved Permanently"}
        if port in statuses:
            writer.write(b"HTTP/1.1 " + statuses[port] + b"\r\nContent-Length: 4\r\n\r\nnope"); await writer.drain(); return
        if port == 9027:
            writer.write(b"NOTHTTP garbage\r\n\r\n"); await writer.drain(); return
        if port == 9028:
            return
        if port == 9029:
            await asyncio.sleep(60); return
        if port == 9030:
            writer.write(b"HTTP/1.1 200 OK\r\n\r\n"); await writer.drain(); return
        if port == 9031:
            writer.write(b"HTTP/1.1 200 Connection"); await writer.drain()
            await asyncio.sleep(0.3)
            writer.write(b" established\r\n\r\n"); await writer.drain()
        elif port == 9032:
            writer.write(b"HTTP/1.1 200 OK\r\n" + b"X-Pad: " + b"a" * 20000 + b"\r\n\r\n"); await writer.drain(); return
        elif port == 9026:
            writer.write(b"HTTP/1.1 200 OK\r\n\r\nEARLY-DATA"); await writer.drain()
        else:
            writer.write(b"HTTP/1.1 200 OK\r\n\r\n"); await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), 5)
        writer.write(b"echo:" + data); await writer.drain()
    except Exception as e:
        log("ERR", repr(e))
    finally:
        writer.close()


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, mode):
        self.mode = mode

    def connection_made(self, transport):
        self.t = transport
        self.stranger = None

    def datagram_received(self, data, addr):
        if len(data) < 10 or data[2] != 0:
            return
        atyp = data[3]
        if atyp == 1:
            raw, off = data[4:8], 8
        elif atyp == 4:
            raw, off = data[4:20], 20
        else:
            n = data[4]; raw, off = data[5:5 + n], 5 + n
        port = struct.unpack("!H", data[off:off + 2])[0]
        payload = data[off + 2:]
        if atyp == 1:
            dst = socket.inet_ntoa(raw) + ":" + str(port)
        elif atyp == 4:
            dst = socket.inet_ntop(socket.AF_INET6, raw) + ":" + str(port)
        else:
            dst = raw.decode() + ":" + str(port)
        log("UDP", self.mode, dst, len(payload))
        if self.mode == "swallow":
            return
        head = data[:off + 2]
        echo = f"UDP-U {dst} ".encode() + payload
        if self.mode == "spoof" and payload.startswith(b"SPOOF"):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", 0)); s.sendto(head + echo, addr); s.close()
            return
        if self.mode == "malformed":
            if payload.startswith(b"FRAG"):
                self.t.sendto(b"\0\0\x01" + head[3:] + echo, addr); return
            if payload.startswith(b"DOM"):
                name = b"host.example"
                self.t.sendto(b"\0\0\0\x03" + bytes([len(name)]) + name + struct.pack("!H", port) + echo, addr); return
            if payload.startswith(b"SHORT"):
                self.t.sendto(b"\0\0\0", addr); return
            if payload.startswith(b"ZERO"):
                self.t.sendto(head, addr); return
        self.t.sendto(head + echo, addr)
        if self.mode == "dropctl":
            asyncio.get_running_loop().call_later(0.3, self.close_control)

    close_control = lambda self: None


def udp_control(mode, bind_ip="127.0.0.1"):
    async def handle(reader, writer):
        try:
            ver, n = await reader.readexactly(2)
            await reader.readexactly(n)
            writer.write(b"\x05\x00"); await writer.drain()
            _v, cmd, _r = await reader.readexactly(3)
            await read_addr(reader)
            if mode == "refuse" or cmd != 3:
                writer.write(reply(7)); await writer.drain(); return
            loop = asyncio.get_running_loop()
            relay_mode = {"dropctl": "dropctl", "spoof": "spoof", "malformed": "malformed", "swallow": "swallow"}.get(mode, "echo")
            fam = socket.AF_INET6 if mode == "ipv6" else socket.AF_INET
            sock = socket.socket(fam, socket.SOCK_DGRAM)
            sock.bind(("::1" if mode == "ipv6" else "127.0.0.1", 0))
            transport, proto = await loop.create_datagram_endpoint(lambda: UdpRelay(relay_mode), sock=sock)
            port = sock.getsockname()[1]
            if mode == "dropctl":
                proto.close_control = lambda: writer.close()
            if mode == "unspec":
                writer.write(reply(0, 1, b"\0\0\0\0", port))
            elif mode == "domain":
                writer.write(reply(0, 3, b"relay.example.test", port))
            elif mode == "ipv6":
                writer.write(reply(0, 4, b"\0" * 15 + b"\x01", port))
            else:
                writer.write(reply(0, 1, b"\x7f\0\0\x01", port))
            await writer.drain()
            log("ASSOC", mode)
            try:
                while await reader.read(1024):
                    pass
            finally:
                transport.close()
        except Exception as e:
            log("ERR", repr(e))
        finally:
            writer.close()
    return handle


async def main():
    def socks(greeting):
        return lambda r, w: serve_socks(r, w, greeting)
    for port, g in ((19100, "ok"), (19101, "gssapi"), (19102, "none"), (19103, "reject"), (19104, "login"), (19105, "any"), (19106, "noudp")):
        await asyncio.start_server(socks(g), "127.0.0.1", port)
    await asyncio.start_server(serve_http, "127.0.0.1", 19110)
    for port, mode in ((19120, "unspec"), (19121, "domain"), (19122, "ipv6"), (19123, "spoof"), (19124, "malformed"),
                       (19125, "refuse"), (19126, "dropctl"), (19127, "swallow")):
        await asyncio.start_server(udp_control(mode), "127.0.0.1", port)
    print("fault proxies up", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
