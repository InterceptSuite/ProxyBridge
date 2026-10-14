#!/usr/bin/env python3
"""Fake upstream proxies for ProxyBridge end-to-end tests.

Starts, on 127.0.0.1:
  A  SOCKS5 no-auth          19080   (also UDP ASSOCIATE)
  B  SOCKS5 user/pass        19081   (user "bob", pass "pw")
  C  HTTP CONNECT            19082
  D  HTTP CONNECT, Basic auth 19083   (user "bob", pass "pw"; anything else gets 407)
Whatever destination a client asks for, the "origin" is a built-in responder:
  TCP -> an HTTP/1.0 200 response whose body is "hello-from-<proxy> dst=<requested host:port>"
  UDP -> "UDP-<proxy> <requested host:port> <payload>"
Every request is appended to the log file given as argv[1] ("<proxy> TCP <host>:<port>" / "<proxy> UDP <host>:<port>").
"""
import asyncio, ipaddress, socket, struct, sys

LOG = open(sys.argv[1], "a", buffering=1) if len(sys.argv) > 1 else sys.stdout


def log(proxy, kind, dst):
    LOG.write(f"{proxy} {kind} {dst}\n")


async def origin(reader, writer, proxy, dst):
    """Minimal HTTP/echo origin on an already-tunnelled stream."""
    if dst.endswith(":8888"):                      # "hold" destination: keep the tunnel open until the client closes (scale tests)
        try:
            while await reader.read(65536):
                pass
        except Exception:
            pass
        writer.close()
        return
    try:
        data = await asyncio.wait_for(reader.read(65536), 5)
    except Exception:
        data = b""
    if data.startswith((b"GET", b"HEAD", b"POST")):
        body = f"hello-from-{proxy} dst={dst}\n".encode()
        writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    else:
        writer.write(f"echo-{proxy}:".encode() + data)
    try:
        await writer.drain()
    except Exception:
        pass
    writer.close()


def addr_str(atyp, raw):
    if atyp == 1:
        return str(ipaddress.IPv4Address(raw))
    if atyp == 4:
        return str(ipaddress.IPv6Address(raw))
    return raw.decode()


async def read_addr(reader):
    atyp = (await reader.readexactly(1))[0]
    if atyp == 1:
        raw = await reader.readexactly(4)
    elif atyp == 4:
        raw = await reader.readexactly(16)
    else:
        n = (await reader.readexactly(1))[0]
        raw = await reader.readexactly(n)
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return atyp, raw, port


def socks_handler(name, auth):
    async def handle(reader, writer):
        try:
            ver, n = await reader.readexactly(2)
            methods = await reader.readexactly(n)
            if auth:
                if 2 not in methods:
                    writer.write(b"\x05\xff"); await writer.drain(); writer.close(); return
                writer.write(b"\x05\x02"); await writer.drain()
                v, ul = await reader.readexactly(2)
                user = await reader.readexactly(ul)
                pl = (await reader.readexactly(1))[0]
                pw = await reader.readexactly(pl)
                ok = user == b"bob" and pw == b"pw"
                writer.write(b"\x01" + (b"\x00" if ok else b"\x01")); await writer.drain()
                if not ok:
                    log(name, "AUTHFAIL", user.decode()); writer.close(); return
            else:
                writer.write(b"\x05\x00"); await writer.drain()
            ver, cmd, _rsv = await reader.readexactly(3)
            atyp, raw, port = await read_addr(reader)
            dst = f"{addr_str(atyp, raw)}:{port}"
            if cmd == 1:
                log(name, "TCP", dst)
                writer.write(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 0)); await writer.drain()
                await origin(reader, writer, name, dst)
            elif cmd == 3:
                loop = asyncio.get_running_loop()
                transport, _ = await loop.create_datagram_endpoint(lambda: UdpRelay(name), local_addr=("127.0.0.1", 0))
                bport = transport.get_extra_info("sockname")[1]
                writer.write(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", bport)); await writer.drain()
                try:
                    while await reader.read(1024):   # association lives as long as the TCP control connection
                        pass
                finally:
                    transport.close()
            else:
                writer.write(b"\x05\x07\x00\x01" + b"\0" * 6); await writer.drain()
        except Exception as e:
            log(name, "ERR", repr(e))
        finally:
            try:
                writer.close()
            except Exception:
                pass
    return handle


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, name):
        self.name = name

    def connection_made(self, transport):
        self.t = transport

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
        dst = f"{addr_str(atyp, raw)}:{port}"
        log(self.name, "UDP", dst)
        reply = f"UDP-{self.name} {dst} ".encode() + payload
        self.t.sendto(data[:off + 2] + reply, addr)


import base64


def http_connect_handler(name, need_auth):
    async def handler(reader, writer):
        await http_connect(reader, writer, name, need_auth)
    return handler


async def http_connect(reader, writer, name="C", need_auth=False):
    try:
        head = await reader.readuntil(b"\r\n\r\n")
        first = head.split(b"\r\n")[0].decode()
        if need_auth:
            want = b"Proxy-Authorization: Basic " + base64.b64encode(b"bob:pw")
            if want.lower() not in head.lower():
                log(name, "AUTHFAIL", first)
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\nContent-Length: 0\r\n\r\n")
                await writer.drain(); writer.close(); return
        if not first.startswith("CONNECT "):
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"); await writer.drain(); writer.close(); return
        dst = first.split()[1]
        log(name, "TCP", dst)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n"); await writer.drain()
        await origin(reader, writer, name, dst)
    except Exception as e:
        log(name, "ERR", repr(e))
    finally:
        writer.close()


async def main():
    await asyncio.start_server(socks_handler("A", False), "127.0.0.1", 19080)
    await asyncio.start_server(socks_handler("B", True), "127.0.0.1", 19081)
    await asyncio.start_server(http_connect_handler("C", False), "127.0.0.1", 19082)
    await asyncio.start_server(http_connect_handler("D", True), "127.0.0.1", 19083)
    print("fake proxies up: A=socks5:19080 B=socks5(bob:pw):19081 C=http:19082", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
