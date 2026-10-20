#!/usr/bin/env python3
"""A real (forwarding) SOCKS5 CONNECT proxy for the exemption tests: it opens the connection the client asks for.
usage: fwd_socks5.py <bind-ip> <port> <logfile>"""
import asyncio, ipaddress, struct, sys

LOG = open(sys.argv[3], "a", buffering=1)


async def pipe(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    try:
        w.close()
    except Exception:
        pass


async def handle(r, w):
    try:
        _v, n = await r.readexactly(2)
        await r.readexactly(n)
        w.write(b"\x05\x00")
        _v, cmd, _r, atyp = await r.readexactly(4)
        if atyp == 1:
            host = str(ipaddress.IPv4Address(await r.readexactly(4)))
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(await r.readexactly(16)))
        else:
            host = (await r.readexactly((await r.readexactly(1))[0])).decode()
        port = struct.unpack("!H", await r.readexactly(2))[0]
        LOG.write(f"FWD {host}:{port}\n")
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
        except Exception as e:
            LOG.write(f"FAIL {host}:{port} {e!r}\n")
            w.write(b"\x05\x05\x00\x01\0\0\0\0\0\0"); await w.drain(); w.close(); return
        w.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00"); await w.drain()
        await asyncio.gather(pipe(r, uw), pipe(ur, w))
    except Exception:
        pass
    finally:
        w.close()


async def main():
    srv = await asyncio.start_server(handle, sys.argv[1], int(sys.argv[2]))
    await srv.serve_forever()

asyncio.run(main())
