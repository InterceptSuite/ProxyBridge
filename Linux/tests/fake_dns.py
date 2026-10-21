#!/usr/bin/env python3
"""Tiny authoritative DNS server for ProxyBridge end-to-end tests (UDP + TCP, IPv4 A records and CNAME chains).

usage: fake_dns.py <bind-ip> <logfile>
Zone (everything else answers NXDOMAIN):
  app.example.test        A      192.0.2.77
  blocked.example.test    A      192.0.2.78
  www.corp.test           CNAME  edge.cdnnet.test
  edge.cdnnet.test        A      192.0.2.79
  tcp.example.test        A      192.0.2.80
  svc.byname.test         A      192.0.2.81
  plain.other.test        A      192.0.2.82
"""
import socket, socketserver, struct, sys, threading

ZONE = {
    "app.example.test": [("A", "192.0.2.77")],
    "blocked.example.test": [("A", "192.0.2.78")],
    "www.corp.test": [("CNAME", "edge.cdnnet.test")],
    "edge.cdnnet.test": [("A", "192.0.2.79")],
    "tcp.example.test": [("A", "192.0.2.80")],
    "svc.byname.test": [("A", "192.0.2.81")],
    "plain.other.test": [("A", "192.0.2.82")],
}
# extra records for tests: PB_DNS_ZONE="name=ip;name2=ip2"
import os
for item in filter(None, os.environ.get("PB_DNS_ZONE", "").split(";")):
    n, ip = item.split("=", 1)
    ZONE[n.strip().lower()] = [("A", ip.strip())]
LOG = open(sys.argv[2], "a", buffering=1)


def enc_name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"


def dec_name(m, off):
    parts = []
    while m[off]:
        l = m[off]; parts.append(m[off + 1:off + 1 + l].decode()); off += 1 + l
    return ".".join(parts), off + 1


def answer(query, proto):
    qid, flags, qd = struct.unpack("!HHH", query[:6])
    name, off = dec_name(query, 12)
    qtype = struct.unpack("!H", query[off:off + 2])[0]
    LOG.write(f"{proto} {name} type={qtype}\n")
    key = name.lower()
    rrs, cur, seen = [], key, 0
    while cur in ZONE and seen < 8:
        seen += 1
        for kind, val in ZONE[cur]:
            if kind == "CNAME":
                rd = enc_name(val)
                rrs.append(enc_name(cur) + struct.pack("!HHIH", 5, 1, 300, len(rd)) + rd)
                cur = val
            elif qtype in (1, 255):
                rrs.append(enc_name(cur) + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(val))
                cur = None
            else:
                cur = None
            if cur is None:
                break
        if cur is None:
            break
    rcode = 0 if rrs or key in ZONE else 3
    hdr = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(rrs), 0, 0)
    return hdr + query[12:off + 4] + b"".join(rrs)


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            sock.sendto(answer(data, "udp"), self.client_address)
        except Exception as e:
            LOG.write(f"error {e!r}\n")


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                hdr = self.request.recv(2)
                if len(hdr) < 2:
                    return
                n = struct.unpack("!H", hdr)[0]
                data = b""
                while len(data) < n:
                    chunk = self.request.recv(n - len(data))
                    if not chunk:
                        return
                    data += chunk
                resp = answer(data, "tcp")
                # deliver in two pieces to exercise stream reassembly in the relay
                out = struct.pack("!H", len(resp)) + resp
                self.request.sendall(out[:3]); self.request.sendall(out[3:])
        except Exception as e:
            LOG.write(f"error {e!r}\n")


class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


class US(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 1024

    def server_bind(self):
        # a burst of a few hundred queries (parallel resolvers) must fit in the receive buffer while the handler threads start
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        super().server_bind()


ip = sys.argv[1]
threading.Thread(target=TS((ip, 53), TCP).serve_forever, daemon=True).start()
print("fake dns up on", ip, flush=True)
US((ip, 53), UDP).serve_forever()
