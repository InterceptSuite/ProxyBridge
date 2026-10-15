#!/usr/bin/env python3
"""Real origin servers for the Nexus Proxy end-to-end tests (they actually serve data, nothing is faked on the proxy side).

usage: nexus_origins.py   (binds the addresses below; add them to `lo` first)
  HTTP   10.77.1.1..6:18700 "origin-1".."origin-6"
         10.77.1.1:18701..18705 "origin-1-p<port>"
         GET  /big?mb=N   -> N MiB of a deterministic pattern (see PATTERN)
         POST /upload     -> sha256 of the request body
         GET  /slowclose  -> response, then the server half-closes and waits for the client to close
  UDP    10.77.1.1:18710 "U1:"  10.77.1.2:18710 "U2:"  10.77.1.1:18711 "U3:"   echo prefixed with the tag
"""
import hashlib, http.server, socket, socketserver, threading, sys, time

BLOCK = bytes((i * 7 + 13) & 255 for i in range(1 << 20))      # 1 MiB pattern block


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    tag = "origin"

    def do_GET(self):
        if self.path.startswith("/big"):
            mb = int(self.path.split("mb=")[1])
            self.send_response(200); self.send_header("Content-Length", str(mb << 20)); self.end_headers()
            for _ in range(mb):
                self.wfile.write(BLOCK)
        else:
            body = (self.tag + "\n").encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0")); h = hashlib.sha256(); left = n
        while left:
            b = self.rfile.read(min(1 << 20, left))
            if not b:
                break
            h.update(b); left -= len(b)
        body = h.hexdigest().encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *a):
        pass


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 1024


def http(ip, port, tag):
    handler = type("H_" + tag, (H,), {"tag": tag})
    srv = TS((ip, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def udp(ip, port, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((ip, port))
    def loop():
        while True:
            d, a = s.recvfrom(70000)
            try:
                s.sendto(tag.encode() + d, a)
            except OSError:
                pass
    threading.Thread(target=loop, daemon=True).start()


for i in (1, 2, 3, 4, 5, 6):
    http("10.77.1.%d" % i, 18700, "origin-%d" % i)
for p in range(18701, 18706):
    http("10.77.1.1", p, "origin-1-p%d" % p)
udp("10.77.1.1", 18710, "U1:"); udp("10.77.1.2", 18710, "U2:"); udp("10.77.1.1", 18711, "U3:")
print("origins up", flush=True)
while True:
    time.sleep(3600)
