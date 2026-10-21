"""A tiny HTTP proxy for the Windows end-to-end test: it only understands CONNECT (what ProxyBridge sends to an HTTP
proxy), optionally with Basic authentication, and writes one "[CONNECT] host:port" line per tunnel to its log so the
test can see what really went through it.

    python http_proxy.py --port 33128 --log proxy.log [--username u --password p]
"""
import argparse
import base64
import socket
import sys
import threading

lock = threading.Lock()


def log(path, text):
    with lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")
            f.flush()


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, args):
    try:
        client.settimeout(20)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                return
            data += chunk
            if len(data) > 65536:
                return
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) < 2 or parts[0] != b"CONNECT":
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(b":")
            headers[k.strip().lower()] = v.strip()
        if args.username is not None:
            want = b"Basic " + base64.b64encode((args.username + ":" + args.password).encode())
            if headers.get(b"proxy-authorization") != want:
                log(args.log, "[AUTH-FAILED]")
                client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"e2e\"\r\nContent-Length: 0\r\n\r\n")
                return
        host, _, port = parts[1].rpartition(b":")
        host = host.decode().strip("[]")
        log(args.log, "[CONNECT] %s:%s" % (host, port.decode()))
        upstream = socket.create_connection((host, int(port)), timeout=15)
        client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        client.settimeout(None)
        upstream.settimeout(None)
        if rest:
            upstream.sendall(rest)
        t = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
        t.start()
        pipe(client, upstream)
        t.join(5)
    except (OSError, ValueError) as e:
        log(args.log, "[ERROR] %s" % e)
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=33128)
    ap.add_argument("--log", required=True)
    ap.add_argument("--username")
    ap.add_argument("--password", default="")
    args = ap.parse_args()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(64)
    log(args.log, "[LISTENING] %s:%d" % (args.host, args.port))
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, args), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
