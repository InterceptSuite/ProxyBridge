#!/usr/bin/env python3
"""End-to-end checks of the iOS router without a phone. The router (built by run.sh) is driven the way hev drives it,
over the IPv6 loopback, against the local test proxies of the macOS tests (MacOS/tests/servers.py).

  python3 router_e2e.py <router binary>

Needs ports 1080, 1081 and 8080 free for the test proxies, and network access for the DNS check."""
import concurrent.futures as cf, http.server, json, os, socket, struct, subprocess, sys, tempfile, threading, time, uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SERVERS = os.path.join(HERE, "..", "..", "MacOS", "tests", "servers.py")
ROUTER = sys.argv[1]
WORK = tempfile.mkdtemp()
EVENTS = os.path.join(WORK, "events.log")
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok or not detail else f"  ({detail})"))


def events():
    try:
        return [json.loads(line) for line in open(EVENTS)]
    except OSError:
        return []


def seen(kind, proxy, port, **extra):
    return [e for e in events() if e["kind"] == kind and e.get("proxy") == proxy and e.get("port") == port
            and all(e.get(k) == v for k, v in extra.items())]


def new_id():
    return str(uuid.uuid4()).upper()


# ---------------------------------------------------------------- config
P = {name: new_id() for name in ("socks", "http", "auth", "dead", "ip_only")}


def proxy(name, kind, port, user="", password="", send_hostname=True):
    return {"id": P[name], "name": name, "kind": kind, "host": "127.0.0.1", "port": port,
            "username": user, "password": password, "sendHostname": send_hostname}


def rule(port, proto, action, proxy_name=None, hosts="127.0.0.1"):
    return {"id": new_id(), "name": "", "hosts": hosts, "ports": str(port), "proto": proto, "action": action,
            "proxyId": P[proxy_name] if proxy_name else None, "enabled": True}


config = {
    "proxies": [proxy("socks", "socks5", 1080), proxy("http", "http", 8080),
                proxy("auth", "socks5", 1081, "pbtest", "pbpass"), proxy("dead", "socks5", 9),
                proxy("ip_only", "socks5", 1080, send_hostname=False)],
    "rules": [rule(18081, "tcp", "proxy", "socks"), rule(18082, "tcp", "proxy", "http"), rule(18083, "tcp", "direct"),
              rule(18084, "tcp", "block"), rule(18085, "tcp", "block", hosts="blocked.test"),
              rule(18086, "tcp", "proxy", "auth"), rule(18087, "tcp", "proxy", "dead"), rule(18088, "tcp", "proxy"),
              rule(18090, "tcp", "proxy", "ip_only"),
              rule(19001, "udp", "direct"), rule(19002, "udp", "proxy", "socks"), rule(19003, "udp", "proxy", "http")],
    "defaultAction": "direct",
}
config_path = os.path.join(WORK, "config.json")
json.dump(config, open(config_path, "w"))

# ---------------------------------------------------------------- local servers
class Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello-{self.server.server_address[1]}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


for web_port in (18081, 18082, 18083, 18084, 18085, 18086, 18087, 18088, 18090):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", web_port), Page)
    threading.Thread(target=server.serve_forever, daemon=True).start()

udp_sources = {}


def udp_echo(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    while True:
        data, addr = sock.recvfrom(2000)
        udp_sources.setdefault(port, []).append(addr[1])
        sock.sendto(b"echo:" + data, addr)


for udp_port in (19001, 19002, 19003):
    threading.Thread(target=udp_echo, args=(udp_port,), daemon=True).start()

open(EVENTS, "w").close()
proxies_process = subprocess.Popen([sys.executable, SERVERS], env=dict(os.environ, PB_EVENTS=EVENTS),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
router = subprocess.Popen([ROUTER, "serve", config_path], stdout=subprocess.PIPE, text=True)
port = next(int(line.split()[1]) for line in router.stdout if line.startswith("PORT"))
time.sleep(1.5)


# ---------------------------------------------------------------- the client side of hev
def socks_connect(host, dport, timeout=8):
    sock = socket.create_connection(("::1", port), timeout)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    assert sock.recv(2) == b"\x05\x00"
    sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", dport))
    return sock, sock.recv(10)


def fetch(dport, timeout=8):
    """Returns (reply code, body). 2 means refused or closed, 99 means no answer at all."""
    try:
        sock, reply = socks_connect("127.0.0.1", dport, timeout)
    except socket.timeout:
        return 99, None
    if len(reply) < 2:
        sock.close()
        return 2, None
    if reply[1] != 0:
        sock.close()
        return reply[1], None
    sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    body = b""
    try:
        while chunk := sock.recv(4096):
            body += chunk
    except OSError:
        pass
    sock.close()
    return 0, body


def associate():
    control = socket.create_connection(("::1", port), 5)
    control.sendall(b"\x05\x01\x00")
    control.recv(2)
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply = b""
    while len(reply) < 22:
        reply += control.recv(22 - len(reply))
    assert reply[3] == 4, "the relay address must be IPv6"
    return control, struct.unpack("!H", reply[20:22])[0]


def udp_client():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.settimeout(4)
    sock.bind(("::1", 0))
    return sock


def udp_send(sock, relay, host, dport, payload):
    sock.sendto(b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", dport) + payload, ("::1", relay))


try:
    code, body = fetch(18081)
    check("TCP through a SOCKS5 proxy", code == 0 and b"hello-18081" in body, (code, body))
    check("the proxy gets the host name", len(seen("connect", "socks1080", 18081, dest="localhost")) == 1)
    code, body = fetch(18082)
    check("TCP through an HTTP CONNECT proxy", code == 0 and b"hello-18082" in body, (code, body))
    check("the HTTP proxy gets the host name", len(seen("connect", "http8080", 18082, dest="localhost")) == 1)
    code, body = fetch(18090)
    check("with the option off the proxy gets the IP", code == 0 and len(seen("connect", "socks1080", 18090, dest="127.0.0.1")) == 1, (code, body))
    code, body = fetch(18083)
    check("direct, no proxy involved", code == 0 and b"hello-18083" in body and not seen("connect", "socks1080", 18083), (code, body))
    check("block refuses", fetch(18084)[0] == 2)
    check("a domain rule matches through the name map", fetch(18085)[0] == 2)
    code, body = fetch(18086)
    check("SOCKS5 proxy with a login", code == 0 and b"hello-18086" in body, (code, body))
    check("the login was accepted", any(e["kind"] == "auth" and e.get("ok") for e in events() if e.get("proxy") == "socks1081"))
    check("a dead proxy fails fast", fetch(18087, 4)[0] in (1, 2), "no answer within 4s")
    code, body = fetch(18088)
    check("no proxy named uses the first one", code == 0 and b"hello-18088" in body and len(seen("connect", "socks1080", 18088)) == 1, (code, body))
    check("a closed port fails fast", fetch(18089, 4)[0] in (1, 2), "no answer within 4s")

    control, relay = associate()
    client = udp_client()
    udp_send(client, relay, "127.0.0.1", 19001, b"one")
    try:
        check("UDP direct round trip", client.recvfrom(2000)[0].endswith(b"echo:one"))
    except OSError as error:
        check("UDP direct round trip", False, error)
    udp_send(client, relay, "127.0.0.1", 19001, b"two")
    udp_send(client, relay, "127.0.0.1", 19001, b"three")
    replies = []
    try:
        replies = [client.recvfrom(2000)[0] for _ in range(2)]
    except OSError:
        pass
    check("later datagrams are answered", len(replies) == 2)
    check("direct UDP keeps one source port per flow", len(set(udp_sources.get(19001, []))) == 1, udp_sources.get(19001))

    control2, relay2 = associate()
    client2 = udp_client()
    client2.settimeout(5)
    udp_send(client2, relay2, "127.0.0.1", 19002, b"proxied")
    try:
        check("UDP through a SOCKS5 proxy", client2.recvfrom(2000)[0].endswith(b"echo:proxied"))
    except OSError as error:
        check("UDP through a SOCKS5 proxy", False, error)

    control3, relay3 = associate()
    client3 = udp_client()
    client3.settimeout(5)
    udp_send(client3, relay3, "127.0.0.1", 19003, b"viahttp")
    try:
        check("UDP for an HTTP proxy goes direct", client3.recvfrom(2000)[0].endswith(b"echo:viahttp"))
    except OSError as error:
        check("UDP for an HTTP proxy goes direct", False, error)
    check("the HTTP proxy was not used for it", not [e for e in events() if e["kind"] == "connect" and e.get("port") == 19003])

    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    client4 = udp_client()
    udp_send(client4, relay, "10.64.0.1", 53, query)
    try:
        client4.recvfrom(2000)
        check("a query to the tunnel resolver is answered", True)
    except OSError:
        check("a query to the tunnel resolver is answered", False, "no answer, is the network up?")

    with cf.ThreadPoolExecutor(50) as pool:
        codes = list(pool.map(lambda _: fetch(18083)[0], range(200)))
    check("200 parallel direct flows", codes.count(0) == 200, codes.count(0))
    with cf.ThreadPoolExecutor(50) as pool:
        codes = list(pool.map(lambda _: fetch(18081)[0], range(200)))
    check("200 parallel flows through a proxy", codes.count(0) == 200, codes.count(0))
finally:
    router.terminate()
    proxies_process.terminate()

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
