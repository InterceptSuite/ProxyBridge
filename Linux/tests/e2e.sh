#!/bin/bash
# End-to-end test of the eBPF backend. Needs root, curl, python3. Uses only loopback + TEST-NET addresses (nothing leaves the host).
#   sudo Linux/tests/e2e.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
WORK="$(mktemp -d)"
LOG="$WORK/proxy.log"; : > "$LOG"
PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
expect_contains() { # name haystack needle
  if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1 (got: ${2:0:200})"; fi; }

cleanup() { kill "$PB_PID" "$FAKE_PID" "$DIRECT_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export LD_LIBRARY_PATH="$PB_DIR"

python3 "$HERE/fake_proxies.py" "$LOG" > "$WORK/fake.out" 2>&1 & FAKE_PID=$!
# a direct (non-proxied) origin on the host's own LAN address, so DIRECT rules can be seen to work
MYIP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1); MYIP=${MYIP:-127.0.0.1}
mkdir -p "$WORK/www"; echo "direct-origin" > "$WORK/www/index.html"
python3 -m http.server 18399 --bind "$MYIP" --directory "$WORK/www" >/dev/null 2>&1 & DIRECT_PID=$!
sleep 1

cp "$(command -v curl)" "$WORK/newcurl"            # a binary that did not exist when ProxyBridge started

stdbuf -oL "$PBL" --verbose 3 \
  --proxy a=socks5://127.0.0.1:19080 --proxy b=socks5://bob:pw@127.0.0.1:19081 --proxy c=http://127.0.0.1:19082 \
  --rule "curl:$MYIP/32:18399:TCP:DIRECT" \
  --rule "curl:192.0.2.0/24:*:TCP:PROXY=a" \
  --rule "curl:198.51.100.0/24:*:TCP:PROXY=b" \
  --rule "curl:203.0.113.0/24:*:TCP:PROXY=c" \
  --rule "curl:203.0.114.0/24:*:TCP:BLOCK" \
  --rule "curl:2001:db8::/32:80:TCP:PROXY=a" \
  --rule "curl:10.200.0.0/24:*:TCP:PROXY=a" \
  --rule "newcurl:192.0.2.0/24:*:TCP:PROXY=b" \
  --rule "python3*:192.0.2.0/24:5300:UDP:PROXY=a" \
  --rule "python3*:198.51.100.0/24:5300:UDP:PROXY=b" \
  --rule "python3*:2001:db8::/32:*:BOTH:PROXY=a" \
  > "$WORK/pb.out" 2>&1 & PB_PID=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
if ! grep -q "ProxyBridge started" "$WORK/pb.out"; then echo "ProxyBridge failed to start:"; cat "$WORK/pb.out"; exit 1; fi
sleep 1

echo "== TCP: per-rule proxy selection, original destination recovery"
out=$(curl -s -m 5 http://192.0.2.7/);        expect_contains "proxy A via SOCKS5"          "$out" "hello-from-A dst=192.0.2.7:80"
out=$(curl -s -m 5 http://198.51.100.7:8080/); expect_contains "proxy B via SOCKS5 user/pass" "$out" "hello-from-B dst=198.51.100.7:8080"
out=$(curl -s -m 5 http://203.0.113.7:81/);   expect_contains "proxy C via HTTP CONNECT"     "$out" "hello-from-C dst=203.0.113.7:81"
out=$(curl -s -m 5 http://203.0.114.7/ 2>&1; echo "rc=$?"); expect_contains "BLOCK rule rejects connect()" "$out" "rc=7"
out=$(curl -s -m 5 "http://$MYIP:18399/");    expect_contains "DIRECT rule bypasses the proxies" "$out" "direct-origin"
out=$(curl -s -g -m 5 'http://[2001:db8::7]/'); expect_contains "IPv6 destination through proxy A" "$out" "hello-from-A dst=2001:db8::7:80"
out=$(curl -s -m 5 http://127.0.0.1:19080/ 2>&1; echo "rc=$?"); expect_contains "loopback is never redirected" "$out" "rc="
out=$("$WORK/newcurl" -s -m 5 http://192.0.2.8/); expect_contains "binary unknown at start (slow path)" "$out" "hello-from-B dst=192.0.2.8:80"
out=$("$WORK/newcurl" -s -m 5 http://192.0.2.9/); expect_contains "same binary, learned class (fast path)" "$out" "hello-from-B dst=192.0.2.9:80"
out=$(curl -s -m 5 http://192.0.2.10/);       expect_contains "other binary still uses its own rule" "$out" "hello-from-A dst=192.0.2.10:80"
pids=(); for i in $(seq 30); do curl -s -m 5 http://192.0.2.$((20+i))/ >/dev/null & pids+=($!); done; wait "${pids[@]}" 2>/dev/null
sleep 1
c=$(grep -c "^A TCP 192.0.2.\(2[1-9]\|3[0-9]\|4[0-9]\|50\):80" "$LOG"); [ "$c" -ge 30 ] && ok "30 concurrent connections all proxied ($c)" || bad "concurrent: only $c/30 reached proxy A"

echo "== isolation: other network namespaces (containers) are never redirected"
if ip netns add pbtest 2>/dev/null; then
  ip netns exec pbtest ip link set lo up; ip netns exec pbtest ip addr add 10.200.0.1/32 dev lo
  ip netns exec pbtest python3 -m http.server 18400 --bind 10.200.0.1 --directory "$WORK/www" >/dev/null 2>&1 & NSPID=$!
  sleep 1
  out=$(ip netns exec pbtest curl -s -m 4 http://10.200.0.1:18400/ 2>&1; echo "rc=$?")
  expect_contains "curl inside a netns reaches its own server (rule matches the IP, but the namespace is foreign)" "$out" "direct-origin"
  kill $NSPID 2>/dev/null; ip netns del pbtest 2>/dev/null
else
  echo "  SKIP  ip netns not available"
fi

echo "== UDP: unconnected, multi-destination, connected, IPv6"
out=$(python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
res = []
for dst in [("192.0.2.9", 5300), ("198.51.100.9", 5300), ("192.0.2.9", 5300)]:
    s.sendto(b"ping", dst)
    d, a = s.recvfrom(200)
    res.append(f"{d.decode()}|from={a[0]}:{a[1]}")
print("\n".join(res))
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(4)
c.connect(("192.0.2.9", 5300)); c.send(b"conn"); d = c.recv(200)
print("connected:" + d.decode() + "|peer=%s:%d" % c.getpeername())
s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s6.settimeout(4)
try:
    s6.sendto(b"v6", ("2001:db8::9", 5300)); print("v6 unconnected: sent")
except OSError as e:
    print("v6 unconnected: blocked errno=%d" % e.errno)
c6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); c6.settimeout(4)
c6.connect(("2001:db8::9", 5300)); c6.send(b"v6c"); d = c6.recv(200)
print("v6 connected:" + d.decode() + "|peer=%s:%d" % c6.getpeername()[:2])
d6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); d6.settimeout(4)
d6.sendto(b"mapped", ("::ffff:192.0.2.9", 5300)); d, a = d6.recvfrom(200)
print("v6 socket, v4 dest:" + d.decode() + "|from=%s" % a[0])
PY
)
expect_contains "UDP via proxy A, source restored"      "$out" "UDP-A 192.0.2.9:5300 ping|from=192.0.2.9:5300"
expect_contains "same socket, second destination -> proxy B" "$out" "UDP-B 198.51.100.9:5300 ping|from=198.51.100.9:5300"
expect_contains "connected UDP works and getpeername restored" "$out" "connected:UDP-A 192.0.2.9:5300 conn|peer=192.0.2.9:5300"
expect_contains "native IPv6 unconnected UDP fails closed (EPERM)" "$out" "v6 unconnected: blocked errno=1"
expect_contains "connected IPv6 UDP through proxy A, peer restored" "$out" "v6 connected:UDP-A 2001:db8::9:5300 v6c|peer=2001:db8::9:5300"
expect_contains "dual-stack socket sending to IPv4 dest" "$out" "v6 socket, v4 dest:UDP-A 192.0.2.9:5300 mapped"

echo "== UDP: large datagrams and many sockets"
out=$(python3 - <<'PY'
import socket, concurrent.futures as cf
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
big = bytes(range(256)) * 230                       # 58,880 bytes
s.sendto(big, ("192.0.2.9", 5300)); d, a = s.recvfrom(70000)
prefix = b"UDP-A 192.0.2.9:5300 "
print("big:", "ok" if d == prefix + big else "MISMATCH len=%d" % len(d))
def one(i):
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(8)
    payload = b"n%d" % i
    c.sendto(payload, ("192.0.2.%d" % (100 + i % 100), 5300))
    d, a = c.recvfrom(100)
    return d.endswith(payload) and a[0] == "192.0.2.%d" % (100 + i % 100)
with cf.ThreadPoolExecutor(64) as ex:
    res = list(ex.map(one, range(400)))
print("many:", sum(res), "/ 400")
PY
)
expect_contains "58KB datagram through SOCKS5 UDP, intact" "$out" "big: ok"
expect_contains "400 concurrent UDP sockets, each reply from the right address" "$out" "many: 400 / 400"

echo "== logging"
sleep 1
grep -q "\[CONN\] curl" "$WORK/pb.out" && ok "connection events reported to the CLI" || bad "no [CONN] events"

echo "== lifecycle"
kill -INT "$PB_PID"; wait "$PB_PID" 2>/dev/null
out=$(curl -s -m 3 http://192.0.2.7/ 2>&1; echo "rc=$?")
[[ "$out" != *hello-from* ]] && ok "after stop traffic is no longer redirected" || bad "still redirected after stop"
"${BPFTOOL:-bpftool}" prog show 2>/dev/null | grep -q pb_connect && bad "BPF programs left behind" || ok "BPF programs detached"
ss -ltn 2>/dev/null | grep -qE ":2401[0-9]" && bad "relay ports still listening" || ok "relay ports released"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "---- proxy log"; cat "$LOG"; echo "---- pb output"; tail -30 "$WORK/pb.out"; exit 1; }
