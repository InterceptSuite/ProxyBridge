#!/bin/bash
# End-to-end test of the Windows/macOS parity options: a proxy that resolves host names ("DNS via proxy", per proxy) and
# "Also proxy localhost traffic" (per rule). Needs root, dig, curl, python3.
#   sudo Linux/tests/e2e_parity.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"; PLOG="$WORK/proxy.log"; DLOG="$WORK/dns.log"; : > "$PLOG"; : > "$DLOG"
PASS=0; FAIL=0; DNSIP=10.77.0.6; LODNS=127.0.0.9
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
has() { [[ "$2" == *"$3"* ]] && ok "$1" || bad "$1 (got: ${2:0:200})"; }
hasnt() { [[ "$2" != *"$3"* ]] && ok "$1" || bad "$1 (got: ${2:0:200})"; }
PB_PID=""
cleanup() { [ -n "$PB_PID" ] && kill "$PB_PID" 2>/dev/null; kill $FAKE $DNSP $DNSL $WWW $UDPE 2>/dev/null; wait 2>/dev/null; ip addr del $DNSIP/32 dev lo 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
ip addr add $DNSIP/32 dev lo 2>/dev/null
python3 "$HERE/fake_proxies.py" "$PLOG" > /dev/null 2>&1 & FAKE=$!
python3 "$HERE/fake_dns.py" $DNSIP "$DLOG" > /dev/null 2>&1 & DNSP=$!
python3 "$HERE/fake_dns.py" $LODNS "$DLOG" > /dev/null 2>&1 & DNSL=$!
mkdir -p "$WORK/www"; echo "local-origin" > "$WORK/www/index.html"
python3 -m http.server 18401 --bind 127.0.0.1 --directory "$WORK/www" > /dev/null 2>&1 & WWW=$!
python3 - > /dev/null 2>&1 <<'PY' & UDPE=$!
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 18402))
while True:
    d, a = s.recvfrom(2048); s.sendto(b"LOCAL-ECHO " + d, a)
PY
sleep 1
for n in curl2 curl3 curl4 curl5; do cp "$(command -v curl)" "$WORK/$n"; done

start_pb() { # args...
  stdbuf -oL "$PBL" "$@" > "$WORK/pb.out" 2>&1 & PB_PID=$!
  for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && return 0; kill -0 "$PB_PID" 2>/dev/null || return 1; sleep 0.25; done; return 1
}
stop_pb() { kill -INT "$PB_PID" 2>/dev/null; wait "$PB_PID" 2>/dev/null; PB_PID=""; }
resolve() { dig @$DNSIP "$1" +short +time=3 +tries=1 | head -1; }

echo "== per-proxy host-name sending (DNS via proxy)"
start_pb --verbose 1 \
  --proxy a=socks5://127.0.0.1:19080 --proxy l=socks5://127.0.0.1:19080?dns=local \
  --proxy c=http://127.0.0.1:19082 --proxy cl=http://127.0.0.1:19082?dns=local \
  --rule "*:192.0.2.77:*:TCP:PROXY=a" --rule "*:192.0.2.80:*:TCP:PROXY=l" \
  --rule "*:192.0.2.81:*:TCP:PROXY=c" --rule "*:192.0.2.82:*:TCP:PROXY=cl" --rule "*:192.0.2.99:*:TCP:PROXY=a" || { bad "start"; cat "$WORK/pb.out"; }
has "proxy option dns=local is reported" "$(cat "$WORK/pb.out")" "Proxies: 4"
resolve app.example.test >/dev/null; resolve tcp.example.test >/dev/null; resolve svc.byname.test >/dev/null; resolve plain.other.test >/dev/null
out=$(curl -s -m 5 http://192.0.2.77/);  has "SOCKS5: the resolved name goes to the proxy (ATYP domain)"   "$out" "hello-from-A dst=app.example.test:80"
out=$(curl -s -m 5 http://192.0.2.80/);  has "SOCKS5 with dns=local: the IP goes to the proxy"            "$out" "hello-from-A dst=192.0.2.80:80"
out=$(curl -s -m 5 http://192.0.2.81/);  has "HTTP CONNECT: the resolved name goes to the proxy"          "$out" "hello-from-C dst=svc.byname.test:80"
out=$(curl -s -m 5 http://192.0.2.82/);  has "HTTP CONNECT with dns=local: the IP goes to the proxy"      "$out" "hello-from-C dst=192.0.2.82:80"
out=$(curl -s -m 5 http://192.0.2.99/);  has "no DNS answer seen for the address: the IP is sent"        "$out" "hello-from-A dst=192.0.2.99:80"
resolve app.example.test >/dev/null
out=$(curl -s -m 5 "http://192.0.2.77:8080/"); has "port is kept with the name" "$out" "dst=app.example.test:8080"
stop_pb

echo "== a hostile DNS name never reaches a proxy request"
cat > "$WORK/evil_dns.py" <<'PY'
import socket, struct, sys
ip, = sys.argv[1:2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((ip, 53))
while True:
    q, a = s.recvfrom(512)
    # answer: question copied, one A record for 192.0.2.60 whose owner is "ok.test\r\nX-Evil: 1" (label with control bytes)
    name = b"ok.test\r\nX-Evil: 1"
    lab = bytes([len(name)]) + name + b"\x00"
    hdr = q[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    ques = lab + b"\x00\x01\x00\x01"
    ans = lab + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([192, 0, 2, 60])
    s.sendto(hdr + ques + ans, a)
PY
python3 "$WORK/evil_dns.py" 127.0.0.10 > /dev/null 2>&1 & EVIL=$!
sleep 0.5
start_pb --verbose 1 --proxy c=http://127.0.0.1:19082 --rule "*:192.0.2.60:*:TCP:PROXY=c" || bad "start"
dig @127.0.0.10 evil.test +short +time=2 +tries=1 > /dev/null
out=$(curl -s -m 5 http://192.0.2.60/)
has "HTTP CONNECT carries the IP, not the unsafe name" "$out" "hello-from-C dst=192.0.2.60:80"
hasnt "no header injection reached the proxy"            "$(cat "$PLOG")" "X-Evil"
stop_pb; kill $EVIL 2>/dev/null

echo "== per-rule localhost"
start_pb --verbose 1 \
  --proxy a=socks5://127.0.0.1:19080 \
  --rule "curl:127.0.0.1:18401:TCP:PROXY=a+localhost" \
  --rule "curl2:127.0.0.1:18401:TCP:PROXY=a" \
  --rule "curl2:*:*:TCP:PROXY=a+localhost" \
  --rule "curl3:*:*:TCP:BLOCK" \
  --rule "curl4:127.0.0.*:18401:TCP:PROXY=a+localhost" \
  --rule "curl5:127.0.0.*:18401:TCP:PROXY=a" \
  --rule "python3*:127.0.0.1:18402:UDP:PROXY=a+localhost" \
  --rule "dig:*:*:BOTH:PROXY=a+localhost" || { bad "start"; cat "$WORK/pb.out"; }
has "rule line shows the option" "$(cat "$WORK/pb.out")" "(+localhost)"
out=$(curl -s -m 5 http://127.0.0.1:18401/);            has "PROXY+localhost: loopback TCP goes to the proxy (kernel path)" "$out" "hello-from-A dst=127.0.0.1:18401"
out=$("$WORK/curl2" -s -m 5 http://127.0.0.1:18401/);   has "PROXY without the option leaves loopback direct"           "$out" "local-origin"
out=$("$WORK/curl2" -s -m 5 http://192.0.2.5/);         has "...and the same process is still proxied elsewhere"        "$out" "hello-from-A dst=192.0.2.5:80"
out=$("$WORK/curl3" -s -m 5 http://127.0.0.1:18401/);   has "BLOCK rules do not apply to loopback"                       "$out" "local-origin"
out=$("$WORK/curl3" -s -m 3 http://192.0.2.6/ 2>&1; echo "rc=$?"); has "...but still block everything else"            "$out" "rc=7"
out=$("$WORK/curl4" -s -m 5 http://127.0.0.1:18401/);   has "PROXY+localhost with a pattern the kernel defers (slow path)" "$out" "hello-from-A dst=127.0.0.1:18401"
out=$("$WORK/curl5" -s -m 5 http://127.0.0.1:18401/);   has "pattern rule without the option stays direct (slow path)"    "$out" "local-origin"
out=$(python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(4); s.sendto(b'ping',('127.0.0.1',18402))
print(s.recvfrom(2048)[0].decode())
" 2>&1);                                                   has "UDP to loopback goes through the proxy too"             "$out" "UDP-A 127.0.0.1:18402 ping"
out=$(dig @$LODNS app.example.test +short +time=3 +tries=1 | head -1); has "DNS to a loopback resolver is never proxied (port 53)" "$out" "192.0.2.77"
hasnt "the fake proxy never saw the DNS query"  "$(cat "$PLOG")" "127.0.0.9:53"
stop_pb

echo "== no localhost rule: loopback is untouched, as before"
start_pb --proxy a=socks5://127.0.0.1:19080 --rule "curl:*:*:TCP:PROXY=a" || bad "start"
out=$(curl -s -m 5 http://127.0.0.1:18401/);            has "loopback stays direct without the option" "$out" "local-origin"
stop_pb

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
