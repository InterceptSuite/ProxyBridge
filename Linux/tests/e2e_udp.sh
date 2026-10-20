#!/bin/bash
# UDP through SOCKS5 UDP ASSOCIATE: a normal proxy, a pile of misbehaving ones, and every rule outcome (proxy, direct, block, HTTP proxy).
# Needs root, python3.   sudo Linux/tests/e2e_udp.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"; : > "$WORK/fault.log"; : > "$WORK/proxy.log"
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
PB_PID=""; ECHO_PID=""
cleanup() { [ -n "$PB_PID" ] && kill "$PB_PID" 2>/dev/null; kill $F1 $F2 $ECHO_PID 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
python3 "$HERE/fault_proxies.py" "$WORK/fault.log" > /dev/null 2>&1 & F1=$!
python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & F2=$!
MYIP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1); MYIP=${MYIP:-127.0.0.1}
python3 - "$MYIP" > /dev/null 2>&1 <<'PY' & ECHO_PID=$!
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((sys.argv[1], 5301))
while True:
    d, a = s.recvfrom(65535); s.sendto(b"DIRECT-ECHO " + d, a)
PY
sleep 1.5

probe() { timeout 60 python3 "$HERE/udp_probe.py" "$@" 2>&1; }
want() { # name, output, expected substring
  if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1 (got: ${2:0:300})"; fi; }
nowant() { if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1 (got: ${2:0:300})"; fi; }
logged() { grep -q "$2" "$WORK/pb.out" && ok "$1" || bad "$1 (log lacks '$2')"; }

stdbuf -oL "$PBL" --verbose 1 \
  --proxy a=socks5://127.0.0.1:19080 --proxy c=http://127.0.0.1:19082 \
  --proxy u0=socks5://127.0.0.1:19120 --proxy u1=socks5://127.0.0.1:19121 --proxy u2=socks5://127.0.0.1:19122 --proxy u3=socks5://127.0.0.1:19123 \
  --proxy u4=socks5://127.0.0.1:19124 --proxy u5=socks5://127.0.0.1:19125 --proxy u6=socks5://127.0.0.1:19126 --proxy u7=socks5://127.0.0.1:19127 \
  --rule "python3*:198.51.100.20:5300:UDP:PROXY=u0" --rule "python3*:198.51.100.21:5300:UDP:PROXY=u1" \
  --rule "python3*:198.51.100.22:5300:UDP:PROXY=u2" --rule "python3*:198.51.100.23:5300:UDP:PROXY=u3" \
  --rule "python3*:198.51.100.24:5300:UDP:PROXY=u4" --rule "python3*:198.51.100.25:5300:UDP:PROXY=u5" \
  --rule "python3*:198.51.100.26:5300:UDP:PROXY=u6" --rule "python3*:198.51.100.27:5300:UDP:PROXY=u7" \
  --rule "python3*:198.51.100.100:5300:UDP:BLOCK" --rule "python3*:198.51.100.110:5300:UDP:PROXY=c" \
  --rule "python3*:$MYIP:5301:UDP:DIRECT" --rule "python3*:198.51.100.30-198.51.100.99:5300:UDP:PROXY=a" \
  --rule "python3*:2001:db8::/32:*:UDP:PROXY=a" > "$WORK/pb.out" 2>&1 & PB_PID=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
grep -q "ProxyBridge started" "$WORK/pb.out" || { echo "ProxyBridge failed to start"; cat "$WORK/pb.out"; exit 1; }
sleep 1

echo "== a normal SOCKS5 proxy"
out=$(probe echo 198.51.100.31 5300 hello);   want "unconnected socket: reply comes from the destination" "$out" "RESULT REPLY 198.51.100.31:5300 UDP-A 198.51.100.31:5300 hello"
out=$(probe multi 198.51.100.40 5 5300);      want "one socket, five destinations" "$out" "RESULT ok every destination answered from its own address"
nowant "...with the right replies" "$out" "RESULT BAD"
out=$(probe connected 198.51.100.41 5300);    want "connected socket" "$out" "RESULT ok connected socket gets both replies"
want "getpeername reports the real destination" "$out" "RESULT ok getpeername shows the real destination"
out=$(probe many 198.51.100.42 5300 150);     want "150 sockets at once" "$out" "RESULT ok 150 sockets, each got its own reply"
out=$(probe sizes 198.51.100.43 5300);        want "datagram sizes 1..60000" "$out" "RESULT ok payloads of 1..60000 bytes survive the round trip"
out=$(probe boundport 198.51.100.44 5300);    want "reply returns to the bound local port" "$out" "RESULT ok reply arrives on the bound port"
out=$(probe v6connected 2001:db8::7 5300);    want "connected IPv6 destination through the proxy" "$out" "RESULT ok connected IPv6 UDP goes through the proxy"
out=$(probe v6unconnected 2001:db8::8 5300);  want "unconnected IPv6 sendto fails closed" "$out" "RESULT ok unconnected IPv6 sendto fails closed"
nowant "...and nothing was sent in the clear or through the proxy" "$(cat "$WORK/proxy.log")" "2001:db8::8"

echo "== rule outcomes"
out=$(probe blocked 198.51.100.100 5300);     want "BLOCK" "$out" "RESULT ok BLOCK refuses sendto"
out=$(probe echo $MYIP 5301 direct);          want "DIRECT bypasses every proxy" "$out" "DIRECT-ECHO direct"
out=$(probe echo 198.51.100.110 5300 http 2); want "UDP through an HTTP proxy gets no reply" "$out" "RESULT NOREPLY"
logged "...and the log says why" "cannot carry UDP"

echo "== misbehaving SOCKS5 UDP proxies"
out=$(probe echo 198.51.100.20 5300 hello);   want "BND.ADDR 0.0.0.0: the proxy's own address is used" "$out" "UDP-U 198.51.100.20:5300 hello"
out=$(probe echo 198.51.100.21 5300 hello 2); want "BND is a domain name: refused, no hang" "$out" "RESULT NOREPLY"
logged "...with a readable reason" "UDP relay address is a domain name"
out=$(probe echo 198.51.100.22 5300 hello);   want "BND is an IPv6 address" "$out" "UDP-U 198.51.100.22:5300 hello"
out=$(probe echo 198.51.100.23 5300 SPOOF-1 2); want "reply from a stranger is dropped" "$out" "RESULT NOREPLY"
out=$(probe echo 198.51.100.23 5300 plain);   want "...and the proxy's own replies still work" "$out" "UDP-U 198.51.100.23:5300 plain"
out=$(probe echo 198.51.100.24 5300 FRAG 2);  want "fragmented reply (FRAG != 0) is dropped" "$out" "RESULT NOREPLY"
out=$(probe echo 198.51.100.24 5300 SHORT 2); want "truncated reply is dropped" "$out" "RESULT NOREPLY"
out=$(probe echo 198.51.100.24 5300 DOM);     want "reply with a domain address is mapped to its flow" "$out" "RESULT REPLY 198.51.100.24:5300 UDP-U 198.51.100.24:5300 DOM"
out=$(probe echo 198.51.100.24 5300 ZERO);    want "empty datagram is delivered" "$out" "RESULT REPLY 198.51.100.24:5300 "
out=$(probe echo 198.51.100.24 5300 OK);      want "relay is healthy after malformed replies" "$out" "UDP-U 198.51.100.24:5300 OK"
out=$(probe echo 198.51.100.25 5300 hello 2); want "association refused: no reply, no hang" "$out" "RESULT NOREPLY"
logged "...with the proxy's reason" "command not supported"
out=$(probe echo 198.51.100.27 5300 hello 2); want "proxy that swallows datagrams: no reply, no hang" "$out" "RESULT NOREPLY"
out=$(probe seq 198.51.100.26 5300 one two three)
want "control connection dropped by the proxy: a new association is made" "$out" "UDP-U 198.51.100.26:5300 three"
nowant "...every datagram was answered" "$out" "NOREPLY"
logged "...and logged" "control connection closed"
out=$(probe echo 198.51.100.31 5300 after);   want "the relay is still healthy at the end" "$out" "UDP-A 198.51.100.31:5300 after"

kill -INT "$PB_PID" 2>/dev/null; wait "$PB_PID" 2>/dev/null; PB_PID=""
echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
