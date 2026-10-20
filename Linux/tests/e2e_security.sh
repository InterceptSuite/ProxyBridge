#!/bin/bash
# Security checks on the relay hand-off. Needs root, bpftool, python3.   sudo tests/e2e_security.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
BPFTOOL="${BPFTOOL:-bpftool}"; command -v "$BPFTOOL" >/dev/null || { echo "bpftool not found (set BPFTOOL)"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export LD_LIBRARY_PATH="$PB_DIR"
WORK="$(mktemp -d)"; PLOG="$WORK/proxy.log"; : > "$PLOG"; PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup() { kill $FAKE $PB 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

python3 "$HERE/fake_proxies.py" "$PLOG" >/dev/null 2>&1 & FAKE=$!
sleep 1
stdbuf -oL "$PBL" --verbose 1 --proxy a=socks5://127.0.0.1:19080 --rule "curl:192.0.2.1:*:TCP:PROXY=a" > "$WORK/pb.out" 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
RELAY=$(sed -n 's/.*relay tcp:\([0-9]*\) udp.*/\1/p' "$WORK/pb.out" | head -1)
[ -n "$RELAY" ] || { echo "ProxyBridge did not start"; cat "$WORK/pb.out"; exit 1; }

PORT=40123
# plant the kind of entry the kernel creates for a redirected connection from 127.0.0.1:PORT -> 192.0.2.99:80 via proxy 1
HEXKEY=$(python3 -c "import struct,socket;print(' '.join('%02x'%b for b in socket.inet_aton('127.0.0.1')+struct.pack('<I',$PORT)))")
HEXVAL=$(python3 - <<PY
import struct, socket
v = bytes(10) + b"\xff\xff" + socket.inet_aton("192.0.2.99") + struct.pack("<HHI", 80, 1, 4242) + bytes([2, 6, 0, 0]) + struct.pack("<II4xQ", 0, 0, 0)
print(" ".join("%02x" % b for b in v))
PY
)
plant() { "$BPFTOOL" map update name by_port key hex $HEXKEY value hex $HEXVAL >/dev/null 2>&1; }
planted() { "$BPFTOOL" map lookup name by_port key hex $HEXKEY >/dev/null 2>&1; }

try_connect() { # source ip -> prints "closed" or "open"
python3 - "$1" $PORT $RELAY <<'PY'
import socket, sys
src, port, relay = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((src, port)); s.settimeout(3)
try:
    s.connect(("127.0.0.1", relay)); s.sendall(b"GET / HTTP/1.0\r\n\r\n"); d = s.recv(100)
    print("closed" if not d else "open:" + d[:30].decode(errors="replace"))
except (ConnectionError, socket.timeout) as e:
    print("closed")
PY
}

plant && planted && ok "test setup: a pending flow entry for 127.0.0.1:$PORT is in the kernel map" || { bad "could not plant the map entry (bpftool map update)"; exit 1; }
r=$(try_connect 127.0.0.2); [ "$r" = closed ] && ok "a process connecting from 127.0.0.2 with the same source port is refused" || bad "foreign source address was served ($r)"
grep -q "192.0.2.99" "$PLOG" && bad "the foreign connection reached the proxy" || ok "nothing reached the proxy for the foreign connection"
planted && ok "the legitimate pending entry survived the attempt" || bad "the foreign attempt consumed the victim's entry"
r=$(try_connect 127.0.0.1); sleep 1
grep -q "A TCP 192.0.2.99:80" "$PLOG" && ok "the legitimate source (127.0.0.1) claims the entry and is proxied" || bad "legitimate connection was not proxied ($r)"
planted && bad "the entry was not consumed" || ok "the entry is consumed after use (no replay)"
r=$(try_connect 127.0.0.1); [ "$r" = closed ] && ok "a second connection with no pending entry is refused" || bad "relay served a connection without a pending entry ($r)"

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "--- proxy log"; cat "$PLOG"; exit 1; }
