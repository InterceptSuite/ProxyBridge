#!/bin/bash
# A rule such as "*:...:PROXY" also matches the proxy's own outbound connections. ProxyBridge exempts the processes that listen on a
# configured local proxy address, so they cannot loop back through themselves. Needs root, python3, curl.
#   sudo Linux/tests/e2e_exempt.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"; PASS=0; FAIL=0; PB=""; FWD=""; WWW=""
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
diag() { echo "---- diagnostics: ProxyBridge output"; tail -15 "$WORK/pb.out" 2>/dev/null; echo "---- proxy log"; tail -8 "$WORK/fwd.log" 2>/dev/null; echo "---- address and kernel"; echo "origin address: $MYIP"; uname -r; ip -4 addr show 2>/dev/null | grep -E 'inet |^[0-9]' | head -8; echo "----"; }
cleanup() { kill $PB $FWD $WWW 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
MYIP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
[ -n "$MYIP" ] || { echo "no non-loopback address: skipped"; exit 0; }
mkdir -p "$WORK/www"; echo "origin-ok" > "$WORK/www/index.html"
python3 -m http.server 18399 --bind "$MYIP" --directory "$WORK/www" > /dev/null 2>&1 & WWW=$!
sleep 1
start_pb() { # proxy spec
  stdbuf -oL "$PBL" --verbose 1 --proxy "fwd=$1" --rule "*:$MYIP:18399:TCP:PROXY=fwd" > "$WORK/pb.out" 2>&1 & PB=$!
  for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && return 0; sleep 0.25; done; return 1
}
stop_pb() { kill -INT $PB 2>/dev/null; wait $PB 2>/dev/null; PB=""; }
start_fwd() { : > "$WORK/fwd.log"; python3 "$HERE/fwd_socks5.py" "$1" "$2" "$WORK/fwd.log" > /dev/null 2>&1 & FWD=$!; sleep 1; }
stop_fwd() { kill $FWD 2>/dev/null; wait $FWD 2>/dev/null; FWD=""; }
fetch() { curl -s -m 4 "http://$MYIP:18399/"; }

echo "== proxy on 127.0.0.1 running first"
start_fwd 127.0.0.1 19090
start_pb socks5://127.0.0.1:19090 || bad "start"
out=$(fetch); [[ "$out" == *origin-ok* ]] && ok "request reaches the origin through the forwarding proxy" || bad "no answer (${out:0:100}): $(tail -3 "$WORK/fwd.log")"
# the proxy may be given the host name of the origin address (ProxyBridge sends the name it knows, e.g. from /etc/hosts), so count by port
n=$(grep -c "^FWD .*:18399" "$WORK/fwd.log")
[ "$n" = 1 ] && ok "the proxy was asked exactly once: its own connection to the origin was not looped back" || { bad "proxy saw $n requests"; diag; }
grep -q "FAIL" "$WORK/fwd.log" && bad "forwarding failed: $(grep FAIL "$WORK/fwd.log")"
stop_pb; stop_fwd

echo "== proxy configured by host name"
start_fwd 127.0.0.1 19090
start_pb socks5://localhost:19090 || bad "start"
out=$(fetch); [[ "$out" == *origin-ok* ]] && ok "proxy given as 'localhost'" || bad "localhost proxy: ${out:0:100}"
stop_pb; stop_fwd

echo "== proxy listening on the machine's own LAN address"
start_fwd "$MYIP" 19091
start_pb "socks5://$MYIP:19091" || bad "start"
out=$(fetch); [[ "$out" == *origin-ok* ]] && ok "proxy bound to $MYIP is recognised as local" || bad "LAN proxy: ${out:0:100} $(tail -2 "$WORK/fwd.log")"
stop_pb; stop_fwd

echo "== proxy that starts after ProxyBridge"
start_pb socks5://127.0.0.1:19090 || bad "start"
out=$(fetch); [[ "$out" != *origin-ok* ]] && ok "nothing listens yet: the request fails (and does not hang)" || bad "unexpected success"
start_fwd 127.0.0.1 19090
good=no
for _ in $(seq 40); do out=$(fetch); if [[ "$out" == *origin-ok* ]]; then good=yes; break; fi; sleep 0.5; done
[ $good = yes ] && ok "once the proxy is up it is exempted and the request works" || bad "never worked after the proxy started"
# the proxy may be given the host name of the origin address (ProxyBridge sends the name it knows, e.g. from /etc/hosts), so count by port
n=$(grep -c "^FWD .*:18399" "$WORK/fwd.log")
[ "$n" -ge 1 ] && [ "$n" -le 2 ] && ok "no request storm from a loop ($n requests)" || { bad "proxy saw $n requests"; diag; }
stop_pb; stop_fwd

echo "== a proxy that is NOT local is not exempted"
start_pb socks5://198.51.100.55:1080 || bad "start"
out=$(fetch); [[ "$out" != *origin-ok* ]] && ok "traffic for the rule goes to the remote proxy (unreachable here), not around it" || bad "bypassed the rule"
stop_pb

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
