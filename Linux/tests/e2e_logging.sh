#!/bin/bash
# Connection log: one line per (application, destination, action) by default, every connection with --log-every-connection,
# and exactly one line per decision (the kernel and the relay used to report proxied flows twice). Needs root, python3.
#   sudo Linux/tests/e2e_logging.sh        (PB_SLOW=1 also waits out the 30 s UDP re-log window)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"; PASS=0; FAIL=0; PB_PID=""
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup() { [ -n "$PB_PID" ] && kill "$PB_PID" 2>/dev/null; kill $FAKE 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & FAKE=$!
sleep 1

start_pb() {
  stdbuf -oL "$PBL" --verbose 2 --proxy a=socks5://127.0.0.1:19080 "$@" > "$WORK/pb.out" 2>&1 & PB_PID=$!
  for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && return 0; sleep 0.25; done; return 1
}
stop_pb() { kill -INT "$PB_PID" 2>/dev/null; wait "$PB_PID" 2>/dev/null; PB_PID=""; }
lines() { grep -c -- "$1" "$WORK/pb.out"; }
# Wait until the output has stopped growing (not a fixed second: on a loaded machine the lines arrive late, and a count taken too early is wrong)
settle() { local last=-1 now stable=0 i; for i in $(seq 100); do now=$(wc -c < "$WORK/pb.out"); if [ "$now" = "$last" ]; then stable=$((stable+1)); else stable=0; fi; last=$now; [ $stable -ge 6 ] && return 0; sleep 0.2; done; }
connects() { python3 - "$@" <<'PY'
import socket, sys
ip, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for _ in range(n):
    s = socket.socket(); s.setblocking(False); s.connect_ex((ip, port)); s.close()
PY
}
udp_sends() { python3 - "$@" <<'PY'
import socket, sys, time
ip, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(n):
    s.sendto(b"x", (ip, port)); time.sleep(0.05)
PY
}

RULES=(--rule "python3*:198.51.100.50:80:TCP:PROXY=a" --rule "python3*:198.51.100.51:80:TCP:BLOCK" --rule "python3*:198.51.100.52:80:TCP:DIRECT"
       --rule "python3*:198.51.100.60-198.51.100.63;198.51.100.70;198.51.100.71;198.51.100.72;198.51.100.73;198.51.100.74;198.51.100.75:80:TCP:PROXY=a"
       --rule "python3*:198.51.100.80:5300:UDP:PROXY=a")

echo "== default: repeats are collapsed"
start_pb "${RULES[@]}" || bad "start"
connects 198.51.100.50 80 6; connects 198.51.100.51 80 4; connects 198.51.100.52 80 4; settle
[ "$(lines '198.51.100.50:80 via SOCKS5')" = 1 ] && ok "6 proxied connections: one line (not two per connection)" || bad "proxied: $(lines '198.51.100.50:80 via')"
[ "$(lines '198.51.100.51:80 via BLOCK')" = 1 ] && ok "4 blocked connections: one line" || bad "blocked: $(lines '198.51.100.51:80 via')"
[ "$(lines '198.51.100.52:80 via DIRECT')" = 1 ] && ok "4 direct connections: one line" || bad "direct: $(lines '198.51.100.52:80 via')"
connects 198.51.100.61 80 5; settle
[ "$(lines '198.51.100.61:80 via SOCKS5')" = 1 ] && ok "decided by the relay (long host list), process already gone: one proxied line" || bad "slow path: $(grep '198.51.100.61' "$WORK/pb.out")"
udp_sends 198.51.100.80 5300 8; settle
[ "$(lines '198.51.100.80:5300 via')" = 1 ] && ok "a UDP flow of 8 datagrams: one line" || bad "udp: $(lines '198.51.100.80:5300 via')"
stop_pb

echo "== --log-every-connection true"
start_pb --log-every-connection true "${RULES[@]}" || bad "start"
connects 198.51.100.50 80 6; connects 198.51.100.51 80 4; connects 198.51.100.52 80 4; settle
[ "$(lines '198.51.100.50:80 via SOCKS5')" = 6 ] && ok "every proxied connection is listed, each exactly once" || bad "proxied: $(lines '198.51.100.50:80 via')"
[ "$(lines '198.51.100.51:80 via BLOCK')" = 4 ] && ok "every blocked connection is listed" || bad "blocked: $(lines '198.51.100.51:80 via')"
[ "$(lines '198.51.100.52:80 via DIRECT')" = 4 ] && ok "every direct connection is listed" || bad "direct: $(lines '198.51.100.52:80 via')"
connects 198.51.100.61 80 5; settle
[ "$(lines '198.51.100.61:80 via SOCKS5')" = 5 ] && ok "decided by the relay: every connection, once" || bad "slow path: $(lines '198.51.100.61:80 via')"
udp_sends 198.51.100.80 5300 8; settle
[ "$(lines '198.51.100.80:5300 via')" = 1 ] && ok "a busy UDP flow is still one line" || bad "udp: $(lines '198.51.100.80:5300 via')"
if [ "${PB_SLOW:-0}" = 1 ]; then
  sleep 31; udp_sends 198.51.100.80 5300 1; settle
  [ "$(lines '198.51.100.80:5300 via')" = 2 ] && ok "after 30 s of silence the UDP flow is listed again" || bad "udp relog: $(lines '198.51.100.80:5300 via')"
fi
stop_pb

echo "== a profile can switch it on"
cat > "$WORK/le.pbprofile" <<'JSON'
{ "Version": "1.0", "LogEveryConnection": true,
  "ProxyConfigs": [ { "Id": 1, "Name": "a", "Type": "socks5", "Host": "127.0.0.1", "Port": "19080" } ],
  "ProxyRules": [ { "ProcessName": "python3*", "TargetHosts": "198.51.100.50", "TargetPorts": "80", "Protocol": "TCP", "Action": "PROXY", "ProxyConfigId": 1 } ] }
JSON
chmod 600 "$WORK/le.pbprofile"
stdbuf -oL "$PB_DIR/ProxyBridge" --verbose 2 --profile "$WORK/le.pbprofile" > "$WORK/pb.out" 2>&1 & PB_PID=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
connects 198.51.100.50 80 3; settle
[ "$(lines '198.51.100.50:80 via SOCKS5')" = 3 ] && ok "LogEveryConnection from the profile" || bad "profile: $(lines '198.51.100.50:80 via')"
stop_pb
start_pb --log-every-connection false "${RULES[@]}" || bad "start"
stop_pb
stdbuf -oL "$PBL" --verbose 2 --profile "$WORK/le.pbprofile" --log-every-connection false > "$WORK/pb.out" 2>&1 & PB_PID=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
connects 198.51.100.50 80 3; settle
[ "$(lines '198.51.100.50:80 via SOCKS5')" = 1 ] && ok "the command line overrides the profile" || bad "override: $(lines '198.51.100.50:80 via')"
stop_pb
cat > "$WORK/le2.pbprofile" <<'JSON'
{ "Version": "1.0", "LogEveryConnection": false,
  "ProxyConfigs": [ { "Id": 1, "Name": "a", "Type": "socks5", "Host": "127.0.0.1", "Port": "19080" } ],
  "ProxyRules": [ { "ProcessName": "python3*", "TargetHosts": "198.51.100.50", "TargetPorts": "80", "Protocol": "TCP", "Action": "PROXY", "ProxyConfigId": 1 } ] }
JSON
chmod 600 "$WORK/le2.pbprofile"
stdbuf -oL "$PB_DIR/ProxyBridge" --verbose 2 --profile "$WORK/le2.pbprofile" > "$WORK/pb.out" 2>&1 & PB_PID=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
connects 198.51.100.50 80 3; settle
[ "$(lines '198.51.100.50:80 via SOCKS5')" = 1 ] && ok "LogEveryConnection=false in the profile collapses repeats" || bad "profile false: $(lines '198.51.100.50:80 via')"
stop_pb

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
