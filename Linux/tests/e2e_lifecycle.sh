#!/bin/bash
# Process lifecycle: however ProxyBridge ends, the machine's networking goes back to normal; relay ports already taken, rapid
# restarts, two instances at once. Needs root, python3, bpftool.   sudo Linux/tests/e2e_lifecycle.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
BPFTOOL="${BPFTOOL:-bpftool}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"; PASS=0; FAIL=0; PB=""; PB2=""; HOLD_T=""; HOLD_U=""; FAKE=""
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup() { kill -9 $PB $PB2 $FAKE $HOLD_T $HOLD_U 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & FAKE=$!
sleep 1
progs() { "$BPFTOOL" prog show 2>/dev/null | grep -c "pb_connect4"; }
RULE="python3*:192.0.2.0/24:80:TCP:PROXY=a"
start() { # outfile args... ; sets PB
  local out="$1"; shift
  stdbuf -oL "$PBL" --verbose 1 --proxy a=socks5://127.0.0.1:19080 --rule "$RULE" "$@" > "$out" 2>&1 & PB=$!
  for _ in $(seq 40); do grep -q "ProxyBridge started" "$out" && return 0; kill -0 $PB 2>/dev/null || return 1; sleep 0.25; done; return 1
}
get() { python3 - "$1" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect((sys.argv[1], 80)); s.sendall(b"GET / HTTP/1.0\r\n\r\n"); d = s.recv(500)
    print("DATA" if b"hello-from" in d else "OTHER")
except socket.timeout: print("TIMEOUT")
except OSError as e: print("ERROR", e.errno)
PY
}

echo "== however it ends, the datapath is gone"
for sig in KILL TERM INT HUP; do
  start "$WORK/pb.out" || { bad "SIG$sig: start"; continue; }
  [ "$(progs)" -ge 1 ] && [ "$(get 192.0.2.7)" = DATA ] && ok "SIG$sig: running and redirecting" || bad "SIG$sig: not running properly ($(progs) programs)"
  kill -$sig $PB 2>/dev/null; wait $PB 2>/dev/null; rc=$?
  sleep 0.5
  [ "$(progs)" = 0 ] && ok "SIG$sig: no BPF program is left" || bad "SIG$sig: $(progs) programs left behind"
  [ "$(get 192.0.2.7)" != DATA ] && ok "SIG$sig: new connections are no longer redirected" || bad "SIG$sig: still redirected"
  case $sig in INT|TERM) [ $rc = 0 ] && ok "SIG$sig: clean exit code" || bad "SIG$sig: exit code $rc";; esac
done
PB=""

echo "== relay ports that are already taken"
python3 - > /dev/null 2>&1 <<'PY' & HOLD_T=$!
import socket, time
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("127.0.0.1", 24010)); t.listen(1)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 24013))
time.sleep(600)
PY
sleep 0.5
start "$WORK/pb.out" || bad "start with busy ports"
grep -q "relay tcp:24014 udp:24015" "$WORK/pb.out" && ok "the relay moved to free ports (24014/24015)" || bad "ports: $(grep 'relay tcp' "$WORK/pb.out")"
[ "$(get 192.0.2.7)" = DATA ] && ok "traffic is relayed through the alternative ports" || bad "no traffic on alternative ports"
kill -INT $PB; wait $PB 2>/dev/null; PB=""; kill $HOLD_T 2>/dev/null

echo "== 20 quick restarts"
good=0
for i in $(seq 20); do
  start "$WORK/pb.out" || continue
  [ "$(get 192.0.2.7)" = DATA ] && good=$((good+1))
  kill -INT $PB; wait $PB 2>/dev/null; PB=""
done
[ $good = 20 ] && ok "20 of 20 start/serve/stop cycles worked" || bad "only $good of 20 cycles worked"
[ "$(progs)" = 0 ] && ok "nothing left behind" || bad "$(progs) programs left behind"

echo "== two instances at once"
start "$WORK/a.out" || bad "first instance"
PA=$PB
stdbuf -oL "$PBL" --verbose 1 --proxy a=socks5://127.0.0.1:19080 --rule "python3*:192.0.2.0/24:81:TCP:PROXY=a" > "$WORK/b.out" 2>&1 & PB2=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/b.out" && break; sleep 0.25; done
grep -q "ProxyBridge started" "$WORK/b.out" && ok "a second instance starts next to the first" || bad "second instance: $(tail -3 "$WORK/b.out")"
[ "$(get 192.0.2.7)" = DATA ] && ok "the first instance's rule still works" || bad "first instance broken by the second"
kill -INT $PB2; wait $PB2 2>/dev/null; PB2=""
sleep 0.5
[ "$(get 192.0.2.7)" = DATA ] && ok "...and after the second one exits" || bad "first instance broken after the second exited"
kill -INT $PA; wait $PA 2>/dev/null; PB=""
[ "$(progs)" = 0 ] && ok "both gone: no programs left" || bad "$(progs) programs left"

echo "== a program that is already running keeps its sockets"
python3 - "$WORK" > "$WORK/long.out" 2>&1 <<'PY' & HOLD_U=$!
import socket, sys, time
s = socket.socket(); s.settimeout(30); s.connect(("127.0.0.1", 19080)) ; print("connected", flush=True)
time.sleep(5)
try:
    s.sendall(b"\x05\x01\x00"); print("still usable", flush=True)
except OSError as e:
    print("broken", e, flush=True)
PY
sleep 1
start "$WORK/pb.out"; kill -INT $PB; wait $PB 2>/dev/null; PB=""
sleep 5
grep -q "still usable" "$WORK/long.out" && ok "an existing connection survives ProxyBridge starting and stopping" || bad "existing connection: $(cat "$WORK/long.out")"

echo "== starting when it cannot work"
cat > "$WORK/probe.c" <<'C'
#include <stdio.h>
#include <string.h>
#include "ProxyBridge.h"
static void log_cb(const char *m) { printf("log: %s\n", m); }
int main(int argc, char **argv)
{
    char err[200];
    ProxyBridge_SetLogCallback(log_cb);
    if (argc > 1 && !strcmp(argv[1], "withproxy")) ProxyBridge_AddProxy("a", PROXY_TYPE_SOCKS5, "127.0.0.1", 19080, "", "", err, sizeof err);
    ProxyBridge_AddRule("curl", "*", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 0, err, sizeof err);
    printf("start=%d\n", ProxyBridge_Start());
    printf("stop=%d\n", ProxyBridge_Stop());
    return 0;
}
C
if gcc -O1 -I"$ROOT/src" -o "$WORK/probe" "$WORK/probe.c" -L"$PB_DIR" -lproxybridge; then
  chmod 755 "$WORK" "$WORK/probe"
  out=$("$WORK/probe" 2>&1)
  [[ "$out" == *"start=0"* && "$out" == *"no proxy is configured"* ]] && ok "a PROXY rule without any proxy refuses to start and says why" || bad "no proxy: $out"
  # the unprivileged user must be able to reach the library wherever the build lives (a CI runner's home folder is not world-readable)
  mkdir -p "$WORK/lib"; chmod 755 "$WORK/lib"; install -m 755 "$PB_DIR/libproxybridge.so" "$WORK/lib/libproxybridge.so"
  out=$(setpriv --reuid=65534 --regid=65534 --clear-groups env LD_LIBRARY_PATH="$WORK/lib" "$WORK/probe" withproxy 2>&1)
  [[ "$out" == *"start=0"* && "$out" == *"needs root"* ]] && ok "without root it fails cleanly and explains" || bad "not root: $out"
  [[ "$out" == *"stop=1"* ]] && ok "Stop after a failed Start is harmless" || bad "stop after failed start: $out"
  [ "$(progs)" = 0 ] && ok "a failed start attaches nothing" || bad "programs attached by a failed start"
else
  bad "could not build the probe"
fi

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
