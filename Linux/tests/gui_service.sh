#!/bin/bash
# The real ProxyBridgeGUI binary run by an UNPRIVILEGED user (Broadway, no desktop window) in front of a real ProxyBridge service:
# access control, loading the profile from the service, routing with no root in the window, and what closing the window does.
#   sudo Linux/tests/gui_service.sh [dir with ProxyBridge, ProxyBridgeGUI and libproxybridge.so]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${1:-${PB_DIR:-$ROOT/output}}"
GUI="$PB_DIR/ProxyBridgeGUI"; PB="$PB_DIR/ProxyBridge"
[ -x "$GUI" ] && [ -x "$PB" ] || { echo "Build first (Linux/build.sh) or pass the directory"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
command -v broadwayd >/dev/null && command -v setpriv >/dev/null || { echo "SKIP: needs broadwayd and setpriv"; exit 0; }
[ ! -e /run/proxybridge/ctl.sock ] || { echo "SKIP: a ProxyBridge service is already running here"; exit 0; }
WORK="$(mktemp -d)"; chmod 755 "$WORK"
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
MADE_GROUP=0
cleanup() {
  # system state first: nothing below may keep this from running (a stuck child must not leave the user in the group)
  gpasswd -d nobody proxybridge >/dev/null 2>&1; [ $MADE_GROUP = 1 ] && groupdel proxybridge 2>/dev/null
  kill $GUI_PID $DPID $FAKE $BW 2>/dev/null; sleep 0.5; kill -KILL $GUI_PID $DPID $FAKE $BW 2>/dev/null
  rm -rf "$WORK" /run/proxybridge
}
GUI_PID=; DPID=; FAKE=; BW=
trap cleanup EXIT
getent group proxybridge >/dev/null || { groupadd -r proxybridge && MADE_GROUP=1; }

python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" >/dev/null 2>&1 & FAKE=$!
mkdir -p "$WORK/cfg" "$WORK/home" "$WORK/bin" "$WORK/xdg"; chown nobody "$WORK/home" "$WORK/xdg"; chmod 700 "$WORK/xdg"
# the display server belongs to the same unprivileged user as the window
( ulimit -c 0; exec env XDG_RUNTIME_DIR="$WORK/xdg" HOME="$WORK/home" setpriv --reuid=nobody --regid=nogroup --clear-groups broadwayd :9 ) >/dev/null 2>&1 & BW=$!
# the window runs as another user: it, and the library next to it, must be reachable by that user wherever the build lives
install -m 755 "$GUI" "$WORK/bin/ProxyBridgeGUI"; install -m 755 "$PB_DIR/libproxybridge.so" "$WORK/bin/libproxybridge.so"
GUI="$WORK/bin/ProxyBridgeGUI"
sleep 1.5
bpf_up() { "${BPFTOOL:-bpftool}" prog show 2>/dev/null | grep -q pb_connect4; }
start_service() { PROXYBRIDGE_CONFIG_DIR="$WORK/cfg" "$PB" --daemon --verbose 1 > "$WORK/daemon.log" 2>&1 & DPID=$!
  for _ in $(seq 40); do [ -S /run/proxybridge/ctl.sock ] && break; sleep 0.25; done; }
stop_service() { kill $DPID 2>/dev/null; wait $DPID 2>/dev/null; DPID=; }
seed() { # start-at-boot (0/1)
python3 - "$1" <<PY
import sys, json
sys.path.insert(0, "$HERE")
import pbd
d = pbd.Daemon.connect("/run/proxybridge/ctl.sock"); d.ok("hello", "1")
prof = {"Version": "1.0", "Name": "Default", "IsTrafficLoggingEnabled": True, "ProxyConfigs": [
  {"Id": 1, "Name": "a", "Type": "SOCKS5", "Host": "127.0.0.1", "Port": "19080", "Username": "", "Password": "", "SendDomainToProxy": True}],
  "ProxyRules": [{"Name": "r", "ProcessName": "curl", "TargetHosts": "192.0.2.0/24", "TargetPorts": "*", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": True, "ProxyConfigId": 1}]}
d.ok("store.put", "Default", json.dumps(prof))
d.ok("store.settings.set", "Default", "1", sys.argv[1])
PY
}
run_gui() { # user group-args...
  local who="$1"; shift
  GDK_BACKEND=broadway BROADWAY_DISPLAY=:9 HOME="$WORK/home" XDG_RUNTIME_DIR="$WORK/xdg" \
    setpriv --reuid="$who" --regid=nogroup "$@" "$GUI" > "$WORK/gui.out" 2>&1 & GUI_PID=$!
}
wait_routing() { for _ in $(seq 40); do bpf_up && return 0; kill -0 $GUI_PID 2>/dev/null || return 1; sleep 0.25; done; return 1; }
stop_gui() { kill -TERM $GUI_PID 2>/dev/null; for _ in $(seq 40); do kill -0 $GUI_PID 2>/dev/null || break; sleep 0.25; done
  if kill -0 $GUI_PID 2>/dev/null; then kill -KILL $GUI_PID; bad "the window did not exit on SIGTERM"; else wait $GUI_PID; fi; GUI_PID=; }

echo "== upgrade: the config.ini of 3.2.x / the Linux beta is converted through the service"
cat > "$WORK/cfg/config.ini" <<CFG
[SETTINGS]
activeProfile=Default
logging=1
dns=1
[PROFILE:Default]
defaultProxy=a
[PROXIES]
a|1|127.0.0.1|19080||
[RULES]
1|0|0|1|curl|192.0.2.0/24|*|a
CFG
chmod 600 "$WORK/cfg/config.ini"
usermod -aG proxybridge nobody
start_service
run_gui nobody --clear-groups
if wait_routing; then ok "the window started the engine from the old configuration"; else bad "no routing: $(head -5 "$WORK/gui.out")"; fi
sleep 1
out=$(curl -s -m 5 http://192.0.2.7/); [[ "$out" == *"hello-from-A dst=192.0.2.7:80"* ]] && ok "the old rule and proxy work through the service" || bad "old configuration not applied: $out"
stop_gui
[ -f "$WORK/cfg/profiles/Default.pbprofile" ] && ok "it became a profile held by the service" || bad "no profile written: $(ls "$WORK/cfg" "$WORK/cfg/profiles" 2>&1)"
[ -f "$WORK/cfg/config.ini.bak" ] && [ ! -f "$WORK/cfg/config.ini" ] && ok "the old file was set aside as config.ini.bak" || bad "config.ini handling"
stop_service
rm -rf "$WORK/cfg"; mkdir -p "$WORK/cfg"

echo "== the service is running, the window is not root"
start_service
ok "service started (socket present)"
seed 0
out=$(curl -s -m 3 http://192.0.2.7/ 2>&1); [[ "$out" != *hello-from* ]] && ok "nothing is routed before a window asks (Start at Boot off)" || bad "routed without a window"

echo "== a user who is not in the group"
gpasswd -d nobody proxybridge >/dev/null 2>&1
run_gui nobody --clear-groups
sleep 3
kill -0 $GUI_PID 2>/dev/null && ok "the window stays up showing its error (no crash)" || bad "window died: $(head -3 "$WORK/gui.out")"
grep -q "refused a connection from user" "$WORK/daemon.log" && ok "the service refused that user and said so" || bad "no refusal in the service log"
out=$(curl -s -m 3 http://192.0.2.7/ 2>&1); [[ "$out" != *hello-from* ]] && ok "a refused window changes nothing" || bad "routed for a refused user"
kill -KILL $GUI_PID 2>/dev/null; wait $GUI_PID 2>/dev/null; GUI_PID=

echo "== a member of the group (added just now, no new login)"
usermod -aG proxybridge nobody
run_gui nobody --clear-groups
if wait_routing; then ok "the window started the engine through the service"; else bad "no routing: $(head -5 "$WORK/gui.out")"; fi
sleep 1
uid=$(stat -c %u /proc/$GUI_PID 2>/dev/null)
[ -n "$uid" ] && [ "$uid" != 0 ] && ok "the window runs as an ordinary user (uid $uid)" || bad "window uid: $uid"
out=$(curl -s -m 5 http://192.0.2.7/); [[ "$out" == *"hello-from-A dst=192.0.2.7:80"* ]] && ok "the profile held by the service routes traffic" || bad "not routed: $out"
stop_gui
sleep 1
out=$(curl -s -m 3 http://192.0.2.7/ 2>&1); [[ "$out" != *hello-from* ]] && ok "Start at Boot off: closing the window stops routing" || bad "still routed after the window closed"

echo "== Start at Boot on: routing continues after the window closes"
python3 - <<PY
import sys; sys.path.insert(0, "$HERE")
import pbd
d = pbd.Daemon.connect("/run/proxybridge/ctl.sock"); d.ok("hello", "1"); d.ok("boot.set", "1")
PY
run_gui nobody --clear-groups
wait_routing && ok "window started" || bad "window did not start routing"
sleep 1
stop_gui
sleep 1
out=$(curl -s -m 5 http://192.0.2.7/); [[ "$out" == *"hello-from-A"* ]] && ok "the service keeps routing after the window closed" || bad "routing stopped with the window: $out"

echo "== the service restarts while a window is open"
python3 - <<PY
import sys; sys.path.insert(0, "$HERE")
import pbd
d = pbd.Daemon.connect("/run/proxybridge/ctl.sock"); d.ok("hello", "1"); d.ok("boot.set", "0")
PY
run_gui nobody --clear-groups
wait_routing && ok "window started" || bad "window did not start routing"
sleep 1
stop_service
out=$(curl -s -m 3 http://192.0.2.7/ 2>&1); [[ "$out" != *hello-from* ]] && ok "the service is gone: traffic is direct" || bad "still routed"
start_service
back=0
for _ in $(seq 40); do out=$(curl -s -m 2 http://192.0.2.7/ 2>&1); [[ "$out" == *"hello-from-A"* ]] && { back=1; break; }; sleep 0.5; done
[ $back = 1 ] && ok "the open window reconnected, sent its rules again and restarted the engine" || bad "routing did not come back after the service restarted"
kill -0 $GUI_PID 2>/dev/null && ok "the window stayed open throughout" || bad "the window died"
stop_gui
python3 - <<PY
import sys; sys.path.insert(0, "$HERE")
import pbd
d = pbd.Daemon.connect("/run/proxybridge/ctl.sock"); d.ok("hello", "1"); d.ok("boot.set", "1")
PY

echo "== the service restarts: a fresh service applies the profile by itself"
stop_service
out=$(curl -s -m 3 http://192.0.2.7/ 2>&1); [[ "$out" != *hello-from* ]] && ok "stopping the service ends routing (fail-open)" || bad "routed with no service"
start_service
sleep 1.5
out=$(curl -s -m 5 http://192.0.2.7/); [[ "$out" == *"hello-from-A"* ]] && ok "at start the service applies the active profile (Start at Boot on)" || bad "not applied at start: $out"
stop_service

echo "== no service at all, window run as a normal user"
run_gui nobody --clear-groups
sleep 3
kill -0 $GUI_PID 2>/dev/null && ok "the window explains that the service is not running (does not crash or hang the desktop)" || bad "window died: $(head -3 "$WORK/gui.out")"
kill -KILL $GUI_PID 2>/dev/null; wait $GUI_PID 2>/dev/null; GUI_PID=

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "---- gui"; cat "$WORK/gui.out"; echo "---- service"; tail -20 "$WORK/daemon.log"; exit 1; }
