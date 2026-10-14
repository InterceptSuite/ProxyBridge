#!/bin/bash
# Runs the real GTK GUI headlessly (GTK Broadway backend, no window on your desktop) against the real engine:
# config loading (profiles, proxies, rules incl. domain rules) -> engine start -> real traffic -> clean shutdown.
# Needs root, broadwayd, dig, curl, and a built GUI: pass the path of ProxyBridgeGUI and of the directory holding libproxybridge.so.
#   sudo tests/gui_headless.sh <ProxyBridgeGUI> <libdir>
set -u
GUI=${1:?path to ProxyBridgeGUI}; LIBDIR=${2:?dir with libproxybridge.so}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"; PLOG="$WORK/proxy.log"; DLOG="$WORK/dns.log"; : > "$PLOG"; : > "$DLOG"
PASS=0; FAIL=0; DNSIP=10.77.0.4
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
has() { [[ "$2" == *"$3"* ]] && ok "$1" || bad "$1 (got: ${2:0:160})"; }
cleanup() { kill $GUI_PID $FAKE $DNSP $BW 2>/dev/null; wait 2>/dev/null; ip addr del $DNSIP/32 dev lo 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
ip addr add $DNSIP/32 dev lo 2>/dev/null
python3 "$HERE/fake_proxies.py" "$PLOG" >/dev/null 2>&1 & FAKE=$!
python3 "$HERE/fake_dns.py" $DNSIP "$DLOG" >/dev/null 2>&1 & DNSP=$!
broadwayd :9 >/dev/null 2>&1 & BW=$!
sleep 1.5

# profile "Default": proxy a (default) + b; "Alt": curl goes through b instead
write_cfg() { # active-profile
mkdir -p "$WORK/cfg"
cat > "$WORK/cfg/config.ini" <<CFG
[SETTINGS]
activeProfile=$1
logging=1
dns=1
[PROFILE:Default]
defaultProxy=a
[PROXIES]
a|1|127.0.0.1|19080||
b|1|127.0.0.1|19081|bob|pw
[RULES]
1|0|0|1|curl|192.0.2.0/26|*|a
2|0|0|1|curl|198.51.100.0/24|*|b
3|0|2|1|curl|203.0.114.0/24|*|
4|0|0|1|*|*.example.test|*|b
5|0|0|0|curl|203.0.113.0/24|*|a
[PROFILE:Alt]
defaultProxy=b
[PROXIES]
b|1|127.0.0.1|19081|bob|pw
[RULES]
1|0|0|1|curl|192.0.2.0/26|*|b
CFG
chmod 600 "$WORK/cfg/config.ini"
}

run_gui() { # active profile
  write_cfg "$1"
  GDK_BACKEND=broadway BROADWAY_DISPLAY=:9 PROXYBRIDGE_CONFIG_DIR="$WORK/cfg" LD_LIBRARY_PATH="$LIBDIR" "$GUI" > "$WORK/gui.out" 2>&1 & GUI_PID=$!
  for _ in $(seq 60); do bpftool prog show 2>/dev/null | grep -q pb_connect4 && break; kill -0 $GUI_PID 2>/dev/null || break; sleep 0.25; done
  sleep 1
}
stop_gui() {
  kill -TERM $GUI_PID 2>/dev/null
  for _ in $(seq 40); do kill -0 $GUI_PID 2>/dev/null || break; sleep 0.25; done
  if kill -0 $GUI_PID 2>/dev/null; then kill -KILL $GUI_PID; bad "GUI did not exit on SIGTERM"; else wait $GUI_PID; rc=$?; [ "$rc" = 0 ] && ok "GUI exits cleanly on SIGTERM (rc=0)" || bad "GUI exit code $rc"; fi
}

echo "== profile Default"
run_gui Default
kill -0 $GUI_PID 2>/dev/null && ok "GUI started under Broadway" || { bad "GUI died: $(head -5 "$WORK/gui.out")"; }
bpftool prog show 2>/dev/null | grep -q pb_connect4 && ok "engine started by the GUI (eBPF programs attached)" || bad "no eBPF programs"
out=$(curl -s -m 5 http://192.0.2.7/);        has "rule 1 from the config file: curl -> proxy a" "$out" "hello-from-A dst=192.0.2.7:80"
out=$(curl -s -m 5 http://198.51.100.7/);     has "rule 2: curl -> proxy b (with credentials from the config)" "$out" "hello-from-B dst=198.51.100.7:80"
out=$(curl -s -m 5 http://203.0.114.7/ 2>&1; echo "rc=$?"); has "rule 3: BLOCK" "$out" "rc=7"
out=$(curl -s -m 2 http://203.0.113.7/ 2>&1; echo "rc=$?"); [[ "$out" != *hello-from* ]] && ok "disabled rule 5 is not applied" || bad "disabled rule applied"
ip4=$(dig @$DNSIP app.example.test +short +time=3 +tries=1 | head -1)
out=$(curl -s -m 5 http://$ip4/);             has "domain rule from the config (*.example.test -> b) after a real DNS lookup" "$out" "hello-from-B dst=192.0.2.77:80"
stop_gui
bpftool prog show 2>/dev/null | grep -q pb_connect && bad "BPF programs left after GUI exit" || ok "programs detached after GUI exit"

echo "== profile Alt (same GUI, different active profile)"
run_gui Alt
out=$(curl -s -m 5 http://192.0.2.7/);        has "Alt profile: same rule now goes through proxy b" "$out" "hello-from-B dst=192.0.2.7:80"
out=$(curl -s -m 2 http://198.51.100.7/ 2>&1; echo "rc=$?"); [[ "$out" != *hello-from* ]] && ok "Alt profile does not apply rules of the Default profile" || bad "Default rules leaked into Alt"
stop_gui
grep -q "^\[PROFILE:Default\]" "$WORK/cfg/config.ini" && grep -q "^\[PROFILE:Alt\]" "$WORK/cfg/config.ini" && ok "both profiles preserved in the config after the GUI saved it" || bad "profiles lost from the config"
[ "$(stat -c %a "$WORK/cfg/config.ini")" = 600 ] && ok "config file mode is 0600" || bad "config file mode"

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "---- gui output"; cat "$WORK/gui.out"; echo "---- config"; cat "$WORK/cfg/config.ini"; exit 1; }
