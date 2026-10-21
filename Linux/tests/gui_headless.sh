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
cleanup() { kill $GUI_PID 2>/dev/null; wait $GUI_PID 2>/dev/null; kill $FAKE $DNSP $BW $WWW 2>/dev/null; wait 2>/dev/null;   # the client first: the display daemon aborts when its client vanishes
    ip addr del $DNSIP/32 dev lo 2>/dev/null; rm -rf "$WORK"; }
GUI_PID=; FAKE=; DNSP=; BW=; WWW=
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
# A window started as root talks to a running ProxyBridge service instead of loading its own engine, and this test would then change
# the real service's profiles and routing.
[ ! -S /run/proxybridge/ctl.sock ] || { echo "SKIP: a ProxyBridge service is running here (stop it first: sudo systemctl stop proxybridge)"; exit 0; }
ip addr add $DNSIP/32 dev lo 2>/dev/null
python3 "$HERE/fake_proxies.py" "$PLOG" >/dev/null 2>&1 & FAKE=$!
python3 "$HERE/fake_dns.py" $DNSIP "$DLOG" >/dev/null 2>&1 & DNSP=$!
( ulimit -c 0; exec broadwayd :9 ) >/dev/null 2>&1 & BW=$!   # no core dump (see gui_ui.sh)
sleep 1.5

# Seeded in the format of the previous GUI versions, so the first start also exercises the migration to .pbprofile files.
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
  if [ ! -d "$WORK/cfg/profiles" ]; then write_cfg "$1"
  else printf '{ "ActiveProfileName": "%s" }\n' "$1" > "$WORK/cfg/settings.json"; fi
  GDK_BACKEND=broadway BROADWAY_DISPLAY=:9 PROXYBRIDGE_CONFIG_DIR="$WORK/cfg" LD_LIBRARY_PATH="$LIBDIR" "$GUI" > "$WORK/gui.out" 2>&1 & GUI_PID=$!
  for _ in $(seq 60); do "${BPFTOOL:-bpftool}" prog show 2>/dev/null | grep -q pb_connect4 && break; kill -0 $GUI_PID 2>/dev/null || break; sleep 0.25; done
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
"${BPFTOOL:-bpftool}" prog show 2>/dev/null | grep -q pb_connect4 && ok "engine started by the GUI (eBPF programs attached)" || bad "no eBPF programs"
out=$(curl -s -m 5 http://192.0.2.7/);        has "rule 1 from the config file: curl -> proxy a" "$out" "hello-from-A dst=192.0.2.7:80"
out=$(curl -s -m 5 http://198.51.100.7/);     has "rule 2: curl -> proxy b (with credentials from the config)" "$out" "hello-from-B dst=198.51.100.7:80"
out=$(curl -s -m 5 http://203.0.114.7/ 2>&1; echo "rc=$?"); has "rule 3: BLOCK" "$out" "rc=7"
out=$(curl -s -m 2 http://203.0.113.7/ 2>&1; echo "rc=$?"); [[ "$out" != *hello-from* ]] && ok "disabled rule 5 is not applied" || bad "disabled rule applied"
ip4=$(dig @$DNSIP app.example.test +short +time=3 +tries=1 | head -1)
out=$(curl -s -m 5 http://$ip4/);             has "domain rule from the config (*.example.test -> b) after a real DNS lookup" "$out" "hello-from-B dst=app.example.test:80"
stop_gui
"${BPFTOOL:-bpftool}" prog show 2>/dev/null | grep -q pb_connect && bad "BPF programs left after GUI exit" || ok "programs detached after GUI exit"

echo "== profile Alt (same GUI, different active profile)"
run_gui Alt
out=$(curl -s -m 5 http://192.0.2.7/);        has "Alt profile: same rule now goes through proxy b" "$out" "hello-from-B dst=192.0.2.7:80"
out=$(curl -s -m 2 http://198.51.100.7/ 2>&1; echo "rc=$?"); [[ "$out" != *hello-from* ]] && ok "Alt profile does not apply rules of the Default profile" || bad "Default rules leaked into Alt"
stop_gui
P="$WORK/cfg/profiles"
[ -f "$P/Default.pbprofile" ] && [ -f "$P/Alt.pbprofile" ] && ok "the old config.ini was converted to one .pbprofile per profile" || bad "profiles not written: $(ls "$WORK/cfg" "$P")"
[ -f "$WORK/cfg/config.ini.bak" ] && [ ! -f "$WORK/cfg/config.ini" ] && ok "config.ini was set aside as config.ini.bak" || bad "config.ini handling"
grep -q '"ActiveProfileName": "Alt"' "$WORK/cfg/settings.json" && ok "settings.json remembers the active profile" || bad "settings.json: $(cat "$WORK/cfg/settings.json")"
grep -q '"ProxyConfigs"' "$P/Default.pbprofile" && grep -q '"TargetDomains": "\*.example.test"' "$P/Default.pbprofile" && grep -q '"Version": "1.0"' "$P/Default.pbprofile" \
  && ok "the saved profile uses the Windows/macOS format (domain rule in TargetDomains)" || bad "profile format: $(head -40 "$P/Default.pbprofile")"
grep -q '"IsTrafficLoggingEnabled": true' "$P/Default.pbprofile" && grep -q '"DnsViaProxy": true' "$P/Default.pbprofile" \
  && [ "$(grep -c . "$WORK/cfg/settings.json")" -le 5 ] && ! grep -q Dns "$WORK/cfg/settings.json" \
  && ok "logging and DNS switches live in the profile; settings.json only names the active profile" || bad "switches placement"
[ "$(stat -c %a "$P/Default.pbprofile")" = 600 ] && [ "$(stat -c %a "$P")" = 700 ] && ok "profile files are 0600 in a 0700 directory" || bad "profile permissions"

echo "== a profile exported by the Windows app, dropped into the profiles directory"
cat > "$P/From Windows.pbprofile" <<'JSON'
{ "Version": "1.0", "LocalhostViaProxy": false, "IsTrafficLoggingEnabled": true,
  "ProxyConfigs": [ { "Id": 5, "Type": "socks5", "Host": "127.0.0.1", "Port": "19080", "Username": "", "Password": "", "SendDomainToProxy": true } ],
  "ProxyRules": [
    { "ProcessName": "curl", "TargetHosts": "192.0.2.0/24", "TargetPorts": "*", "TargetDomains": "", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": true, "ProxyConfigId": 5 },
    { "Name": "Burp intercept", "ProcessName": "curl", "TargetHosts": "127.0.0.1", "TargetPorts": "18401", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": true, "ProxyConfigId": 5, "LocalhostViaProxy": true } ] }
JSON
mkdir -p "$WORK/www"; echo local-origin > "$WORK/www/index.html"
python3 -m http.server 18401 --bind 127.0.0.1 --directory "$WORK/www" >/dev/null 2>&1 & WWW=$!
sleep 0.5
run_gui "From Windows"
out=$(curl -s -m 5 http://192.0.2.9/);        has "rule and proxy imported from the Windows file are applied" "$out" "hello-from-A dst=192.0.2.9:80"
out=$(curl -s -m 5 http://127.0.0.1:18401/);  has "per-rule LocalhostViaProxy from the Windows file is applied" "$out" "hello-from-A dst=127.0.0.1:18401"
stop_gui
grep -q '"Name": "Burp intercept"' "$P/From Windows.pbprofile" && grep -q '"LocalhostViaProxy": true' "$P/From Windows.pbprofile" && grep -q '"SendDomainToProxy": true' "$P/From Windows.pbprofile" \
  && ok "rule name, localhost flag and DNS-via-proxy survive the GUI saving the profile" || bad "fields lost: $(cat "$P/From Windows.pbprofile")"
out=$(ls "$P")
has "the GUI saved its profiles as files the CLI can load" "$out" "From Windows.pbprofile"
[ "$(stat -c %a "$P/From Windows.pbprofile")" = 600 ] && ok "the dropped-in file was tightened to 0600" || bad "dropped-in file mode"

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "---- gui output"; cat "$WORK/gui.out"; echo "---- config"; ls -lR "$WORK/cfg"; exit 1; }
