#!/bin/bash
# End-to-end test of `ProxyBridge --profile`: a profile in the Windows/macOS .pbprofile format drives the real datapath.
#   sudo Linux/tests/e2e_profile.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"
LOG="$WORK/proxy.log"; : > "$LOG"
PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
has()  { if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1 (got: ${2:0:300})"; fi; }
PB_PID=""; FAKE_PID=""
cleanup() { [ -n "$PB_PID" ] && kill "$PB_PID" 2>/dev/null; [ -n "$FAKE_PID" ] && kill "$FAKE_PID" 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
export PROXYBRIDGE_CONFIG_DIR="$WORK/cfg"
mkdir -p "$WORK/cfg/profiles"

python3 "$HERE/fake_proxies.py" "$LOG" > "$WORK/fake.out" 2>&1 & FAKE_PID=$!
sleep 1

start_pb() { # args...; leaves PB_PID set and waits for start-up. Plain --profile/--verbose runs the real program; extras go through pbl
  local prog="$PB_DIR/ProxyBridge" a
  for a in "$@"; do case "$a" in --proxy|--rule|--dns-via-proxy|--log-every-connection) prog="$PBL";; esac; done
  stdbuf -oL "$prog" "$@" > "$WORK/pb.out" 2>&1 & PB_PID=$!
  for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && return 0; kill -0 "$PB_PID" 2>/dev/null || return 1; sleep 0.25; done
  return 1
}
stop_pb() { kill -INT "$PB_PID" 2>/dev/null; wait "$PB_PID" 2>/dev/null; PB_PID=""; }

# What the Windows GUI exports: numeric ids, no proxy names on the first entry, domains in TargetDomains, a disabled rule.
cat > "$WORK/win.pbprofile" <<'JSON'
{
  "Version": "1.0",
  "LocalhostViaProxy": false,
  "IsTrafficLoggingEnabled": true,
  "ProxyConfigs": [
    { "Id": 1, "Type": "socks5", "Host": "127.0.0.1", "Port": "19080", "Username": "", "Password": "", "SendDomainToProxy": true },
    { "Id": 2, "Name": "bobby", "Type": "SOCKS5", "Host": "127.0.0.1", "Port": "19081", "Username": "bob", "Password": "pw" }
  ],
  "ProxyRules": [
    { "ProcessName": "curl", "TargetHosts": "192.0.2.0/24", "TargetPorts": "*", "TargetDomains": "", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": true, "ProxyConfigId": 1 },
    { "ProcessName": "curl", "TargetHosts": "198.51.100.0/24", "TargetPorts": "80;8080", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": true, "ProxyConfigId": 2 },
    { "ProcessName": "curl", "TargetHosts": "203.0.113.0/24", "TargetPorts": "*", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": false, "ProxyConfigId": 1 },
    { "ProcessName": "curl", "TargetHosts": "*", "TargetPorts": "*", "TargetDomains": "*.profile-test.invalid", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": true, "ProxyConfigId": 2 },
    { "ProcessName": "curl", "TargetHosts": "203.0.114.0/24", "TargetPorts": "*", "Protocol": "BOTH", "Action": "BLOCK", "IsEnabled": true }
  ]
}
JSON
chmod 600 "$WORK/win.pbprofile"

echo "== a profile file (Windows format) by path"
if start_pb --verbose 3 --profile "$WORK/win.pbprofile"; then ok "ProxyBridge starts from a profile"; else bad "start"; cat "$WORK/pb.out"; fi
out=$(cat "$WORK/pb.out")
has "profile path is reported"             "$out" "Loading profile: $WORK/win.pbprofile"
has "both proxies loaded"                  "$out" "Proxies: 2"
has "unnamed proxy gets a stable name"     "$out" "proxy1"
has "named proxy keeps its name"           "$out" "bobby"
has "the disabled rule is skipped"         "$out" "Rules: 4"
out=$(curl -s -m 5 http://192.0.2.7/);        has "ProxyConfigId 1 -> first proxy"            "$out" "hello-from-A dst=192.0.2.7:80"
out=$(curl -s -m 5 http://198.51.100.7:8080/); has "ProxyConfigId 2 -> authenticated proxy"  "$out" "hello-from-B dst=198.51.100.7:8080"
out=$(curl -s -m 3 http://203.0.113.7/ 2>&1; echo "rc=$?"); has "disabled rule does not route" "$out" "rc=28"
out=$(curl -s -m 5 http://203.0.114.7/ 2>&1; echo "rc=$?");  has "BLOCK action from the profile" "$out" "rc=7"
stop_pb

echo "== a profile saved by the GUI, by name (also with spaces)"
cp "$WORK/win.pbprofile" "$WORK/cfg/profiles/Work Profile.pbprofile"
if start_pb --profile "Work Profile"; then ok "starts by profile name"; else bad "start by name"; cat "$WORK/pb.out"; fi
out=$(curl -s -m 5 http://192.0.2.9/);        has "rules from the named profile apply" "$out" "hello-from-A dst=192.0.2.9:80"
stop_pb

echo "== default proxy, combining with --proxy/--rule, DNS flag"
cat > "$WORK/dflt.pbprofile" <<'JSON'
{ "Version": "1.0", "DnsViaProxy": false, "DefaultProxyId": 2,
  "ProxyConfigs": [
    { "Id": 1, "Name": "one", "Type": "socks5", "Host": "127.0.0.1", "Port": "19080" },
    { "Id": 2, "Name": "two", "Type": "http", "Host": "127.0.0.1", "Port": "19082" } ],
  "ProxyRules": [ { "ProcessName": "curl", "TargetHosts": "192.0.2.0/24", "Protocol": "TCP", "Action": "PROXY" } ] }
JSON
chmod 600 "$WORK/dflt.pbprofile"
start_pb --profile "$WORK/dflt.pbprofile" --proxy extra=socks5://127.0.0.1:19080 --rule "curl:198.51.100.0/24:*:TCP:PROXY=extra"
out=$(cat "$WORK/pb.out")
has "DefaultProxyId is honoured by rules without a proxy" "$(curl -s -m 5 http://192.0.2.5/)" "hello-from-C dst=192.0.2.5:80"
has "--rule works after --profile"         "$(curl -s -m 5 http://198.51.100.5/)" "hello-from-A dst=198.51.100.5:80"
has "profile DnsViaProxy=false is applied" "$out" "DNS via Proxy: Disabled"
stop_pb
start_pb --profile "$WORK/dflt.pbprofile" --dns-via-proxy true
has "explicit --dns-via-proxy wins"        "$(cat "$WORK/pb.out")" "DNS via Proxy: Enabled"
stop_pb

echo "== per-rule LocalhostViaProxy and per-proxy SendDomainToProxy from a profile"
cat > "$WORK/lo.pbprofile" <<'JSON'
{ "Version": "1.0", "LocalhostViaProxy": false,
  "ProxyConfigs": [ { "Id": 1, "Name": "p", "Type": "socks5", "Host": "127.0.0.1", "Port": "19080", "SendDomainToProxy": false } ],
  "ProxyRules": [
    { "Name": "with", "ProcessName": "curl", "TargetHosts": "127.0.0.1", "TargetPorts": "18403", "Protocol": "TCP", "Action": "PROXY", "ProxyConfigId": 1, "LocalhostViaProxy": true },
    { "Name": "without", "ProcessName": "curl", "TargetHosts": "127.0.0.1", "TargetPorts": "18404", "Protocol": "TCP", "Action": "PROXY", "ProxyConfigId": 1 } ] }
JSON
chmod 600 "$WORK/lo.pbprofile"
start_pb --profile "$WORK/lo.pbprofile" || { bad "start"; cat "$WORK/pb.out"; }
has "the proxy's dns:local option is shown" "$(cat "$WORK/pb.out")" "(dns:local)"
has "the rule's localhost option is shown"  "$(cat "$WORK/pb.out")" "(+localhost)"
out=$(curl -s -m 5 http://127.0.0.1:18403/);  has "LocalhostViaProxy=true: loopback goes to the proxy" "$out" "hello-from-A dst=127.0.0.1:18403"
out=$(curl -s -m 3 http://127.0.0.1:18404/ 2>&1; echo "rc=$?"); has "no LocalhostViaProxy: loopback stays direct (nothing listens there)" "$out" "rc=7"
stop_pb
cat > "$WORK/legacy.pbprofile" <<'JSON'
{ "Version": "1.0", "LocalhostViaProxy": true,
  "ProxyConfigs": [ { "Id": 1, "Type": "socks5", "Host": "127.0.0.1", "Port": "19080" } ],
  "ProxyRules": [ { "ProcessName": "curl", "TargetHosts": "127.0.0.1", "TargetPorts": "18405", "Protocol": "TCP", "Action": "PROXY", "ProxyConfigId": 1 } ] }
JSON
chmod 600 "$WORK/legacy.pbprofile"
start_pb --profile "$WORK/legacy.pbprofile" || bad "start"
out=$(curl -s -m 5 http://127.0.0.1:18405/);  has "an older profile's global LocalhostViaProxy becomes the rule default" "$out" "hello-from-A dst=127.0.0.1:18405"
stop_pb

echo "== bad input is rejected before anything is attached"
expect_fail() { # name expected-text args...
  local name="$1" want="$2"; shift 2
  out=$("$PB_DIR/ProxyBridge" "$@" 2>&1); rc=$?
  if [ $rc -ne 0 ] && [[ "$out" == *"$want"* ]]; then ok "$name"; else bad "$name (rc=$rc: ${out:0:300})"; fi
}
expect_fail "missing file"                 "ERROR"         --profile "$WORK/nope.pbprofile"
expect_fail "unknown profile name"         "ERROR"         --profile "no such profile"
echo '{ "ProxyRules": [ { "ProxyConfigId": 9 } ] }' > "$WORK/badref.pbprofile"
expect_fail "rule referring to a missing proxy" "does not match any proxy" --profile "$WORK/badref.pbprofile"
echo 'not json' > "$WORK/junk.pbprofile"
expect_fail "malformed JSON"               "not a valid profile" --profile "$WORK/junk.pbprofile"
echo '{ "ProxyRules": [ { "TargetHosts": "999.1.1.1", "Action": "DIRECT" } ] }' > "$WORK/badhost.pbprofile"
expect_fail "rule the engine rejects"      "ERROR"               --profile "$WORK/badhost.pbprofile"
expect_fail "--profile without a value"    "Unknown option"      --profile
echo '{ "ProxyConfigs": [ { "Id": 1, "Type": "socks5", "Host": "127.0.0.1", "Port": "19080" } ] }' > "$WORK/norules.pbprofile"
expect_fail "a profile without rules"      "no enabled rules"    --profile "$WORK/norules.pbprofile"
echo '{ "ProxyRules": [ { "TargetHosts": "10.0.0.1" } ] }' > "$WORK/noproxy.pbprofile"
expect_fail "a PROXY rule without any proxy" "no proxy server"   --profile "$WORK/noproxy.pbprofile"
echo '{ "ProxyConfigs": [ { "Id": 1, "Type": "socks5", "Host": "127.0.0.1", "Port": "19080" } ], "ProxyRules": [ { "IsEnabled": false } ] }' > "$WORK/off.pbprofile"
expect_fail "a profile whose rules are all disabled" "no enabled rules" --profile "$WORK/off.pbprofile"
expect_fail "no profile at all"            "No profile specified"

echo "== credentials in a world-readable profile trigger a warning"
cp "$WORK/win.pbprofile" "$WORK/open.pbprofile"; chmod 644 "$WORK/open.pbprofile"
out=$(timeout 3 "$PB_DIR/ProxyBridge" --profile "$WORK/open.pbprofile" 2>&1)
has "permission warning"                   "$out" "other users can read it"

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
