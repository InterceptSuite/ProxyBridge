#!/bin/bash
# Command line (the same options as the Windows CLI: --profile, --verbose, --version, -?/-h/--help, --update): every way to get
# them wrong and right, without ever starting the engine. Works as any user.   Linux/tests/e2e_cli.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
WORK="$(mktemp -d)"; PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
trap 'rm -rf "$WORK"' EXIT
export LD_LIBRARY_PATH="$PB_DIR"
export PROXYBRIDGE_CONFIG_DIR="$WORK/cfg"

# t <name> <exit code> <text the output must contain or '-'> -- args...
t() {
  local name="$1" want="$2" needle="$3"; shift 4
  local out; out=$(timeout 30 "$PB_DIR/ProxyBridge" "$@" 2>&1); local rc=$?
  if [ "$rc" != "$want" ]; then bad "$name (exit $rc, wanted $want: ${out:0:240})"; return; fi
  if [ "$needle" != "-" ] && [[ "$out" != *"$needle"* ]]; then bad "$name (output lacks '$needle': ${out:0:240})"; return; fi
  ok "$name"
}

secure() { chmod 600 "$1"; }
echo "== help and version"
t "--help" 0 "--profile" -- --help
t "-h" 0 "--verbose" -- -h
t "-?" 0 "--update" -- '-?'
t "help documents verbosity levels" 0 "Silent" -- --help
t "help documents the version option" 0 "--version" -- --help
t "--version" 0 "ProxyBridge CLI V" -- --version
out=$("$PB_DIR/ProxyBridge" --help 2>&1)
for gone in --proxy --rule --dns-via-proxy --log-every-connection --test-proxy --list-profiles --cleanup; do
  [[ "$out" != *"$gone"* ]] && ok "help no longer lists $gone" || bad "help still lists $gone"
  t "$gone is rejected" 1 "Unknown option '$gone'" -- "$gone"
done

echo "== unknown and incomplete options"
t "unknown option" 1 "Unknown option '--bogus'" -- --bogus
t "stray argument" 1 "Unknown option 'stray'" -- stray
t "--profile without a value" 1 "Unknown option '--profile'" -- --profile
t "--verbose without a value" 1 "Unknown option '--verbose'" -- --verbose
t "--verbose out of range" 1 "Verbose level must be 0-3" -- --verbose 9
t "--verbose negative" 1 "Verbose level must be 0-3" -- --verbose -1
t "--verbose not a number" 1 "Verbose level must be 0-3" -- --verbose x
t "no profile" 1 "No profile specified" -- --verbose 1

echo "== profile loading and validation"
t "missing file" 1 "ERROR" -- --profile "$WORK/nope.pbprofile"
t "unknown profile name" 1 "ERROR" -- --profile "No Such Profile"
echo 'this is not json' > "$WORK/junk.pbprofile"
t "not JSON" 1 "ERROR" -- --profile "$WORK/junk.pbprofile"
echo '{ "ProxyRules": [ { "TargetHosts": "999.1.1.1", "Action": "DIRECT" } ] }' > "$WORK/badhost.pbprofile"
t "invalid host in a rule" 1 "ERROR" -- --profile "$WORK/badhost.pbprofile"
echo '{ "ProxyConfigs": [ { "Id": 1, "Type": "socks5", "Host": "127.0.0.1", "Port": "1" } ] }' > "$WORK/norules.pbprofile"
t "profile with no rules" 1 "no enabled rules" -- --profile "$WORK/norules.pbprofile"
echo '{ "ProxyConfigs": [ { "Id": 1, "Type": "socks5", "Host": "127.0.0.1", "Port": "1" } ], "ProxyRules": [ { "IsEnabled": false } ] }' > "$WORK/off.pbprofile"
t "all rules disabled" 1 "no enabled rules" -- --profile "$WORK/off.pbprofile"
echo '{ "ProxyRules": [ { "TargetHosts": "10.0.0.1" } ] }' > "$WORK/noproxy.pbprofile"
t "PROXY rule but no proxy" 1 "no proxy server" -- --profile "$WORK/noproxy.pbprofile"
mkdir -p "$WORK/cfg/profiles"
echo '{ "ProxyRules": [ { "TargetHosts": "10.0.0.1", "Action": "DIRECT" } ] }' > "$WORK/cfg/profiles/Named.pbprofile"; secure "$WORK/cfg/profiles/Named.pbprofile"
if [ "$(id -u)" != 0 ]; then
  echo "== not root (a valid profile reaches the privilege check)"
  t "by path" 1 "requires root privileges" -- --profile "$WORK/cfg/profiles/Named.pbprofile"
  t "by GUI profile name" 1 "requires root privileges" -- --profile Named
  t "with --verbose" 1 "requires root privileges" -- --verbose 3 --profile Named
  echo '{ "ProxyConfigs": [ { "Id": 1, "Type": "socks5", "Host": "h", "Port": "1", "Username": "u", "Password": "secretpw" } ], "ProxyRules": [ { "Action": "PROXY", "ProxyConfigId": 1 } ] }' > "$WORK/open.pbprofile"; chmod 644 "$WORK/open.pbprofile"
  t "readable credentials are warned about" 1 "WARNING" -- --profile "$WORK/open.pbprofile"
  out=$("$PB_DIR/ProxyBridge" --profile "$WORK/open.pbprofile" 2>&1)
  [[ "$out" != *secretpw* ]] && ok "the password never appears in the output" || bad "password printed"
fi

echo "== --update (feed overridden through PROXYBRIDGE_UPDATE_FEED)"
feed() { echo "$2" > "$WORK/$1.json"; }
upd() { local name="$1" want="$2" needle="$3" file="$4"; local out rc; out=$(PROXYBRIDGE_UPDATE_FEED="$file" timeout 30 "$PB_DIR/ProxyBridge" --update 2>&1); rc=$?
        [ "$rc" = "$want" ] && [[ "$out" == *"$needle"* ]] && ok "$name" || bad "$name (exit $rc: ${out:0:240})"; }
feed new '{"linux":{"version":"99.0.0","download":"https://example.test/pb.tar.gz","release_notes":"https://example.test/n"}}'
feed same "{\"linux\":{\"version\":\"$(sed -n 's/.*PROXYBRIDGE_VERSION "\(.*\)"/\1/p' "$ROOT/src/ProxyBridge.h")\",\"download\":\"https://example.test/a\"}}"
feed old '{"linux":{"version":"0.0.1","download":"https://example.test/a"}}'
feed junk 'not json'
feed http '{"linux":{"version":"99.0.0","download":"http://example.test/a"}}'
upd "a newer version is reported" 0 "99.0.0" "file://$WORK/new.json"
upd "the download link is shown" 0 "https://example.test/pb.tar.gz" "file://$WORK/new.json"
upd "an older feed means up to date" 0 "latest version" "file://$WORK/old.json"
upd "the same version means up to date" 0 "latest version" "file://$WORK/same.json"
upd "a broken feed is an error" 1 "ERROR" "file://$WORK/junk.json"
upd "a missing feed is an error" 1 "ERROR" "file://$WORK/absent.json"
out=$(PROXYBRIDGE_UPDATE_FEED="file://$WORK/http.json" "$PB_DIR/ProxyBridge" --update 2>&1)
[[ "$out" != *"http://example.test"* ]] && ok "a non-https download link is never shown" || bad "http link shown"
[ "$(id -u)" != 0 ] && { out=$(PROXYBRIDGE_UPDATE_FEED="file://$WORK/new.json" "$PB_DIR/ProxyBridge" --update 2>&1); [[ "$out" != *"root"* ]] && ok "--update needs no root" || bad "--update asked for root"; }

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
