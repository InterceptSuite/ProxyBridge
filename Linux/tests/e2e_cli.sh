#!/bin/bash
# Command line: every way to get the arguments wrong, and the ways to get them right, without ever starting the engine.
# Works as any user (valid specs are checked through --test-proxy, which needs no root).   Linux/tests/e2e_cli.sh
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
# a proxy spec that parses is reported by --test-proxy ("Proxy: ..."); one that does not is an error before that
parses() { t "$1" 1 "Proxy:" -- --proxy "$2" --test-proxy 127.0.0.1:9; }
rejects() { t "$1" 1 "$3" -- --proxy "$2" --test-proxy 127.0.0.1:9; }

echo "== help, version, small commands"
t "--help" 0 "--proxy" -- --help
t "-h" 0 "--rule" -- -h
t "help documents the new options" 0 "--test-proxy" -- --help
t "help documents profiles" 0 "--profile" -- --help
t "--cleanup is a harmless no-op" 0 "Nothing to clean up" -- --cleanup
t "--list-profiles without a profiles directory" 1 "No profiles directory" -- --list-profiles
mkdir -p "$WORK/cfg/profiles"
t "--list-profiles with an empty directory" 0 "No profiles" -- --list-profiles
echo '{}' > "$WORK/cfg/profiles/A b.pbprofile"; echo '{}' > "$WORK/cfg/profiles/plain.pbprofile"; echo x > "$WORK/cfg/profiles/ignored.txt"
out=$("$PB_DIR/ProxyBridge" --list-profiles 2>&1)
[[ "$out" == *"A b"* && "$out" == *"plain"* && "$out" != *"ignored"* ]] && ok "--list-profiles lists exactly the .pbprofile files" || bad "list: $out"

echo "== unknown and incomplete options"
t "unknown option" 1 "Unknown option '--bogus'" -- --bogus
t "stray argument" 1 "Unknown option 'stray'" -- stray
t "--proxy without a value" 1 "Unknown option '--proxy'" -- --proxy
t "--rule without a value" 1 "Unknown option '--rule'" -- --rule
t "--profile without a value" 1 "Unknown option '--profile'" -- --profile
t "--test-proxy without a value" 1 "Unknown option '--test-proxy'" -- --test-proxy
t "--verbose without a value" 1 "Unknown option '--verbose'" -- --verbose
t "--verbose out of range" 1 "Verbose level must be 0-3" -- --verbose 9
t "--verbose negative" 1 "Verbose level must be 0-3" -- --verbose -1
t "--dns-via-proxy with a bad value" 1 "Invalid value for --dns-via-proxy" -- --dns-via-proxy maybe
t "--log-every-connection with a bad value" 1 "Invalid value for --log-every-connection" -- --log-every-connection 2

echo "== proxy specs that are accepted"
parses "socks5" "socks5://127.0.0.1:1"
parses "http" "http://127.0.0.1:1"
parses "uppercase scheme" "SOCKS5://127.0.0.1:1"
parses "named" "work=socks5://127.0.0.1:1"
parses "user and password" "socks5://bob:pw@127.0.0.1:1"
parses "password with a colon and an at sign" "socks5://bob:p:w@x@127.0.0.1:1"
parses "legacy host:port:user:pass" "socks5://127.0.0.1:1:bob:pw"
parses "IPv6 proxy address" "socks5://[::1]:1"
parses "host name" "socks5://localhost:1"
parses "dns=local" "socks5://127.0.0.1:1?dns=local"
parses "dns=proxy" "socks5://127.0.0.1:1?dns=proxy"
parses "port 65535" "socks5://127.0.0.1:65535"
t "credentials are reported as present, never shown" 1 "with credentials" -- --proxy "a=socks5://bob:topsecret@127.0.0.1:1" --test-proxy 127.0.0.1:9
out=$("$PB_DIR/ProxyBridge" --proxy "a=socks5://bob:topsecret@127.0.0.1:1" --test-proxy 127.0.0.1:9 2>&1)
[[ "$out" != *topsecret* ]] && ok "the password never appears in the output" || bad "password printed"

echo "== proxy specs that are refused"
rejects "no scheme" "127.0.0.1:1080" "Expected [name=]type://host:port"
rejects "unknown scheme" "ftp://127.0.0.1:1" "Invalid proxy type"
rejects "missing port" "socks5://127.0.0.1" "missing port"
rejects "port zero" "socks5://127.0.0.1:0" "Invalid proxy port"
rejects "port too large" "socks5://127.0.0.1:65536" "Invalid proxy port"
rejects "port not a number" "socks5://127.0.0.1:abc" "Invalid proxy port"
rejects "empty host" "socks5://:1080" "host is empty"
rejects "IPv6 without closing bracket" "socks5://[::1:1080" "Invalid IPv6 proxy host"
rejects "unknown option after ?" "socks5://127.0.0.1:1?dns=maybe" "Unknown proxy option"
t "too many proxies" 1 "Maximum 64 proxies" -- $(for i in $(seq 65); do printf -- '--proxy socks5://127.0.0.1:%d ' $((1000 + i)); done)

echo "== rule specs that are refused"
r() { t "$1" 1 "$3" -- --rule "$2"; }
r "no colons at all" "curl" "Invalid rule format"
r "too few fields" "curl:*:*:TCP" "Invalid rule format"
r "bad protocol" "curl:*:*:ICMP:PROXY" "Invalid protocol"
r "bad action" "curl:*:*:TCP:ALLOW" "Invalid action"
r "empty protocol" "::::PROXY" "Invalid protocol"
r "proxy on DIRECT" "curl:*:*:TCP:DIRECT=a" "only valid with PROXY"
r "+localhost on BLOCK" "curl:*:*:TCP:BLOCK+localhost" "only valid with PROXY"
r "+localhost on DIRECT" "curl:*:*:TCP:DIRECT+localhost" "only valid with PROXY"
t "too many rules" 1 "Maximum 1024 rules" -- $(for i in $(seq 1025); do printf -- '--rule curl:*:*:TCP:DIRECT '; done)

echo "== rule specs that parse (--test-proxy stops before the engine)"
for spec in "curl:*:*:TCP:PROXY" "curl:10.0.0.0/8:80;443:UDP:DIRECT" "curl;wget:*:*:BOTH:BLOCK" "*:*.github.com:443:TCP:PROXY=a" \
            "curl:2001:db8::1:80:TCP:PROXY" "curl:[::1]:80:TCP:PROXY" "curl:*:*:tcp:proxy" "curl:*:*:TCP:PROXY=a+localhost" "curl:*:*:TCP:PROXY+LOCALHOST"; do
  out=$("$PB_DIR/ProxyBridge" --proxy a=socks5://127.0.0.1:1 --rule "$spec" --test-proxy 127.0.0.1:9 2>&1)
  [[ "$out" == *"Proxy:"* && "$out" != *"Invalid"* ]] && ok "rule accepted: $spec" || bad "rule '$spec': ${out:0:200}"
done

echo "== target of --test-proxy"
for tg in "example.test" "example.test:80" "198.51.100.1:8080" "[2001:db8::1]:443" "[2001:db8::1]"; do
  out=$("$PB_DIR/ProxyBridge" --proxy a=socks5://127.0.0.1:1 --test-proxy "$tg" 2>&1)
  [[ "$out" == *"Target:"* ]] && ok "target accepted: $tg" || bad "target '$tg': ${out:0:200}"
done
for tg in ":80" "host:0" "host:70000" "host:x" "[::1" "" ; do
  out=$("$PB_DIR/ProxyBridge" --proxy a=socks5://127.0.0.1:1 --test-proxy "$tg" 2>&1); rc=$?
  [ $rc = 2 ] && ok "target refused: '$tg'" || bad "target '$tg' (exit $rc: ${out:0:160})"
done

if [ "$(id -u)" != 0 ]; then
  echo "== not root"
  t "the engine needs root" 1 "requires root privileges" -- --proxy socks5://127.0.0.1:1
  t "...even with rules" 1 "requires root privileges" -- --proxy socks5://127.0.0.1:1 --rule "curl:*:*:TCP:PROXY"
fi

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
