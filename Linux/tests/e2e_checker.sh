#!/bin/bash
# The library's multi-step (what the GUI's Test connection runs, via tests/check_probe.c) proxy check, against working and broken proxies. Needs python3 (no root).
#   Linux/tests/e2e_checker.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
WORK="$(mktemp -d)"; PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup() { kill $F1 $F2 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
gcc -Wall -Wextra -O1 -I"$ROOT/src" -o "$WORK/check_probe" "$HERE/check_probe.c" -L"$PB_DIR" -lproxybridge || exit 1
python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & F1=$!
python3 "$HERE/fault_proxies.py" "$WORK/fault.log" > /dev/null 2>&1 & F2=$!
sleep 1.5

# turns "--proxy name=type://[user:pw@]host:port ... --test-proxy host[:port]" into check_probe arguments
probe_args() {
  local out=() tgt="" th tp
  while [ $# -gt 0 ]; do
    case "$1" in
      --proxy) local spec="$2" nm="p" ty u="-" pw="-" hp; shift 2
        [[ "$spec" == *=* ]] && { nm="${spec%%=*}"; spec="${spec#*=}"; }
        ty="${spec%%://*}"; spec="${spec#*://}"
        [[ "$spec" == *@* ]] && { u="${spec%%:*}"; pw="${spec#*:}"; pw="${pw%%@*}"; spec="${spec#*@}"; }
        out+=("$nm" "$ty" "${spec%:*}" "${spec##*:}" "$u" "$pw");;
      --test-proxy) tgt="$2"; shift 2;;
      *) shift;;
    esac
  done
  if [[ "$tgt" == \[*\]* ]]; then th="${tgt%%]*}"; th="${th#[}"; tp="${tgt##*]}"; tp="${tp#:}"
  elif [[ "$tgt" == *:* ]]; then th="${tgt%%:*}"; tp="${tgt#*:}"
  else th="$tgt"; tp=""; fi
  [ -z "$tp" ] && [[ "$tgt" != *:* || "$tgt" == \[*\] ]] && tp=80
  printf '%s\n' "${out[@]}" "$th" "$tp"
}

# check <name> <expected exit> <needle>... -- <ProxyBridge args>
check() {
  local name="$1" want_rc="$2"; shift 2
  local needles=()
  while [ "$1" != "--" ]; do needles+=("$1"); shift; done; shift
  local out; local pa; mapfile -t pa < <(probe_args "$@")
  out=$(timeout 60 "$WORK/check_probe" "${pa[@]}" 2>&1); local rc=$?
  if [ "$rc" != "$want_rc" ]; then bad "$name (exit $rc, wanted $want_rc: ${out:0:300})"; return; fi
  for n in "${needles[@]}"; do
    if [[ "$out" != *"$n"* ]]; then bad "$name (output lacks '$n': ${out:0:400})"; return; fi
  done
  ok "$name"
}

echo "== working proxies"
check "SOCKS5, every step passes" 0 "[1/5]" "OK: connected to 127.0.0.1" "OK: SOCKS5 tunnel established" "OK: HTTP/1.0 200 OK" \
  "OK: min/avg/max" "OK: UDP ASSOCIATE accepted" "Result: PASSED" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy example.test:80
check "SOCKS5 with a login" 0 "(login accepted)" "Result: PASSED" -- --proxy b=socks5://bob:pw@127.0.0.1:19081 --test-proxy example.test:80
check "HTTP CONNECT" 0 "OK: HTTP CONNECT tunnel established" "HTTP proxies cannot carry UDP" "Result: PASSED" -- --proxy c=http://127.0.0.1:19082 --test-proxy example.test:80
check "HTTP CONNECT with a login" 0 "(login accepted)" "Result: PASSED" -- --proxy d=http://bob:pw@127.0.0.1:19083 --test-proxy example.test:80
check "another port skips the page load" 0 "skipped: only port 80" "Result: PASSED" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy example.test:8443
check "default port is 80" 0 "Target: example.test:80" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy example.test
check "IPv6 literal target" 0 "Target: ::1:80" "Result: PASSED" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy "[::1]:80"
check "IPv4 target" 0 "Target: 198.51.100.7:80" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy 198.51.100.7:80
check "every proxy is checked" 0 "Proxy: a" "Proxy: c" "Result: PASSED" -- --proxy a=socks5://127.0.0.1:19080 --proxy c=http://127.0.0.1:19082 --test-proxy example.test:80

echo "== broken proxies are explained"
check "wrong SOCKS5 password" 1 "FAILED: SOCKS5 authentication failed" "refused the tunnel or the login" -- --proxy b=socks5://bob:wrong@127.0.0.1:19081 --test-proxy example.test:80
check "SOCKS5 login required but none given" 1 "rejected all auth methods" -- --proxy b=socks5://127.0.0.1:19081 --test-proxy example.test:80
check "wrong HTTP password" 1 "authentication required (407)" -- --proxy d=http://bob:wrong@127.0.0.1:19083 --test-proxy example.test:80
check "nothing is listening" 1 "FAILED:" "cannot be reached" -- --proxy dead=socks5://127.0.0.1:19999 --test-proxy example.test:80
check "proxy host that does not resolve" 1 "cannot resolve" -- --proxy dead=socks5://no-such-host.invalid:1080 --test-proxy example.test:80
check "tunnel refused by the proxy" 1 "connection refused by target" -- --proxy f=socks5://127.0.0.1:19100 --test-proxy 203.0.113.1:9005
check "proxy that sends garbage" 1 "bad SOCKS5 reply version" -- --proxy f=socks5://127.0.0.1:19100 --test-proxy 203.0.113.1:9015
check "proxy that never answers" 1 "timed out" -- --proxy f=socks5://127.0.0.1:19100 --test-proxy 203.0.113.1:9014
check "HTTP proxy that refuses with 403" 1 "forbids this connection (403)" -- --proxy h=http://127.0.0.1:19110 --test-proxy 203.0.113.1:9021
check "UDP refused is a warning, not a failure" 0 "WARNING: UDP ASSOCIATE refused" "command not supported" "Result: PASSED" -- --proxy n=socks5://127.0.0.1:19106 --test-proxy 203.0.113.1:80
check "page load through a proxy that answers nothing is a warning" 0 "Result: PASSED" -- --proxy f=socks5://127.0.0.1:19100 --test-proxy 203.0.113.1:9016
check "one bad proxy among good ones fails the run" 1 "Result: PASSED" "Result: FAILED" -- --proxy a=socks5://127.0.0.1:19080 --proxy dead=socks5://127.0.0.1:19999 --test-proxy example.test:80

echo "== bad arguments"
check "empty host" 2 "Invalid target" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy :80
check "port out of range" 2 "Invalid target" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy example.test:99999
check "port that is not a number" 2 "Invalid target" -- --proxy a=socks5://127.0.0.1:19080 --test-proxy example.test:http
echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
