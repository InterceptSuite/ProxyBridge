#!/bin/bash
# Rule-matrix end-to-end test: every rule form and every upstream proxy type through the real kernel datapath.
#   sudo tests/e2e_rules.sh      (needs curl, python3; only loopback + TEST-NET addresses are used)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
WORK="$(mktemp -d)"; PLOG="$WORK/proxy.log"; : > "$PLOG"
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
via() { # name url expected-proxy-letter expected-dst
  local out; out=$(curl -s -m 5 "$2" 2>&1)
  [[ "$out" == *"hello-from-$3 dst=$4"* ]] && ok "$1" || bad "$1 (got: ${out:0:140})"; }
direct() { # name url   -> must NOT reach any proxy (times out / fails)
  local out; out=$(curl -s -m 2 "$2" 2>&1; echo "rc=$?")
  [[ "$out" != *hello-from* && "$out" != *"rc=0"* ]] && ok "$1" || bad "$1 (got: ${out:0:140})"; }
blocked() { local out; out=$(curl -s -m 5 "$2" 2>&1; echo "rc=$?"); [[ "$out" == *"rc=7"* ]] && ok "$1" || bad "$1 (got: ${out:0:140})"; }
cleanup() { kill $PB_PID $FAKE_PID 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export LD_LIBRARY_PATH="$PB_DIR"

python3 "$HERE/fake_proxies.py" "$PLOG" >/dev/null 2>&1 & FAKE_PID=$!
mkdir -p "$WORK/bin" "$WORK/pbpath"
CURL=$(command -v curl)
cp "$CURL" "$WORK/bin/wget"; cp "$CURL" "$WORK/bin/newtool"; cp "$CURL" "$WORK/bin/mycurlbin"; cp "$CURL" "$WORK/pbpath/tool"
sleep 1

start_pb() { # extra CLI args...
  stdbuf -oL "$PBL" --verbose 1 \
    --proxy a=socks5://127.0.0.1:19080 --proxy b=socks5://bob:pw@127.0.0.1:19081 --proxy c=http://127.0.0.1:19082 \
    --proxy d=http://bob:pw@127.0.0.1:19083 --proxy e=http://bob:wrong@127.0.0.1:19083 "$@" > "$WORK/pb.out" 2>&1 & PB_PID=$!
  for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && return 0; sleep 0.25; done
  echo "ProxyBridge failed to start"; cat "$WORK/pb.out"; exit 1; }

start_pb \
  --rule "curl:192.0.2.90:*:TCP:BLOCK" \
  --rule "curl:192.0.2.0/24:*:TCP:PROXY=a" \
  --rule "curl:198.51.100.20-198.51.100.29:*:TCP:PROXY=b" \
  --rule "curl:198.51.*.*:443:TCP:PROXY=c" \
  --rule "curl:203.0.1-3.*:*:TCP:PROXY=a" \
  --rule "curl:203.0.113.40:80;443;8000-9000:TCP:PROXY=b" \
  --rule "wget;newtool:203.0.113.50:*:TCP:PROXY=a" \
  --rule "$WORK/pbpath/*:203.0.113.60:*:TCP:PROXY=b" \
  --rule "*urlbin*:203.0.113.70:*:TCP:PROXY=a" \
  --rule "curl:203.0.113.80:1;2;3;4;5;6;7;80:TCP:PROXY=b" \
  --rule "curl:10.0.0.0/8;172.16.0.0/12;100.64.0.0/10;192.168.0.0/16;169.254.0.0/16;203.0.113.90:*:TCP:PROXY=a" \
  --rule "CURL:203.0.113.150:*:TCP:PROXY=a" \
  --rule "curl:203.0.113.100:*:TCP:PROXY=d" \
  --rule "curl:203.0.113.101:*:TCP:PROXY=e" \
  --rule "python3*:203.0.113.70:*:UDP:PROXY=a" \
  --rule "python3*:203.0.113.110:5300:UDP:PROXY=c" \
  --rule "python3*:203.0.113.120:*:UDP:BLOCK" \
  --rule "python3*:203.0.113.130:5300-5310:UDP:PROXY=b" \
  --rule "python3*:203.0.113.140:53:UDP:PROXY=a" \
  --rule "python3*:203.0.113.160:*:BOTH:PROXY=a"
sleep 1

echo "== diagnostics"
grep -q "sends UDP to HTTP proxy 'c', which cannot carry UDP" "$WORK/pb.out" && ok "a UDP rule pointing at an HTTP proxy is reported in the log" || bad "no warning for UDP over an HTTP proxy"

echo "== host forms (process: curl)"
via     "single IP"                               http://192.0.2.10/            A 192.0.2.10:80
via     "CIDR /24"                                http://192.0.2.200/           A 192.0.2.200:80
via     "range a-b (inside)"                      http://198.51.100.25/         B 198.51.100.25:80
direct  "range a-b (outside)"                     http://198.51.100.30:8080/
via     "octet wildcard 198.51.*.* + port 443"    http://198.51.100.99:443/     C 198.51.100.99:443
via     "octet-range box 203.0.1-3.* (slow path)" http://203.0.2.77/            A 203.0.2.77:80
direct  "octet-range box (outside)"               http://203.0.4.77/
via     "6 CIDRs in one rule (kernel cannot hold them, slow path)" http://203.0.113.90/ A 203.0.113.90:80

echo "== port forms"
via     "port list: 80"                           http://203.0.113.40/          B 203.0.113.40:80
via     "port range 8000-9000 (8500)"             http://203.0.113.40:8500/     B 203.0.113.40:8500
direct  "port not in list/range (22)"             http://203.0.113.40:22/
via     "8 ports in a list (kernel table has 4 -> slow path)" http://203.0.113.80/ B 203.0.113.80:80
direct  "port 81 not in that list"                http://203.0.113.80:81/

echo "== process forms"
out=$("$WORK/bin/wget" -s -m 5 http://203.0.113.50/); [[ "$out" == *"hello-from-A dst=203.0.113.50:80"* ]] && ok "process list a;b matches 'wget'" || bad "process list (got ${out:0:100})"
out=$("$WORK/bin/newtool" -s -m 5 http://203.0.113.50/); [[ "$out" == *"hello-from-A dst=203.0.113.50:80"* ]] && ok "process list a;b matches 'newtool'" || bad "process list 2 (got ${out:0:100})"
out=$(curl -s -m 2 http://203.0.113.50/ 2>&1; echo "rc=$?"); [[ "$out" != *hello-from* ]] && ok "process not in the list ('curl') is not matched" || bad "list leaked"
out=$("$WORK/pbpath/tool" -s -m 5 http://203.0.113.60/); [[ "$out" == *"hello-from-B dst=203.0.113.60:80"* ]] && ok "full-path glob /dir/* matches" || bad "path glob (got ${out:0:100})"
out=$("$WORK/bin/mycurlbin" -s -m 5 http://203.0.113.70/); [[ "$out" == *"hello-from-A dst=203.0.113.70:80"* ]] && ok "middle glob *urlbin* matches 'mycurlbin'" || bad "middle glob (got ${out:0:100})"
direct "process names are case-sensitive (rule 'CURL' does not match 'curl')" http://203.0.113.150/

echo "== ordering: first match wins"
blocked "specific BLOCK before the broader /24 PROXY"   http://192.0.2.90/
via     "same /24, other address, still proxied"        http://192.0.2.91/       A 192.0.2.91:80

echo "== HTTP proxies"
via     "HTTP CONNECT with Basic auth (correct credentials)"  http://203.0.113.100/ D 203.0.113.100:80
out=$(curl -s -m 5 http://203.0.113.101/ 2>&1; echo "rc=$?"); [[ "$out" != *hello-from* ]] && ok "HTTP CONNECT with wrong credentials fails (407), nothing leaks" || bad "wrong creds accepted"
grep -q "^D AUTHFAIL" "$PLOG" && ok "the proxy really answered 407 (proxy log)" || bad "no 407 seen by the proxy"

echo "== UDP rules"
out=$(python3 - <<'PY'
import socket
def probe(dst, payload=b"p", timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(payload, dst); d, a = s.recvfrom(200); return d.decode() + "|" + a[0] + ":" + str(a[1])
    except socket.timeout: return "timeout"
    except OSError as e: return "errno=%d" % e.errno
print("port-range-in:", probe(("203.0.113.130", 5305)))
print("port-range-out:", probe(("203.0.113.130", 5400), timeout=1))
print("udp-only-rule-on-tcp-dst:", probe(("203.0.113.70", 5300), timeout=1))
print("block:", probe(("203.0.113.120", 5300)))
print("http-proxy-udp:", probe(("203.0.113.110", 5300), timeout=1))
print("both:", probe(("203.0.113.160", 5300)))
print("dns-port-53:", probe(("203.0.113.140", 53)))
PY
)
[[ "$out" == *"port-range-in: UDP-B 203.0.113.130:5305 p|203.0.113.130:5305"* ]] && ok "UDP port range 5300-5310 via SOCKS5+auth, source restored" || bad "udp port range ($out)"
[[ "$out" == *"port-range-out: timeout"* ]] && ok "UDP port outside the range is not proxied" || bad "udp range leak"
[[ "$out" == *"udp-only-rule-on-tcp-dst: UDP-A 203.0.113.70:5300"* ]] && ok "protocol UDP rule matches UDP" || bad "udp proto rule ($out)"
direct "protocol UDP rule does NOT match TCP to the same address" http://203.0.113.70/
[[ "$out" == *"block: errno=1"* ]] && ok "UDP BLOCK rule: sendto fails with EPERM" || bad "udp block ($out)"
[[ "$out" == *"http-proxy-udp: timeout"* ]] && ok "UDP rule pointing at an HTTP proxy goes direct (HTTP cannot carry UDP)" || bad "http udp ($out)"
grep -q "UDP 203.0.113.110" "$PLOG" && bad "UDP leaked into the HTTP proxy" || ok "the HTTP proxy never saw that UDP"
[[ "$out" == *"both: UDP-A 203.0.113.160:5300"* ]] && ok "protocol BOTH rule matches UDP" || bad "both/udp ($out)"
tcpout=$(python3 - <<'PY'
import socket
s = socket.create_connection(("203.0.113.160", 80), timeout=5); s.sendall(b"GET / HTTP/1.0\r\n\r\n"); print(s.recv(300).decode())
PY
)
[[ "$tcpout" == *"hello-from-A dst=203.0.113.160:80"* ]] && ok "protocol BOTH rule matches TCP too" || bad "both/tcp (got ${tcpout:0:100})"
[[ "$out" == *"dns-port-53: UDP-A 203.0.113.140:53"* ]] && ok "DNS port rule applies when --dns-via-proxy is true (default)" || bad "dns true ($out)"

echo "== DNS switch: --dns-via-proxy false makes port 53 always direct"
kill -INT $PB_PID; wait $PB_PID 2>/dev/null
start_pb --dns-via-proxy false --rule "python3*:203.0.113.140:53:UDP:PROXY=a" --rule "python3*:203.0.113.141:5353:UDP:PROXY=a"
out=$(python3 - <<'PY'
import socket
def probe(dst, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try: s.sendto(b"p", dst); d, a = s.recvfrom(200); return d.decode()
    except socket.timeout: return "timeout"
print("dns:", probe(("203.0.113.140", 53)))
print("other:", probe(("203.0.113.141", 5353)))
PY
)
[[ "$out" == *"dns: timeout"* ]] && ok "port 53 stays direct with dns-via-proxy=false" || bad "dns false ($out)"
[[ "$out" == *"other: UDP-A 203.0.113.141:5353"* ]] && ok "non-DNS UDP rule still proxied" || bad "other udp ($out)"

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "---- proxy log"; cat "$PLOG"; echo "---- pb output"; tail -20 "$WORK/pb.out"; exit 1; }
