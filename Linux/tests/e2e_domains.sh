#!/bin/bash
# End-to-end test of domain-name rules (DNS tap). Needs root, dig, curl, python3.
# Proxies get the resolved host name (the default "DNS via proxy"), so the fake proxy reports names, not addresses.
#   sudo Linux/tests/e2e_domains.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
WORK="$(mktemp -d)"; PLOG="$WORK/proxy.log"; DLOG="$WORK/dns.log"; : > "$PLOG"; : > "$DLOG"
PASS=0; FAIL=0; DNSIP=10.77.0.2
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
has() { [[ "$2" == *"$3"* ]] && ok "$1" || bad "$1 (got: ${2:0:160})"; }
cleanup() { kill "$PB_PID" "$FAKE_PID" "$DNS_PID" 2>/dev/null; wait 2>/dev/null; ip addr del $DNSIP/32 dev lo 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export LD_LIBRARY_PATH="$PB_DIR"
ip addr add $DNSIP/32 dev lo 2>/dev/null
python3 "$HERE/fake_proxies.py" "$PLOG" > /dev/null 2>&1 & FAKE_PID=$!
python3 "$HERE/fake_dns.py" $DNSIP "$DLOG" > /dev/null 2>&1 & DNS_PID=$!
sleep 1

stdbuf -oL "$PBL" --verbose 2 \
  --proxy a=socks5://127.0.0.1:19080 --proxy b=socks5://bob:pw@127.0.0.1:19081 --proxy h=socks5://localhost:19080 \
  --rule "*:blocked.example.test:*:TCP:BLOCK" \
  --rule "*:*.example.test:*:TCP:PROXY=a" \
  --rule "*:*.corp.test;*.cdnnet.test:*:TCP:PROXY=b" \
  --rule "*:svc.byname.test:*:TCP:PROXY=h" \
  > "$WORK/pb.out" 2>&1 & PB_PID=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
grep -q "ProxyBridge started" "$WORK/pb.out" || { echo "ProxyBridge failed to start"; cat "$WORK/pb.out"; exit 1; }
sleep 1

resolve() { dig @$DNSIP "$@" +short +time=3 +tries=1 | head -1; }

echo "== resolver answers are delivered unchanged"
ip1=$(resolve app.example.test);            has "UDP DNS answer reaches the application"  "$ip1" "192.0.2.77"
ip2=$(dig @$DNSIP +tcp tcp.example.test +short +time=3 +tries=1 | head -1); has "TCP DNS answer reaches the application" "$ip2" "192.0.2.80"
nx=$(dig @$DNSIP nope.example.test +time=3 +tries=1 | grep -c NXDOMAIN); [ "$nx" -ge 1 ] && ok "NXDOMAIN is passed through" || bad "NXDOMAIN lost"

echo "== domain rules: resolve with one process, connect with another"
out=$(curl -s -m 5 http://192.0.2.77/);       has "*.example.test -> proxy a (UDP DNS learned)" "$out" "hello-from-A dst=app.example.test:80"
out=$(curl -s -m 5 http://192.0.2.80/);       has "*.example.test -> proxy a (TCP DNS learned)" "$out" "hello-from-A dst=tcp.example.test:80"
resolve blocked.example.test >/dev/null
out=$(curl -s -m 5 http://192.0.2.78/ 2>&1; echo "rc=$?"); has "exact-name BLOCK rule beats the wildcard rule" "$out" "rc=7"
resolve www.corp.test >/dev/null
out=$(curl -s -m 5 http://192.0.2.79/);       has "CNAME chain: rule on the canonical name -> proxy b" "$out" "hello-from-B dst=www.corp.test:80"
resolve svc.byname.test >/dev/null
out=$(curl -s -m 5 http://192.0.2.81/);       has "domain rule + proxy configured by hostname (localhost)" "$out" "hello-from-A dst=svc.byname.test:80"

echo "== things that must NOT match"
resolve plain.other.test >/dev/null
out=$(curl -s -m 2 http://192.0.2.82/ 2>&1; echo "rc=$?"); [[ "$out" != *hello-from* ]] && ok "resolved name without a rule is not proxied" || bad "unexpected proxying"
out=$(curl -s -m 2 http://192.0.2.99/ 2>&1; echo "rc=$?");  [[ "$out" != *hello-from* ]] && ok "IP never seen in DNS is not matched by a domain rule" || bad "unexpected proxying"
grep -q "192.0.2.82\|192.0.2.99" "$PLOG" && bad "proxy saw traffic it should not have" || ok "proxies saw no unmatched destinations"

echo "== latency: first connection right after the answer (no race)"
okc=0; for i in 1 2 3 4 5; do resolve app.example.test >/dev/null; r=$(curl -s -m 5 http://192.0.2.77/); [[ "$r" == *hello-from-A* ]] && okc=$((okc+1)); done
[ "$okc" = 5 ] && ok "5/5 connections matched immediately after resolution" || bad "only $okc/5 matched immediately"

echo "== logging"
sleep 1
grep -q "192.0.2.77 (app.example.test)" "$WORK/pb.out" && ok "connection log shows the domain name" || bad "no domain name in connection log"

echo "== lifecycle"
kill -INT "$PB_PID"; wait "$PB_PID" 2>/dev/null
out=$(dig @$DNSIP app.example.test +short +time=3 +tries=1 | head -1); has "DNS still works after ProxyBridge stops" "$out" "192.0.2.77"
"${BPFTOOL:-bpftool}" prog show 2>/dev/null | grep -q pb_connect && bad "BPF programs left behind" || ok "BPF programs detached"

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "---- dns log"; cat "$DLOG"; echo "---- proxy log"; cat "$PLOG"; echo "---- pb output"; tail -30 "$WORK/pb.out"; exit 1; }
