#!/bin/bash
# Fault tests: what a misbehaving SOCKS5 or HTTP proxy does to a connection, and what ProxyBridge reports.
# Every case ends with the client seeing a clean close (never a hang) and a readable reason in the log. Needs root, python3.
#   sudo Linux/tests/e2e_faults.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
WORK="$(mktemp -d)"; FLOG="$WORK/fault.log"; : > "$FLOG"
PASS=0; FAIL=0; DST=203.0.113.10
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
PB_PID=""
cleanup() { [ -n "$PB_PID" ] && kill "$PB_PID" 2>/dev/null; kill $FAKE $FAKE2 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export LD_LIBRARY_PATH="$PB_DIR"
python3 "$HERE/fault_proxies.py" "$FLOG" > /dev/null 2>&1 & FAKE=$!
python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" > /dev/null 2>&1 & FAKE2=$!
sleep 1

start_pb() {
  stdbuf -oL "$PBL" --verbose 1 "$@" > "$WORK/pb.out" 2>&1 & PB_PID=$!
  for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && return 0; kill -0 "$PB_PID" 2>/dev/null || return 1; sleep 0.25; done; return 1
}
stop_pb() { kill -INT "$PB_PID" 2>/dev/null; wait "$PB_PID" 2>/dev/null; PB_PID=""; }

# case_ <name> <port> <mode> <result prefix> <log substring, client:<text the client must see>, or -> [timeout]
case_() {
  local name="$1" port="$2" mode="$3" want="$4" log="${5:--}" t="${6:-15}"
  local before; before=$(wc -l < "$WORK/pb.out")
  local res; res=$(timeout 40 python3 "$HERE/tcp_probe.py" $DST "$port" "$mode" "$t" 2>&1 | tail -1)
  sleep 0.2
  local newlog; newlog=$(tail -n +$((before + 1)) "$WORK/pb.out")
  if [[ "$res" != "RESULT $want"* ]]; then bad "$name (client: $res)"; return; fi
  if [[ "$log" == client:* ]]; then
    [[ "$res" == *"${log#client:}"* ]] || { bad "$name (client lacks '${log#client:}': $res)"; return; }
  elif [ "$log" != "-" ] && [[ "$newlog" != *"$log"* ]]; then bad "$name (log lacks '$log': ${newlog:0:240})"; return; fi
  ok "$name"
}

echo "== SOCKS5 proxy: every failure code is reported, the client is closed cleanly"
start_pb --proxy s=socks5://127.0.0.1:19100 --rule "python3*:$DST:9001-9032:TCP:PROXY=s" || { bad "start"; cat "$WORK/pb.out"; }
case_ "REP 1 general failure"        9001 get CLOSED "general SOCKS server failure"
case_ "REP 2 not allowed"            9002 get CLOSED "connection not allowed by ruleset"
case_ "REP 3 network unreachable"    9003 get CLOSED "network unreachable"
case_ "REP 4 host unreachable"       9004 get CLOSED "host unreachable"
case_ "REP 5 connection refused"     9005 get CLOSED "connection refused by target"
case_ "REP 6 TTL expired"            9006 get CLOSED "TTL expired"
case_ "REP 7 command not supported"  9007 get CLOSED "command not supported"
case_ "REP 8 address type"           9008 get CLOSED "address type not supported"
case_ "BND is a domain name"         9010 get DATA "-"
case_ "BND is IPv6"                  9011 get DATA "-"
case_ "BND of an unknown type"       9012 get CLOSED "unknown address type"
case_ "proxy closes after request"   9013 get CLOSED "connection closed by peer during handshake"
case_ "proxy closes after greeting"  9019 get CLOSED "connection closed by peer during handshake"
case_ "SOCKS4-style reply"           9015 get CLOSED "bad SOCKS5 reply version"
case_ "data then close"              9016 get DATA "-"
case_ "4 MiB from the proxy arrive intact"       9017 pattern "PATTERN ok 4194304"
case_ "2 MiB echoed both ways arrive intact"     9018 echo    "ECHO ok 2097152"
case_ "proxy that never answers times out"       9014 get CLOSED "timed out" 30
echo "== the relay still works after all that"
case_ "healthy connection afterwards" 9018 echo "ECHO ok 2097152"
stop_pb

echo "== SOCKS5 greeting and login variants"
for spec in "19101:gssapi:unsupported auth method 0x01" "19102:none:rejected all auth methods"; do
  IFS=: read -r p n want <<< "$spec"
  start_pb --proxy "g=socks5://bob:pw@127.0.0.1:$p" --rule "python3*:$DST:9018:TCP:PROXY=g" || bad "start"
  case_ "$n" 9018 get CLOSED "$want"; stop_pb
done
start_pb --proxy g=socks5://bob:wrong@127.0.0.1:19103 --rule "python3*:$DST:9018:TCP:PROXY=g" || bad "start"
case_ "login rejected" 9018 get CLOSED "authentication failed (wrong username or password)"; stop_pb
start_pb --proxy g=socks5://127.0.0.1:19104 --rule "python3*:$DST:9018:TCP:PROXY=g" || bad "start"
case_ "proxy wants a login, none configured" 9018 get CLOSED "requires username/password but none configured"; stop_pb
LONGU=$(python3 -c "print('u'*255)"); LONGP=$(python3 -c "print('p'*255)")
start_pb --proxy "g=socks5://$LONGU:$LONGP@127.0.0.1:19105" --rule "python3*:$DST:9018:TCP:PROXY=g" || bad "start"
case_ "255-byte user and password are sent intact" 9018 echo "ECHO ok"; stop_pb
grep -q "userlen 255 passlen 255" "$FLOG" && ok "the proxy received 255+255 bytes of credentials" || bad "credential lengths: $(grep AUTH "$FLOG" | tail -2)"

echo "== HTTP CONNECT proxy: every refusal is reported"
start_pb --proxy h=http://127.0.0.1:19110 --rule "python3*:$DST:9021-9032:TCP:PROXY=h" || { bad "start"; cat "$WORK/pb.out"; }
case_ "403"                              9021 get CLOSED "forbids this connection (403)"
case_ "407 without credentials"          9022 get CLOSED "authentication required (407)"
case_ "502"                              9023 get CLOSED "upstream error (502)"
case_ "503"                              9024 get CLOSED "upstream error (503)"
case_ "301"                              9025 get CLOSED "refused CONNECT (301)"
case_ "early data after the headers is delivered" 9026 get DATA "client:EARLY-DATA"
case_ "reply that is not HTTP"           9027 get CLOSED "invalid HTTP proxy response"
case_ "proxy closes without replying"    9028 get CLOSED "connection closed by peer during handshake"
case_ "200 then close"                   9030 get CLOSED "-"
case_ "headers arriving in two segments" 9031 get DATA "client:echo:"
case_ "oversized header block"           9032 get CLOSED "headers too large"
case_ "proxy that never answers times out" 9029 get CLOSED "timed out" 30
case_ "healthy connection afterwards"    9031 get DATA "client:echo:"
stop_pb

echo "== a stalled upstream cannot starve connections that use another one"
start_pb --proxy s=socks5://127.0.0.1:19100 --proxy a=socks5://127.0.0.1:19080 \
  --rule "python3*:$DST:9014:TCP:PROXY=s" --rule "python3*:203.0.113.11:80:TCP:PROXY=a" || { bad "start"; cat "$WORK/pb.out"; }
HUNG=()
for i in $(seq 60); do python3 "$HERE/tcp_probe.py" $DST 9014 get 14 > /dev/null 2>&1 & HUNG+=($!); done
sleep 1.5
t0=$(date +%s.%N)
res=$(timeout 20 python3 "$HERE/tcp_probe.py" 203.0.113.11 80 get 10 2>&1 | tail -1)
dt=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b - a}')
if [[ "$res" == *"hello-from-A"* ]] && awk -v d="$dt" 'BEGIN{exit !(d < 3)}'; then ok "healthy proxy answered in ${dt}s while 60 connections waited on a stalled one"
else bad "healthy connection was held up (${dt}s): $res"; fi
wait "${HUNG[@]}" 2>/dev/null
stop_pb

echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
