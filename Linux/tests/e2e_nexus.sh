#!/bin/bash
# ProxyBridge against a REAL forwarding SOCKS5 server: Nexus Proxy (https://github.com/InterceptSuite/nexus-proxy).
# Real origin servers, real DNS, real transfers with checksums; two Nexus instances (open + username/password) so that rules
# can pick a proxy. Needs root, node, dig, curl, python3, and the Nexus script.
#
#   sudo NODE=/path/to/node NEXUS_JS=/path/to/script.js tests/e2e_nexus.sh
#
# Nexus Proxy 1.1 and later does UDP ASSOCIATE on Linux. Older copies cannot (their IPv6 relay socket binds '0.0.0.0', IPv4
# destinations are not sent as ::ffff: addresses and mapped replies are not matched): apply tests/nexus-linux-udp.patch to a copy of
# their script.js for the UDP part; without it the UDP tests are reported as SKIP and only TCP/DNS-over-TCP is tested.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
NODE="${NODE:-node}"; NEXUS_JS="${NEXUS_JS:-}"
command -v "$NODE" >/dev/null 2>&1 && [ -f "$NEXUS_JS" ] || { echo "SKIP: set NODE and NEXUS_JS (see header)"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export LD_LIBRARY_PATH="$PB_DIR"
WORK="$(mktemp -d)"; PASS=0; FAIL=0; SKIP=0; PIDS=()
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $1"; SKIP=$((SKIP+1)); }
info() { echo "  info  $1"; }
has()  { [[ "$2" == *"$3"* ]] && ok "$1" || bad "$1 (got: ${2:0:150})"; }
eq()   { [ "$2" = "$3" ] && ok "$1" || bad "$1 (got: ${2:0:150})"; }                  # exact match
inlog() { grep -qF -- "$2" "$1" 2>/dev/null; }               # log file, text
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null
            for i in 1 2 3 4 5 6 53; do ip addr del 10.77.1.$i/32 dev lo 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
for i in 1 2 3 4 5 6 53; do ip addr add 10.77.1.$i/32 dev lo 2>/dev/null; done

# ---- udp support probe: does this Nexus copy handle UDP ASSOCIATE on Linux?
"$NODE" "$NEXUS_JS" -p 1099 >/dev/null 2>&1 & PROBE=$!; sleep 1.5
UDPOK=$(python3 - <<'PY'
import socket
try:
    c = socket.create_connection(("127.0.0.1", 1099), timeout=3); c.sendall(b"\x05\x01\x00"); c.recv(2)
    c.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); r = c.recv(64); print("yes" if r[1] == 0 else "no")
except Exception: print("no")
PY
)
kill $PROBE 2>/dev/null; wait $PROBE 2>/dev/null
[ "$UDPOK" = yes ] || info "this Nexus copy cannot do UDP ASSOCIATE here (apply tests/nexus-linux-udp.patch): UDP tests will be skipped"

python3 "$HERE/nexus_origins.py" > "$WORK/origins.log" 2>&1 & PIDS+=($!)
PB_DNS_ZONE="app.example.test=10.77.1.5;svc.corp.test=10.77.1.6" python3 "$HERE/fake_dns.py" 10.77.1.53 "$WORK/dns.log" >/dev/null 2>&1 & PIDS+=($!)
start_nx() { # port log [extra args]
  local port=$1 log=$2; shift 2
  "$NODE" "$NEXUS_JS" -v -p "$port" "$@" > "$log" 2>&1 & NXPID=$!; PIDS+=($NXPID)
  for _ in $(seq 40); do ss -ltn 2>/dev/null | grep -q ":$port " && return 0; sleep 0.25; done; echo "nexus on $port did not start"; cat "$log"; exit 1; }
NX1LOG="$WORK/nx1.log"; NX2LOG="$WORK/nx2.log"
start_nx 1080 "$NX1LOG"; NX1=$NXPID
start_nx 1081 "$NX2LOG" -u nx -P secret; NX2=$NXPID
sleep 1
mkdir -p "$WORK/bin"; cp "$(command -v curl)" "$WORK/bin/wget"
read -r -d '' EXPECT_PY <<'PY'
import hashlib, sys
B = bytes((i * 7 + 13) & 255 for i in range(1 << 20)); h = hashlib.sha256()
for _ in range(int(sys.argv[1])): h.update(B)
print(h.hexdigest())
PY
sha_for() { python3 -c "$EXPECT_PY" "$1"; }

# ?dns=local: the proxies are given the address (the zone names of the fake DNS server do not exist for Nexus); the by-name case
# (DNS via proxy on) is covered by tests/e2e_full.sh, where Nexus can resolve the name
stdbuf -oL "$PBL" --verbose 2 \
  --proxy 'n1=socks5://127.0.0.1:1080?dns=local' --proxy 'n2=socks5://nx:secret@127.0.0.1:1081?dns=local' \
  --rule "curl:10.77.1.3:*:TCP:DIRECT" \
  --rule "curl:10.77.1.4:*:TCP:BLOCK" \
  --rule "curl:10.77.1.1:18701-18703:TCP:PROXY=n2" \
  --rule "curl:10.77.1.1:18700:TCP:PROXY=n1" \
  --rule "curl:10.77.1.2:*:TCP:PROXY=n2" \
  --rule "wget:10.77.1.0/24:*:TCP:PROXY=n2" \
  --rule "python3*:10.77.1.1:18700:TCP:PROXY=n1" \
  --rule "*:*.example.test:*:TCP:PROXY=n2" \
  --rule "*:*.corp.test:*:TCP:PROXY=n1" \
  --rule "python3*:10.77.1.1:18710:UDP:PROXY=n1" \
  --rule "python3*:10.77.1.2:18710:UDP:PROXY=n2" \
  --rule "python3*:10.77.1.1:18711:UDP:PROXY=n1" \
  --rule "dig;python3*:10.77.1.53:53:UDP:PROXY=n1" \
  --rule "dig;python3*:10.77.1.53:53:TCP:PROXY=n1" \
  > "$WORK/pb.out" 2>&1 & PB=$!; PIDS+=($PB)
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
grep -q "ProxyBridge started" "$WORK/pb.out" || { echo "ProxyBridge failed to start"; cat "$WORK/pb.out"; exit 1; }
sleep 1
O() { curl -s -m 10 "$@"; }

echo "== TCP: different rules -> different Nexus instances (real forwarding)"
out=$(O http://10.77.1.1:18700/);   has "ip+port rule -> nexus n1 (open)"             "$out" "origin-1"
inlog $NX1LOG "[CONNECT] 10.77.1.1:18700" && ok "  n1 log shows the CONNECT to 10.77.1.1:18700" || bad "  n1 never saw the connection"
out=$(O http://10.77.1.2:18700/);   has "whole-IP rule -> nexus n2 (username/password)" "$out" "origin-2"
inlog $NX2LOG "[CONNECT] 10.77.1.2:18700" && ok "  n2 log shows the CONNECT (auth succeeded)" || bad "  n2 never saw the connection"
out=$(O http://10.77.1.1:18702/);   has "port-range rule 18701-18703 -> n2"           "$out" "origin-1-p18702"
inlog $NX2LOG "[CONNECT] 10.77.1.1:18702" && ok "  n2 carried port 18702" || bad "  n2 did not carry 18702"
out=$(O http://10.77.1.1:18704/);   has "port outside every rule is direct (served)"   "$out" "origin-1-p18704"
inlog $NX1LOG "10.77.1.1:18704" || inlog $NX2LOG "10.77.1.1:18704" && bad "  18704 leaked into a proxy" || ok "  neither nexus saw 18704"
out=$(O http://10.77.1.3:18700/);   has "DIRECT rule bypasses nexus"                  "$out" "origin-3"
inlog $NX1LOG "10.77.1.3" || inlog $NX2LOG "10.77.1.3" && bad "  DIRECT leaked into a proxy" || ok "  neither nexus saw 10.77.1.3"
out=$(O http://10.77.1.4:18700/ 2>&1; echo "rc=$?"); has "BLOCK rule rejects" "$out" "rc=7"
out=$("$WORK/bin/wget" -s -m 10 http://10.77.1.1:18704/); has "same destination, other process (wget) -> n2" "$out" "origin-1-p18704"
inlog $NX2LOG "[CONNECT] 10.77.1.1:18704" && ok "  n2 saw wget's connection (curl's to the same address stayed direct)" || bad "  wget was not proxied"

echo "== Domain rules with a real resolver, DNS itself carried by Nexus"
# DNS over UDP needs UDP ASSOCIATE through nexus; with a Nexus copy that cannot do it, resolve over TCP instead
if [ "$UDPOK" = yes ]; then DIGMODE=""; DNSKIND="UDP"; else DIGMODE="+tcp"; DNSKIND="TCP"; fi
ip5=$(dig @10.77.1.53 app.example.test +short +time=3 +tries=1 $DIGMODE | head -1);  eq "dig answer (${DNSKIND} DNS via nexus n1)" "$ip5" "10.77.1.5"
out=$(O http://10.77.1.5:18700/); [ -n "$out" ] || { echo "        (empty answer; verbose retry:)"; curl -sv -m 10 http://10.77.1.5:18700/ 2>&1 | tail -12 | sed "s/^/        /"; }
has "*.example.test -> n2"                         "$out" "origin-5"
inlog $NX2LOG "[CONNECT] 10.77.1.5:18700" && ok "  n2 carried the domain-matched connection" || bad "  not via n2"
ip6=$(dig @10.77.1.53 +tcp svc.corp.test +short +time=3 +tries=1 | head -1); eq "dig answer (TCP DNS via nexus n1)" "$ip6" "10.77.1.6"
out=$(O http://10.77.1.6:18700/);   has "*.corp.test -> n1"                            "$out" "origin-6"
inlog $NX1LOG "[CONNECT] 10.77.1.6:18700" && ok "  n1 carried the domain-matched connection" || bad "  not via n1"
inlog $NX1LOG "[CONNECT] 10.77.1.53:53" && ok "  n1 carried the DNS-over-TCP query" || bad "  DNS/TCP did not go through n1"
grep -q "10.77.1.5 (app.example.test)" "$WORK/pb.out" && ok "  connection log names the domain" || bad "  no domain in the connection log"

echo "== the proxy's own process is exempted automatically (no DIRECT rule for node exists)"
inlog $NX2LOG "[CONNECT] 10.77.1.5:18700" && ok "  nexus's own outbound connections were not sent back through itself" || bad "  proxy loop"
before=$(grep -cF "[CONNECT] 10.77.1.5:18700" "$NX2LOG")
"$NODE" -e "require('net').connect(18700,'10.77.1.5').on('connect',function(){this.end()}).on('error',()=>{})"; sleep 1
after=$(grep -cF "[CONNECT] 10.77.1.5:18700" "$NX2LOG")
[ "$after" -gt "$before" ] && ok "another node process (not the proxy) is still proxied: exemption is per process, not per binary" || bad "unrelated node process bypassed the rules"

echo "== TCP: many connections, big transfers, integrity"
cpids=(); for i in $(seq 1 100); do (O http://10.77.1.1:18700/ > "$WORK/p$i.out") & cpids+=($!); done; wait "${cpids[@]}" 2>/dev/null
okc=$(grep -l "origin-1" "$WORK"/p*.out 2>/dev/null | wc -l); [ "$okc" = 100 ] && ok "100 parallel connections through n1" || bad "only $okc/100 parallel connections succeeded"
fail=0; for i in $(seq 1 1500); do r=$(O http://10.77.1.1:18700/); [ "$r" = origin-1 ] || fail=$((fail+1)); done; [ "$fail" = 0 ] && ok "1500 sequential connect/close cycles through n1" || bad "$fail/1500 sequential requests failed"
MB=200; WANT=$(sha_for $MB)
t0=$(date +%s.%N); GOT=$(O -m 120 "http://10.77.1.1:18700/big?mb=$MB" | sha256sum | cut -d' ' -f1); t1=$(date +%s.%N)
[ "$GOT" = "$WANT" ] && ok "200 MB download through n1: checksum identical" || bad "200 MB download corrupted"
T_PB=$(python3 -c "print(round($MB/($t1-$t0)))")
t0=$(date +%s.%N); GOT=$(O -m 120 --socks5 127.0.0.1:1080 "http://10.77.1.1:18704/big?mb=$MB" | sha256sum | cut -d' ' -f1); t1=$(date +%s.%N)
T_SOCKS=$(python3 -c "print(round($MB/($t1-$t0)))"); [ "$GOT" = "$WANT" ] || bad "reference download via --socks5 corrupted"
t0=$(date +%s.%N); GOT=$(O -m 120 "http://10.77.1.1:18704/big?mb=$MB" | sha256sum | cut -d' ' -f1); t1=$(date +%s.%N)
T_DIRECT=$(python3 -c "print(round($MB/($t1-$t0)))")
info "throughput, 200 MB: direct ${T_DIRECT} MB/s | curl speaking SOCKS5 to nexus itself ${T_SOCKS} MB/s | curl -> ProxyBridge -> nexus ${T_PB} MB/s"
python3 -c "import sys; sys.exit(0 if $T_PB >= 0.8*$T_SOCKS else 1)" && ok "ProxyBridge in front of nexus is within 20% of the application speaking SOCKS5 itself" || bad "ProxyBridge overhead above 20% (${T_PB} vs ${T_SOCKS} MB/s)"
python3 - <<PY > "$WORK/up.bin"
import sys
B = bytes((i * 7 + 13) & 255 for i in range(1 << 20)); w = sys.stdout.buffer
for _ in range(100): w.write(B)
PY
WANT=$(sha_for 100); GOT=$(O -m 120 --data-binary @"$WORK/up.bin" http://10.77.1.2:18700/upload)
[ "$GOT" = "$WANT" ] && ok "100 MB upload through n2 (auth): origin received identical bytes" || bad "upload mismatch (${GOT:0:20})"
half=$(python3 - <<'PY'
import socket, struct
def exchange(s):
    s.sendall(b"GET / HTTP/1.0\r\n\r\n"); s.shutdown(socket.SHUT_WR)          # half-close, then read the answer
    data = b""
    while True:
        d = s.recv(4096)
        if not d: break
        data += d
    return "origin-1" in data.decode()
# (a) through ProxyBridge: the python3 rule redirects this connection to nexus n1
print("via-proxybridge:", exchange(socket.create_connection(("10.77.1.1", 18700), timeout=10)))
# (b) reference: the application speaks SOCKS5 to nexus itself (loopback is never redirected)
c = socket.create_connection(("127.0.0.1", 1080), timeout=10); c.sendall(b"\x05\x01\x00"); c.recv(2)
c.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("10.77.1.1") + struct.pack("!H", 18700)); c.recv(10)
print("direct-socks:", exchange(c))
PY
)
echo "$half" | sed 's/^/        /'
if [[ "$half" == *"direct-socks: True"* ]]; then has "half-close through ProxyBridge (client FIN, response still delivered)" "$half" "via-proxybridge: True"
else [[ "$half" == *"via-proxybridge: False"* ]] && ok "half-close: identical to the application speaking SOCKS5 itself (nexus does not support half-open connections: Node allowHalfOpen=false)" || bad "half-close differs from the reference ($half)"; fi

echo "== UDP through nexus"
if [ "$UDPOK" = yes ]; then
out=$(python3 - <<'PY'
import socket, time, concurrent.futures as cf
def sock(t=4):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(t); return s
s = sock()
for dst, tag in [(("10.77.1.1", 18710), "U1:"), (("10.77.1.2", 18710), "U2:"), (("10.77.1.1", 18710), "U1:")]:
    s.sendto(b"hello", dst); d, a = s.recvfrom(100)
    print("one-socket", dst[0], "->", d.decode(), "from", a[0] + ":" + str(a[1]))
c = sock(); c.connect(("10.77.1.1", 18711)); c.send(b"conn"); d = c.recv(100)
print("connected", d.decode(), "peer", "%s:%d" % c.getpeername())
big = bytes(range(256)) * 234                                       # 59,904 bytes
b = sock(8); b.sendto(big, ("10.77.1.1", 18710)); d, a = b.recvfrom(70000)
print("big", "ok" if d == b"U1:" + big else "MISMATCH %d" % len(d))
def one(i):
    k = sock(8); k.sendto(b"n%d" % i, ("10.77.1.%d" % (1 + i % 2), 18710)); d, a = k.recvfrom(100)
    return d.endswith(b"n%d" % i) and a[0] == "10.77.1.%d" % (1 + i % 2)
with cf.ThreadPoolExecutor(32) as ex: r = list(ex.map(one, range(300)))
print("concurrent", sum(r), "/ 300")
# sustained stream: 6000 datagrams of 1000 bytes at ~3000 pps, receiving while sending
import threading
q = sock(1); q.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20); got = set(); sent = 6000; stop = threading.Event()
def rx():
    q.settimeout(0.2)
    while not stop.is_set():
        try:
            d, a = q.recvfrom(2000); got.add(int.from_bytes(d[3:7], "big"))
        except socket.timeout: pass
th = threading.Thread(target=rx, daemon=True); th.start(); t0 = time.perf_counter()
for i in range(sent):
    q.sendto(i.to_bytes(4, "big") + b"x" * 996, ("10.77.1.1", 18710))
    while time.perf_counter() < t0 + (i + 1) / 3000.0: time.sleep(0)
time.sleep(2); stop.set(); th.join()
print("stream", len(got), "/", sent, "replies")
# round-trip latency of small datagrams
l = sock(2); ts = []
for i in range(1500):
    t = time.perf_counter(); l.sendto(b"p", ("10.77.1.1", 18710)); l.recvfrom(100); ts.append(time.perf_counter() - t)
ts.sort(); print("rtt p50=%dus p99=%dus" % (ts[len(ts)//2]*1e6, ts[int(len(ts)*.99)]*1e6))
PY
)
echo "$out" | sed 's/^/        /'
has "UDP one socket -> nexus n1 (destination 1)"            "$out" "one-socket 10.77.1.1 -> U1:hello from 10.77.1.1:18710"
has "same socket -> nexus n2 with auth (destination 2)"      "$out" "one-socket 10.77.1.2 -> U2:hello from 10.77.1.2:18710"
has "connected UDP socket, getpeername restored"             "$out" "connected U3:conn peer 10.77.1.1:18711"
has "59,904-byte datagram round trip through nexus"          "$out" "big ok"
has "300 concurrent UDP sockets across both proxies"         "$out" "concurrent 300 / 300"
n=$(grep -o "stream [0-9]*" <<<"$out" | grep -o "[0-9]*"); [ "${n:-0}" -ge 5940 ] && ok "sustained stream: ${n}/6000 datagrams echoed (>= 99%)" || bad "stream lost too much (${n:-0}/6000)"
inlog $NX1LOG "10.77.1.1:18710" && inlog $NX2LOG "10.77.1.2:18710" && ok "  both nexus logs list their UDP destinations" || bad "  nexus logs lack the UDP destinations"
dq=$(dig @10.77.1.53 app.example.test +short +time=3 +tries=1 | head -1); eq "UDP DNS through nexus still answers" "$dq" "10.77.1.5"
else
  skip "UDP tests (stock Nexus cannot do UDP ASSOCIATE on Linux; apply tests/nexus-linux-udp.patch)"
fi

echo "== resilience: proxy dies and comes back"
if [ "$UDPOK" = yes ]; then
  python3 - <<'PY' > "$WORK/udp_pre.out"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4); s.sendto(b"x", ("10.77.1.1", 18710)); print(s.recv(10).decode())
PY
fi
kill $NX1; wait $NX1 2>/dev/null; sleep 1
out=$(O -m 4 http://10.77.1.1:18700/ 2>&1; echo "rc=$?"); [[ "$out" != *origin-1* ]] && ok "with nexus n1 down the request fails (no leak around the proxy)" || bad "request bypassed the dead proxy"
start_nx 1080 "$NX1LOG.2"; NX1=$NXPID; sleep 1
out=$(O http://10.77.1.1:18700/);  has "TCP works again after nexus n1 restarts" "$out" "origin-1"
if [ "$UDPOK" = yes ]; then
  rec=$(python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1); t0 = time.time()
while time.time() - t0 < 12:
    try:
        s.sendto(b"again", ("10.77.1.1", 18710)); d, a = s.recvfrom(100); print("recovered in %.1fs: %s" % (time.time() - t0, d.decode())); break
    except socket.timeout: pass
else: print("NOT RECOVERED")
PY
  ); has "UDP session re-associates after nexus restarts" "$rec" "recovered in"; info "$rec"
fi
kill $NX2; wait $NX2 2>/dev/null; sleep 1
out=$(O -m 4 http://10.77.1.2:18700/ 2>&1; echo "rc=$?"); [[ "$out" != *origin-2* ]] && ok "with n2 down its rule fails closed (nothing goes direct)" || bad "n2 rule leaked to direct"

echo; echo "passed=$PASS failed=$FAIL skipped=$SKIP"
[ "$FAIL" = 0 ] || { echo "---- pb output"; tail -25 "$WORK/pb.out"; echo "---- nx1"; tail -8 "$NX1LOG"; echo "---- nx2"; tail -8 "$NX2LOG"; exit 1; }
