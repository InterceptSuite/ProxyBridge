#!/bin/bash
# Full end-to-end suite: the installed (or built) ProxyBridge CLI, driven by real .pbprofile files, against REAL forwarding SOCKS5
# servers (Nexus Proxy, one open and one with username/password) and real origin servers written in Python.
#
# The same Python client (tests/full_client.py) runs with the engine OFF (the baseline), with every kind of profile ON, and the
# suite compares the results: the application must not be able to tell the difference, and the proxy logs must show that the traffic
# really went through it (or really did not, for DIRECT/BLOCK rules).
#
#   phase 1  engine OFF            baseline for TCP, UDP, DNS (real packets), QUIC-shaped UDP; the proxies must see nothing
#   phase 2  all traffic proxied   same client, same results, proxies must carry every flow; throughput/loss compared with the baseline
#   phase 3  TCP proxied, UDP direct        UDP never reaches the proxies
#   phase 4  UDP proxied, TCP direct        TCP never reaches the proxies
#   phase 5  everything DIRECT              engine on, nothing proxied
#   phase 6  UDP blocked, TCP proxied       no UDP answer may arrive
#   phase 7  DNS via proxy on vs off        the proxy is asked for the host name or for the address
#   phase 8  load                           500 TCP connections, 1000 UDP sockets, 20000-datagram bursts
#   phase 9  HTTP/3 (real QUIC) with curl   direct first, then through the proxy over UDP ASSOCIATE (needs internet + curl --http3)
#   phase 10 failure handling               wrong password and a dead proxy fail closed; a restarted proxy is used again
#
#   sudo NODE=/path/to/node NEXUS_JS=/path/to/nexus/script.js tests/e2e_full.sh
#   PB_BIN=/usr/local/bin/ProxyBridge   test the installed program (default: $PB_DIR/ProxyBridge, PB_DIR defaults to Linux/output)
#   H3_CURL=/snap/bin/curl              curl with HTTP/3 support (default: any curl whose --version lists HTTP3)
#   KEEP_LOGS=dir  copy the ProxyBridge, proxy and client output there when something fails
#   DL_MB=100 UL_MB=50 STREAM_N=6000    sizes        PHASES="1 2"  only some phases        CLIENT_SCENARIOS="dns"  phases 1-5 run only these
# This script works on a private copy of Nexus (UDP patch and a higher per-address limit for older copies, see where it is made).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"; PB_BIN="${PB_BIN:-$PB_DIR/ProxyBridge}"; PBL="$HERE/pbl"
NODE="${NODE:-node}"; NEXUS_JS="${NEXUS_JS:-}"
[ -x "$PB_BIN" ] || { echo "ProxyBridge not found: $PB_BIN (build first, or set PB_BIN/PB_DIR)"; exit 1; }
command -v "$NODE" >/dev/null 2>&1 && [ -f "$NEXUS_JS" ] || { echo "SKIP: set NODE and NEXUS_JS (see header)"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
want() { [ -z "${PHASES:-}" ] || [[ " $PHASES " == *" $1 "* ]]; }          # PHASES="1 2 8" runs only those phases
SCEN="${CLIENT_SCENARIOS:-tcp udp dns quic}"                              # what phases 1-5 run
export DL_MB="${DL_MB:-100}" UL_MB="${UL_MB:-50}" STREAM_N="${STREAM_N:-6000}"
WORK="$(mktemp -d)"; PASS=0; FAIL=0; SKIP=0; PIDS=(); PB=""
: > "$WORK/off.txt"; REF=0                      # filled by phase 1 (only needed when phases are skipped)
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $1"; SKIP=$((SKIP+1)); }
info() { echo "  info  $1"; }
has()  { [[ "$2" == *"$3"* ]] && ok "$1" || bad "$1 (got: ${2:0:200})"; }
HOSTS_TAG="# pb-e2e-full"
cleanup() { stop_pb; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null
            sed -i "/$HOSTS_TAG/d" /etc/hosts 2>/dev/null
            for i in 1 2 3 4 5 6 53; do ip addr del 10.77.1.$i/32 dev lo 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
for i in 1 2 3 4 5 6 53; do ip addr add 10.77.1.$i/32 dev lo 2>/dev/null; done
# With "DNS via proxy" the proxy is given a host name and has to resolve it itself, with the resolver of this machine: the test
# zone name needs an entry there (removed again on exit). Without it the proxy could not connect and the check would fail.
echo "10.77.1.5 app.example.test $HOSTS_TAG" >> /etc/hosts

# ---- the proxies -------------------------------------------------------------------------------------------------------------
nexus_udp_ok() { # script port -> yes|no
  "$NODE" "$1" -p "$2" >/dev/null 2>&1 & local p=$!; sleep 1.5
  python3 - "$2" <<'PY'
import socket, sys
try:
    c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3); c.sendall(b"\x05\x01\x00"); c.recv(2)
    c.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"); r = c.recv(64); print("yes" if r[1] == 0 else "no")
except Exception: print("no")
PY
  kill $p 2>/dev/null; wait $p 2>/dev/null; }
# A private copy of Nexus. Current Nexus does UDP ASSOCIATE on Linux and has --max-per-ip; older copies get the UDP patch and a
# source edit instead. Nexus allows 500 connections per client address by default, and every proxied UDP socket holds one until
# its session expires: without a higher limit the load phases would measure Nexus's limit, not ProxyBridge.
mkdir -p "$WORK/nexus"; cp "$NEXUS_JS" "$WORK/nexus/script.js"
NX_JS="$WORK/nexus/script.js"
if [ "$(nexus_udp_ok "$NX_JS" 1099)" != yes ]; then
  (cd "$WORK/nexus" && patch -s -p1 < "$HERE/nexus-linux-udp.patch") || { echo "cannot patch Nexus for UDP"; exit 1; }
  [ "$(nexus_udp_ok "$NX_JS" 1099)" = yes ] || { echo "the patched Nexus still cannot do UDP ASSOCIATE"; exit 1; }
  info "stock Nexus cannot do UDP ASSOCIATE on Linux: using a patched private copy"
fi
NXOPT=()
if grep -q -- '--max-per-ip' "$NX_JS"; then NXOPT=(--max-per-ip 20000)                       # current Nexus has the option
else sed -i 's/ipCount >= 500/ipCount >= 20000/; s/maxConnections = 10000/maxConnections = 50000/' "$NX_JS"; fi   # older copies
start_nx() { # port log [args]
  local port=$1 log=$2; shift 2
  "$NODE" "$NX_JS" -v -p "$port" "$@" > "$log" 2>&1 & NXPID=$!; PIDS+=($NXPID)
  for _ in $(seq 40); do ss -ltn 2>/dev/null | grep -q ":$port " && return 0; sleep 0.25; done; echo "nexus on $port did not start"; exit 1; }
NX1LOG="$WORK/nx1.log"; NX2LOG="$WORK/nx2.log"
start_nx 1080 "$NX1LOG" "${NXOPT[@]}"; NX1=$NXPID
start_nx 1081 "$NX2LOG" -u nx -P secret "${NXOPT[@]}"; NX2=$NXPID

# ---- the origins -------------------------------------------------------------------------------------------------------------
python3 "$HERE/nexus_origins.py" > "$WORK/origins.log" 2>&1 & PIDS+=($!)
PB_DNS_ZONE="app.example.test=10.77.1.5;svc.corp.test=10.77.1.6" python3 "$HERE/fake_dns.py" 10.77.1.53 "$WORK/dns.log" >/dev/null 2>&1 & PIDS+=($!)
python3 "$HERE/full_quic_server.py" 10.77.1.1 10.77.1.2 > "$WORK/quic.log" 2>&1 & PIDS+=($!)
sleep 1.5

# ---- profiles (real .pbprofile files, written with the test helper) -------------------------------------------------------------
PX=(--proxy n1=socks5://127.0.0.1:1080 --proxy n2=socks5://nx:secret@127.0.0.1:1081)
mk() { local n=$1; shift; "$PBL" --write "$WORK/$n.pbprofile" "$@" || exit 1; }
# The origin servers are python3 programs too, and the client's source address is one of the 10.77.1.x aliases: a rule for the
# whole /24 on every port would also catch the servers' replies (sendto to the client's ephemeral port) and proxy them back into
# the proxy. The rules therefore name the service ports, like a real set-up would.
# The kernel can decide up to 4 port entries per rule; with more, every datagram of a matching process goes through the relay's
# slow path, which re-sends it from the relay's own socket. A server that shares the rule's process pattern with its client (as
# in this test) then has its replies re-sent too and the client sees them from another source port. Port ranges keep the lists short.
UDPPORTS='18710-18711;53;4433-4434'; TCPPORTS='18700-18705;53'      # at most 4 entries: longer lists cannot be decided in the kernel (see below)
TCP_PROXY=(--rule "python3*:10.77.1.2:$TCPPORTS:TCP:PROXY=n2" --rule "python3*:10.77.1.0/24:$TCPPORTS:TCP:PROXY=n1")
UDP_PROXY=(--rule "python3*:10.77.1.2:$UDPPORTS:UDP:PROXY=n2" --rule "python3*:10.77.1.0/24:$UDPPORTS:UDP:PROXY=n1")
mk all           "${PX[@]}" "${TCP_PROXY[@]}" "${UDP_PROXY[@]}"
mk tcp_only      "${PX[@]}" --rule "python3*:10.77.1.0/24:$UDPPORTS:UDP:DIRECT" "${TCP_PROXY[@]}"
mk udp_only      "${PX[@]}" --rule "python3*:10.77.1.0/24:$TCPPORTS:TCP:DIRECT" "${UDP_PROXY[@]}"
mk direct        "${PX[@]}" --rule "python3*:10.77.1.0/24:$UDPPORTS:UDP:DIRECT" --rule "python3*:10.77.1.0/24:$TCPPORTS:TCP:DIRECT"
mk udp_block     "${PX[@]}" --rule "python3*:10.77.1.0/24:$UDPPORTS:UDP:BLOCK" "${TCP_PROXY[@]}"
mk names_on      --proxy n1=socks5://127.0.0.1:1080 --rule 'python3*:10.77.1.53:53:UDP:PROXY=n1' --rule 'python3*:*.example.test:18700:TCP:PROXY=n1'
mk names_off     --proxy 'n1=socks5://127.0.0.1:1080?dns=local' --rule 'python3*:10.77.1.53:53:UDP:PROXY=n1' --rule 'python3*:*.example.test:18700:TCP:PROXY=n1'
mk auth_bad      --proxy bad=socks5://nx:wrong@127.0.0.1:1081 --rule 'python3*:10.77.1.1:18700:TCP:PROXY=bad' --rule 'python3*:10.77.1.1:18710:UDP:PROXY=bad'
mk h3            "${PX[@]}" --rule 'curl*:*:443:UDP:PROXY=n1'
info "profiles written to $WORK: $(ls "$WORK"/*.pbprofile | xargs -n1 basename | tr '\n' ' ')"
[ -n "${KEEP_PROFILES:-}" ] && { mkdir -p "$KEEP_PROFILES" && cp "$WORK"/*.pbprofile "$KEEP_PROFILES/" && info "profiles copied to $KEEP_PROFILES"; }

# ---- helpers -----------------------------------------------------------------------------------------------------------------
start_pb() { # profile [verbose]
  stop_pb
  stdbuf -oL "$PB_BIN" --profile "$WORK/$1.pbprofile" --verbose "${PB_VERBOSE:-3}" > "$WORK/pb_$1.out" 2>&1 & PB=$!
  for _ in $(seq 60); do grep -q "ProxyBridge started" "$WORK/pb_$1.out" && return 0; kill -0 $PB 2>/dev/null || break; sleep 0.25; done
  echo "ProxyBridge did not start with $1:"; cat "$WORK/pb_$1.out"; exit 1; }
stop_pb() { [ -n "$PB" ] && { kill -INT $PB 2>/dev/null; wait $PB 2>/dev/null; }; PB=""; }
nx_count() { grep -cF -- "$2" "$1" 2>/dev/null || true; }      # log, text
declare -A NXB                                                 # counters before a run
nx_mark()  { NXB[tcp1]=$(nx_count $NX1LOG "[CONNECT]"); NXB[tcp2]=$(nx_count $NX2LOG "[CONNECT]")
             NXB[udp1]=$(nx_count $NX1LOG "[UDP]");     NXB[udp2]=$(nx_count $NX2LOG "[UDP]")
             NXB[dst1]=$(nx_count $NX1LOG "└─>");        NXB[dst2]=$(nx_count $NX2LOG "└─>"); }
nx_delta() { D_TCP=$(( $(nx_count $NX1LOG "[CONNECT]") - NXB[tcp1] + $(nx_count $NX2LOG "[CONNECT]") - NXB[tcp2] ))
             D_UDP=$(( $(nx_count $NX1LOG "[UDP]") - NXB[udp1] + $(nx_count $NX2LOG "[UDP]") - NXB[udp2] ))
             D_DST=$(( $(nx_count $NX1LOG "└─>") - NXB[dst1] + $(nx_count $NX2LOG "└─>") - NXB[dst2] )); }
declare -A MET                                                 # METRIC <phase>/<name> -> value
udp_rcvbuf_errors() { awk '/^Udp:/ { if (!h) { for (i = 1; i <= NF; i++) if ($i == "RcvbufErrors") c = i; h = 1 } else { print $c; exit } }' /proc/net/snmp; }
run_client() { # phase scenario...  (output kept in $WORK/<phase>.txt)
  local ph=$1; shift
  nx_mark
  local rb0; rb0=$(udp_rcvbuf_errors)
  python3 "$HERE/full_client.py" "$@" > "$WORK/$ph.txt" 2>&1
  local rb1; rb1=$(udp_rcvbuf_errors)
  [ "${rb1:-0}" -gt "${rb0:-0}" ] && info "$ph: the kernel dropped $((rb1 - rb0)) UDP datagrams because a receive buffer was full (system wide, any process)"
  nx_delta
  while read -r _ n v; do MET["$ph/$n"]=$v; done < <(grep "^METRIC " "$WORK/$ph.txt")
}
results() { grep "^RESULT ok" "$WORK/$1.txt" | sed 's/^RESULT ok //; s/ |.*//' | sort; }
nbad()    { local c; c=$(grep -c "^RESULT BAD" "$WORK/$1.txt"); echo "${c:-0}"; }
nok()     { local c; c=$(grep -c "^RESULT ok" "$WORK/$1.txt"); echo "${c:-0}"; }
check_phase() { # phase label  : every client check passed
  local b; b=$(nbad "$1")
  if [ "$b" = 0 ] && [ "$(nok "$1")" -gt 0 ]; then ok "$2: $(nok "$1") client checks passed"
  else bad "$2: $b failed checks"; grep -E "^RESULT BAD|crashed" "$WORK/$1.txt" | head -8 | sed 's/^/          /'; fi; }
metric() { echo "${MET[$1]:-n/a}"; }
ratio() { python3 -c "
a, b = '$1', '$2'
print('n/a' if 'n/a' in (a, b) or float(b) == 0 else round(float(a) / float(b), 2))"; }

# =================================================================================================================================
if want 1; then
echo "== phase 1: engine OFF (baseline). The proxies must not see anything"
run_client off $SCEN
check_phase off "baseline"
[ "$D_TCP$D_UDP$D_DST" = "000" ] && ok "baseline: the proxies saw nothing (the engine is off)" || bad "baseline: proxies saw tcp=$D_TCP udp=$D_UDP dst=$D_DST"
REF=$(curl -s -m 120 --socks5 127.0.0.1:1080 -o /dev/null -w "%{speed_download}" "http://10.77.1.1:18700/big?mb=$DL_MB"); REF=$(python3 -c "print(round($REF/1048576))")
info "reference: curl speaking SOCKS5 to nexus itself downloads at ${REF} MB/s (the Python client is slower than curl, so this is only for orientation)"
fi

if want 2; then
echo "== phase 2: all traffic proxied (TCP + UDP), the same client"
start_pb all
run_client all $SCEN
check_phase all "proxied"
[ "$(results off | md5sum)" = "$(results all | md5sum)" ] && ok "same checks pass with the engine on as with it off ($(nok all))" || { bad "result sets differ between engine off and on"; diff <(results off) <(results all) | head -6 | sed 's/^/          /'; }
[ "$D_TCP" -ge 600 ] && ok "the proxies carried the TCP connections ($D_TCP CONNECTs)" || bad "too few CONNECTs reached the proxies ($D_TCP)"
[ "$D_UDP" -ge 100 ] && ok "the proxies opened UDP associations ($D_UDP)" || bad "too few UDP associations ($D_UDP)"
for port in 18710 18711 53 4433; do
  grep -qE "└─> 10\.77\.1\.[0-9]+:$port" "$NX1LOG" "$NX2LOG" && ok "  a proxy relayed UDP to port $port" || bad "  no UDP relayed to port $port"
done
for m in tcp_download_MBps tcp_upload_MBps tcp_request_p50_ms tcp_cycles_per_s udp_rtt_p50_us udp_stream_loss_pct dns_udp_qps; do
  info "$(printf '%-22s off=%-8s on=%-8s on/off=%s' "$m" "$(metric off/$m)" "$(metric all/$m)" "$(ratio "$(metric all/$m)" "$(metric off/$m)")")"
done
python3 -c "import sys; sys.exit(0 if float('${MET[all/tcp_download_MBps]:-0}') >= 0.5 * float('${MET[off/tcp_download_MBps]:-1}') else 1)" \
  && ok "download through ProxyBridge + nexus: ${MET[all/tcp_download_MBps]:-?} MB/s, at least half of the engine-off rate (${MET[off/tcp_download_MBps]:-?} MB/s)" \
  || bad "download ${MET[all/tcp_download_MBps]:-?} MB/s is below half of the engine-off rate ${MET[off/tcp_download_MBps]:-?} MB/s"
python3 -c "import sys; sys.exit(0 if float('${MET[all/udp_stream_loss_pct]:-100}') <= 1.0 else 1)" && ok "UDP stream through the proxy: ${MET[all/udp_stream_loss_pct]}% lost" || bad "UDP stream loss above 1% (${MET[all/udp_stream_loss_pct]:-?})"
fi

if want 3; then
echo "== phase 3: TCP proxied, UDP direct"
start_pb tcp_only
run_client tcp_only $SCEN
check_phase tcp_only "TCP proxied / UDP direct"
[ "$D_TCP" -ge 600 ] && ok "TCP reached the proxies ($D_TCP)" || bad "TCP did not reach the proxies ($D_TCP)"
# DNS over TCP is proxied here, the UDP flows (echo, DNS, QUIC) must never appear
[ "$D_UDP" = 0 ] && [ "$D_DST" = 0 ] && ok "no UDP reached the proxies" || bad "UDP leaked into the proxies (assoc=$D_UDP dst=$D_DST)"
fi

if want 4; then
echo "== phase 4: UDP proxied, TCP direct"
start_pb udp_only
run_client udp_only $SCEN
check_phase udp_only "UDP proxied / TCP direct"
[ "$D_UDP" -ge 100 ] && ok "UDP reached the proxies ($D_UDP associations)" || bad "UDP did not reach the proxies ($D_UDP)"
[ "$D_TCP" = 0 ] && ok "no TCP connection reached the proxies" || bad "TCP leaked into the proxies ($D_TCP)"
fi

if want 5; then
echo "== phase 5: everything DIRECT (engine on, nothing proxied)"
start_pb direct
run_client direct $SCEN
check_phase direct "all DIRECT"
[ "$D_TCP$D_UDP$D_DST" = "000" ] && ok "the proxies saw nothing" || bad "DIRECT rules leaked into the proxies (tcp=$D_TCP udp=$D_UDP)"
[ "$(results off | md5sum)" = "$(results direct | md5sum)" ] && ok "same checks as the baseline" || bad "result sets differ from the baseline"
fi

if want 6; then
echo "== phase 6: UDP blocked, TCP proxied"
start_pb udp_block
run_client udp_block udpblock tcp
check_phase udp_block "UDP BLOCK / TCP PROXY"
[ "$D_UDP" = 0 ] && ok "blocked UDP never reached a proxy" || bad "blocked UDP reached a proxy ($D_UDP)"
grep -q "via BLOCK" "$WORK/pb_udp_block.out" && ok "the connection log shows the block" || bad "no BLOCK in the connection log"
fi

if want 7; then
echo "== phase 7: DNS via proxy ON vs OFF (per proxy)"
NAMECLIENT='import sys; sys.path.insert(0, "'"$HERE"'"); import full_client as c; r = c.dns_udp("app.example.test"); print("answer", r); print(c.http_get("10.77.1.5", 18700))'
for mode in on off; do
  start_pb names_$mode; nx_mark
  out=$(python3 -c "$NAMECLIENT" 2>&1)
  has "names_$mode: the client resolves through the proxy and reaches the origin" "$out" "origin-5"
  if [ "$mode" = on ]; then
    grep -qF "[CONNECT] app.example.test:18700" "$NX1LOG" && ok "DNS via proxy ON: the proxy was asked for the host name app.example.test" || bad "ON: the proxy never received the host name"
  else
    tail -n 30 "$NX1LOG" | grep -qF "[CONNECT] 10.77.1.5:18700" && ok "DNS via proxy OFF: the proxy was given the address 10.77.1.5" || bad "OFF: the proxy did not receive the plain address"
    n_before=$(grep -cF "[CONNECT] app.example.test:18700" "$NX1LOG")
    [ "$n_before" = 1 ] && ok "  and no second request with the name was made" || bad "  host name was sent although DNS via proxy is off ($n_before)"
  fi
done
fi

if want 8; then
echo "== phase 8: load"
start_pb all
run_client load_on load churn
check_phase load_on "load through ProxyBridge + the proxies"
[ "$D_TCP" -ge 450 ] && [ "$D_UDP" -ge 1500 ] && ok "  the proxies carried the load ($D_TCP CONNECTs, $D_UDP UDP associations)" || bad "  load did not go through the proxies (tcp=$D_TCP udp=$D_UDP)"
stop_pb
run_client load_off load churn
check_phase load_off "load without the engine (baseline)"
for r in 3000 6000 12000; do info "UDP at $r datagrams/s, loss: engine off=$(metric load_off/udp_burst_${r}_pps_loss_pct)%  through ProxyBridge+nexus=$(metric load_on/udp_burst_${r}_pps_loss_pct)%"; done
fi

if want 9; then
echo "== phase 9: HTTP/3 (real QUIC) with curl"
H3_CURL="${H3_CURL:-}"
if [ -z "$H3_CURL" ]; then for c in curl /snap/bin/curl; do command -v "$c" >/dev/null 2>&1 && "$c" --version 2>/dev/null | grep -qi "http3" && { H3_CURL=$(command -v "$c"); break; }; done; fi
H3URL="https://www.cloudflare.com/"
if [ -z "$H3_CURL" ]; then skip "no curl with HTTP/3 support (set H3_CURL)"
else
  h3() { timeout 40 "$H3_CURL" --http3-only -s -m 30 -o /dev/null -w "%{http_code} v%{http_version}" "$H3URL" 2>/dev/null | tail -n 1; }   # snap curl prints a banner on stderr
  base=$(h3); info "direct (engine off): $base   [$H3_CURL]"
  if [[ "$base" != "200 v3" ]]; then skip "HTTP/3 does not work even without ProxyBridge (offline or UDP 443 filtered): $base"
  else
    start_pb h3; nx_mark
    via=$(h3)
    has "curl --http3-only through ProxyBridge + nexus (QUIC over SOCKS5 UDP ASSOCIATE)" "$via" "200 v3"
    nx_delta; [ "$D_UDP" -ge 1 ] && grep -qE "└─> .*:443" "$NX1LOG" && ok "  nexus relayed UDP to port 443 ($D_UDP association)" || bad "  nexus saw no UDP to port 443"
    grep -qE "curl.*:443 via SOCKS5 127.0.0.1:1080 \(UDP\)" "$WORK/pb_h3.out" && ok "  the connection log shows the QUIC flow as UDP via the proxy" || bad "  no 'via SOCKS5 ... (UDP)' line for curl in the log"
    n=0; for i in 1 2 3 4 5; do [ "$(h3)" = "200 v3" ] && n=$((n+1)); done; [ "$n" = 5 ] && ok "  5 more HTTP/3 requests in a row" || bad "  only $n/5 further HTTP/3 requests succeeded"
    big=$(timeout 60 "$H3_CURL" --http3-only -s -m 50 -o /dev/null -w "%{http_code} %{size_download}" "https://www.cloudflare.com/cdn-cgi/trace" 2>/dev/null | tail -n 1); has "  small QUIC body transfer" "$big" "200"
  fi
fi
fi

if want 10; then
echo "== phase 10: failure handling"
start_pb auth_bad
out=$(python3 -c "
import sys; sys.path.insert(0, '$HERE'); import full_client as c
try: print('GOT', c.http_get('10.77.1.1', 18700, timeout=8))
except OSError as e: print('FAILED', type(e).__name__)" 2>&1)
[[ "$out" != *origin-1* ]] && ok "wrong proxy password: the connection fails closed (the origin is not reached directly): $out" || bad "wrong password leaked the connection direct: $out"
start_pb all
kill $NX1; wait $NX1 2>/dev/null; sleep 1
out=$(python3 -c "
import sys; sys.path.insert(0, '$HERE'); import full_client as c
try: print('GOT', c.http_get('10.77.1.1', 18700, timeout=6))
except OSError as e: print('FAILED', type(e).__name__)" 2>&1)
[[ "$out" != *origin-1* ]] && ok "proxy down: TCP fails closed, no leak around it ($out)" || bad "TCP leaked around the dead proxy: $out"
python3 "$HERE/full_client.py" udpblock | grep -q "RESULT ok" && ok "proxy down: UDP gets no answer either" || bad "UDP answered although its proxy is down"
start_nx 1080 "$NX1LOG.2" "${NXOPT[@]}"; NX1=$NXPID; sleep 1
out=$(python3 -c "
import sys; sys.path.insert(0, '$HERE'); import full_client as c
print(c.http_get('10.77.1.1', 18700))" 2>&1); has "proxy restarted: TCP works again" "$out" "origin-1"
rec=$(python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1); t0 = time.time()
while time.time() - t0 < 15:
    try:
        s.sendto(b"again", ("10.77.1.1", 18710)); d, a = s.recvfrom(100); print("recovered in %.1fs: %s" % (time.time() - t0, d.decode())); break
    except socket.timeout: pass
else: print("NOT RECOVERED")
PY
); has "proxy restarted: UDP re-associates" "$rec" "recovered in"; info "$rec"
stop_pb
fi

echo; echo "passed=$PASS failed=$FAIL skipped=$SKIP"
if [ "$FAIL" != 0 ]; then
  [ -n "${KEEP_LOGS:-}" ] && { mkdir -p "$KEEP_LOGS" && cp "$WORK"/*.out "$WORK"/*.log "$WORK"/*.txt "$KEEP_LOGS/" 2>/dev/null; echo "logs kept in $KEEP_LOGS"; }
  echo "---- last ProxyBridge output"; tail -15 "$WORK"/pb_*.out 2>/dev/null | tail -30
  echo "---- nexus 1"; tail -8 "$NX1LOG"; echo "---- nexus 2"; tail -8 "$NX2LOG"; exit 1
fi
