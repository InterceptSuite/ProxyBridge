#!/bin/bash
# Overhead of the eBPF hooks on DIRECT traffic. Needs root. sudo tests/hookbench.sh <path-to-hookbench-binary>
HB=${1:?path to hookbench}; ROOT="$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")"
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
export LD_LIBRARY_PATH="$PB_DIR"
IP=10.77.0.1   # alias on lo: local like loopback, but not caught by the implicit-loopback bypass
ip addr add $IP/32 dev lo 2>/dev/null
trap 'ip addr del $IP/32 dev lo 2>/dev/null' EXIT
run() { for i in 1 2 3; do $HB udp $IP 19556 1000000; done; }
echo "### A: ProxyBridge not running"; run
start() { stdbuf -oL "$PBL" "$@" > /tmp/pbbench.out 2>&1 & PB=$!; for _ in $(seq 40); do grep -q "ProxyBridge started" /tmp/pbbench.out && break; sleep 0.25; done; }
echo "### B: running, 20 rules for other programs (this binary: empty class -> immediate direct)"
start $(for i in $(seq 20); do echo --rule "someapp$i:*:*:BOTH:PROXY"; done); run; kill -INT $PB; wait $PB 2>/dev/null
echo "### C: running, rules that match this binary but not this destination (full rule evaluation, then direct)"
start --rule "hookbench:192.0.2.0/24:*:BOTH:PROXY" --rule "hookbench:198.51.100.0/24:80;443;8000-9000:BOTH:PROXY" --rule "hookbench:203.0.113.0/24:*:BOTH:BLOCK"; run; kill -INT $PB; wait $PB 2>/dev/null
echo "### D: running, wildcard process rule with 4 destination ranges (every process evaluated)"
start --rule "*:192.0.2.0/24;198.51.100.0/24;203.0.113.0/24;100.64.0.0/10:*:BOTH:PROXY"; run; kill -INT $PB; wait $PB 2>/dev/null
