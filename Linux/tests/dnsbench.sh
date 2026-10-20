#!/bin/bash
# Latency/throughput of DNS queries with and without the DNS tap. Needs root, python3.
#   sudo tests/dnsbench.sh [queries]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"; N=${1:-20000}
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
export LD_LIBRARY_PATH="$PB_DIR"; DNSIP=10.77.0.3
WORK=$(mktemp -d); trap 'kill $DNS $PB 2>/dev/null; wait 2>/dev/null; ip addr del $DNSIP/32 dev lo 2>/dev/null; rm -rf $WORK' EXIT
ip addr add $DNSIP/32 dev lo 2>/dev/null
python3 "$HERE/fake_dns.py" $DNSIP $WORK/dns.log >/dev/null 2>&1 & DNS=$!
sleep 1
bench() { python3 - "$N" "$DNSIP" <<'PY'
import socket, struct, sys, time
n, ip = int(sys.argv[1]), sys.argv[2]
q = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x03app\x07example\x04test\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
lat = []
t0 = time.perf_counter()
for i in range(n):
    a = time.perf_counter(); s.sendto(q, (ip, 53)); s.recvfrom(512); lat.append(time.perf_counter() - a)
dt = time.perf_counter() - t0; lat.sort()
print("  %d queries: %.0f qps  avg=%.0fus p50=%.0fus p99=%.0fus" % (n, n / dt, sum(lat) / n * 1e6, lat[n // 2] * 1e6, lat[int(n * 0.99)] * 1e6))
PY
}
echo "== no ProxyBridge"; bench; bench
stdbuf -oL "$PBL" --proxy a=socks5://127.0.0.1:19080 --rule "*:*.example.test:*:TCP:PROXY=a" > $WORK/pb.out 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" $WORK/pb.out && break; sleep 0.25; done
echo "== ProxyBridge running, python3 covered by a domain rule (every query goes through the DNS tap)"; bench; bench
kill -INT $PB; wait $PB 2>/dev/null
stdbuf -oL "$PBL" --proxy a=socks5://127.0.0.1:19080 --rule "someother:*.example.test:*:TCP:PROXY=a" > $WORK/pb.out 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" $WORK/pb.out && break; sleep 0.25; done
echo "== ProxyBridge running, python3 NOT covered (DNS untouched by the tap)"; bench; bench
