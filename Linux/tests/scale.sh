#!/bin/bash
# Holds N concurrent proxied TCP connections open through the full stack and reports ProxyBridge memory / CPU.
#   sudo tests/scale.sh [N]
set -u
N=${1:-10000}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
export LD_LIBRARY_PATH="$PB_DIR"
ulimit -n 200000
WORK=$(mktemp -d); trap 'kill $FAKE $PB 2>/dev/null; wait 2>/dev/null; rm -rf $WORK' EXIT
python3 "$HERE/fake_proxies.py" $WORK/log >/dev/null 2>&1 & FAKE=$!
sleep 1
stdbuf -oL "$PBL" --proxy a=socks5://127.0.0.1:19080 --rule "python3*:192.0.2.0/24:*:TCP:PROXY=a" > $WORK/pb.out 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" $WORK/pb.out && break; sleep 0.25; done
rss() { awk '/VmRSS/{print $2}' /proc/$PB/status; }
maps_kb() { "${BPFTOOL:-bpftool}" map show 2>/dev/null | grep -oE 'memlock [0-9]+' | awk '{s+=$2} END{printf "%d", s/1024}'; }
echo "baseline: ProxyBridge RSS=$(( $(rss) / 1024 )) MB  BPF maps=$(maps_kb) KB  threads=$(ls /proc/$PB/task | wc -l)"
CPU0=$(awk '{print $14+$15}' /proc/$PB/stat)
rm -f /tmp/pb_scale_ready /tmp/pb_scale_go
python3 - $N > $WORK/client.out <<'PY' &
import asyncio, sys, time, resource, os
n = int(sys.argv[1])
resource.setrlimit(resource.RLIMIT_NOFILE, (200000, 200000))
async def main():
    t0 = time.time(); conns = []; fails = 0
    sem = asyncio.Semaphore(500)
    async def one(i):
        nonlocal fails
        async with sem:
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection("192.0.2.%d" % (1 + i % 250), 8888), 30)
                w.write(b"x"); await w.drain()
                conns.append((r, w))
            except Exception:
                fails += 1
    await asyncio.gather(*(one(i) for i in range(n)))
    dt = time.time() - t0
    print(f"client: {len(conns)} established, {fails} failed, {dt:.1f}s ({len(conns)/dt:.0f} conn/s)", flush=True)
    open("/tmp/pb_scale_ready", "w").write("1")
    while not os.path.exists("/tmp/pb_scale_go"):
        await asyncio.sleep(0.2)
    for r, w in conns: w.close()
asyncio.run(main())
PY
CL=$!
for _ in $(seq 300); do [ -e /tmp/pb_scale_ready ] && break; sleep 1; done
sleep 2
cat $WORK/client.out
CPU1=$(awk '{print $14+$15}' /proc/$PB/stat)
echo "under load: ProxyBridge RSS=$(( $(rss) / 1024 )) MB  BPF maps=$(maps_kb) KB  threads=$(ls /proc/$PB/task | wc -l)  fds=$(ls /proc/$PB/fd | wc -l)"
echo "ProxyBridge CPU while opening: $(( (CPU1 - CPU0) * 1000 / $(getconf CLK_TCK) )) ms"
echo "kernel socket memory (TCP): $(grep '^TCP:' /proc/net/sockstat)"
touch /tmp/pb_scale_go; wait $CL 2>/dev/null; sleep 3
echo "after close: ProxyBridge RSS=$(( $(rss) / 1024 )) MB  fds=$(ls /proc/$PB/fd | wc -l)"
rm -f /tmp/pb_scale_ready /tmp/pb_scale_go
