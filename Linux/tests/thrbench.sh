#!/bin/bash
# Throughput through ProxyBridge vs the same application speaking SOCKS5 itself. Needs root.
#   sudo tests/thrbench.sh <thrbench-binary>   (binary must be named thrbench so process rules can match it)
TB=${1:?path to thrbench binary named "thrbench"}; ROOT="$(dirname "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")"
export LD_LIBRARY_PATH="$ROOT/src"
MB=${MB:-2048}
$TB sink 19990 & SINK=$!; $TB proxy 19991 19990 & PROXY=$!
trap 'kill $SINK $PROXY $PB 2>/dev/null' EXIT
sleep 0.5
echo "== baselines (ProxyBridge not running)"
for i in 1 2 3; do $TB direct 127.0.0.1 19990 $MB 1; done
for i in 1 2 3; do $TB socks 19991 192.0.2.7 9999 $MB 1; done
for i in 1 2; do $TB socks 19991 192.0.2.7 9999 $((MB/8)) 8; done
stdbuf -oL "$ROOT/cli/ProxyBridge" --proxy a=socks5://127.0.0.1:19991 --rule "thrbench:192.0.2.0/24:*:TCP:PROXY=a" > /tmp/thr_pb.out 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" /tmp/thr_pb.out && break; sleep 0.25; done
echo "== through ProxyBridge (app connects to 192.0.2.7:9999, transparently redirected)"
for i in 1 2 3; do $TB direct 192.0.2.7 9999 $MB 1; done
for i in 1 2; do $TB direct 192.0.2.7 9999 $((MB/8)) 8; done
echo "== direct traffic while ProxyBridge is running (127.0.0.1 is never redirected; non-matching process)"
for i in 1 2 3; do $TB direct 127.0.0.1 19990 $MB 1; done
kill -INT $PB; wait $PB 2>/dev/null
