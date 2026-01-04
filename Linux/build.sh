#!/bin/bash
set -e

echo "[BUILD] ProxyBridge for Linux (eBPF)"

if ! command -v clang &> /dev/null; then echo "ERROR: clang not found"; exit 1; fi
if ! command -v bpftool &> /dev/null; then echo "ERROR: bpftool not found"; exit 1; fi
if ! command -v gcc &> /dev/null; then echo "ERROR: gcc not found"; exit 1; fi

cd "$(dirname "$0")"

# Generate vmlinux.h if not exists
if [ ! -f src/vmlinux.h ]; then
    echo "[0/3] Generating vmlinux.h..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h
fi

echo "[1/3] Compiling BPF program..."
clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -c src/proxybridge.bpf.c -o build/proxybridge.bpf.o

echo "[2/3] Generating BPF skeleton..."
bpftool gen skeleton build/proxybridge.bpf.o > src/proxybridge.skel.h

echo "[3/3] Compiling userspace..."
gcc -Wall -O2 -Isrc -c src/ProxyBridge.c -o build/ProxyBridge.o
gcc -Wall -O2 -Isrc -c cli/main.c -o build/main.o
gcc build/ProxyBridge.o build/main.o -lbpf -lelf -lz -lpthread -o build/proxybridge

echo "[DONE] Binary: build/proxybridge"
echo "Run: sudo ./build/proxybridge --help"
