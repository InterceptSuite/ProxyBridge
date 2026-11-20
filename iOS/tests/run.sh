#!/bin/bash
# Builds the router and its logic for the Mac from the real tunnel sources and runs the checks: the unit checks
# first, then the end-to-end checks against local test proxies. No phone, no signing. Needs the Xcode command
# line tools and python3. The end-to-end part also needs ports 1080, 1081 and 8080 free and network access.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../ProxyBridge"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

clang -c "$SRC/Tunnel/SystemDNS.c" -I "$SRC/Tunnel" -o "$TMP/SystemDNS.o"
mkdir "$TMP/main"
cp "$HERE/logic_tests.swift" "$TMP/main/main.swift"
swiftc -o "$TMP/router" -lresolv -import-objc-header "$SRC/Tunnel/Tunnel-Bridging-Header.h" \
    "$TMP/main/main.swift" "$TMP/SystemDNS.o" "$SRC"/Shared/*.swift \
    $(ls "$SRC"/Tunnel/*.swift | grep -v 'HevTunnel\|PacketTunnelProvider') 2>"$TMP/build.log" \
    || { grep -E "error:" "$TMP/build.log" | head; exit 1; }

"$TMP/router"
python3 "$HERE/router_e2e.py" "$TMP/router"
