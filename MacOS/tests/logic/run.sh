#!/bin/bash
# Compiles each logic test against the real extension sources and runs it. No installed extension or
# network needed, this is what could run on a hosted CI runner. Needs the Xcode command line tools.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT="$HERE/../../ProxyBridge/extension"
APP="$HERE/../../ProxyBridge/ProxyBridge"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run_test() {   # <test file> <extension sources...>
    local test="$1"; shift
    cp "$HERE/$test" "$TMP/main.swift"
    swiftc -o "$TMP/test" "$@" "$TMP/main.swift" -framework NetworkExtension 2>"$TMP/build.log" \
        || { echo "build failed for $test"; grep -E "error:" "$TMP/build.log" | head; exit 1; }
    "$TMP/test"
}

run_test matcher_tests.swift "$EXT/AppProxyProvider.swift" "$EXT/DNSMapStore.swift"
run_test dnsmap_tests.swift "$EXT/DNSMapStore.swift"
run_test cli_tests.swift "$APP/CLIArguments.swift" "$APP/CLIProfile.swift" "$APP/CLIText.swift"
