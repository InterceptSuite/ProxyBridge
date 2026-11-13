#!/bin/bash
# deploy.sh picks the archive for the machine's architecture and the digest GitHub reports for it, with and without jq.
# Nothing is downloaded or installed (PB_SELECT_ONLY=1 reads a saved API answer).   tests/deploy_select_test.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$HERE/../deploy.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

P=https://github.com/InterceptSuite/ProxyBridge/releases/download/v9.9.9
asset() { # name digest
    printf '    {\n      "name": "%s",\n      "size": 1,\n      "digest": "sha256:%s",\n      "download_count": 0,\n      "browser_download_url": "%s/%s"\n    }' "$1" "$2" "$P" "$1"
}
{
    echo '{ "assets": ['
    asset ProxyBridge-Linux-arm64-v9.9.9.tar.gz aaaa; echo ','
    asset ProxyBridge-Linux-v9.9.9.tar.gz bbbb; echo ','
    asset ProxyBridge-Windows-v9.9.9.zip cccc
    echo '] }'
} > "$W/api.json"
{
    echo '{ "assets": ['
    asset ProxyBridge-Windows-v9.9.9.zip cccc; echo ','
    asset ProxyBridge-Linux-v9.9.9.tar.gz bbbb
    echo '] }'
} > "$W/api_x86_only.json"

# a PATH without jq: links to every tool the script needs
mkdir "$W/nojq"
for t in bash sh awk sed grep head cat uname sha256sum curl tar mktemp basename tr chmod rm; do
    p="$(command -v "$t" 2>/dev/null)" && ln -s "$p" "$W/nojq/$t"
done

sel() { # arch json [nojq]
    local path="$PATH"; [ "${3:-}" = nojq ] && path="$W/nojq"
    PATH="$path" PB_SELECT_ONLY=1 PB_ARCH="$1" PB_API_JSON="$2" bash "$DEPLOY" 2>&1
}
for mode in jq nojq; do
    [ "$mode" = jq ] && ! command -v jq >/dev/null && { echo "  skip  jq is not installed"; continue; }
    m=""; [ "$mode" = nojq ] && m=nojq
    echo "== $mode"
    out="$(sel x86_64 "$W/api.json" $m)"
    eq "x86_64 takes the plain archive" "$(grep '^url=' <<<"$out")" "url=$P/ProxyBridge-Linux-v9.9.9.tar.gz"
    eq "x86_64 gets its own digest" "$(grep '^digest=' <<<"$out")" "digest=sha256:bbbb"
    out="$(sel aarch64 "$W/api.json" $m)"
    eq "aarch64 takes the arm64 archive" "$(grep '^url=' <<<"$out")" "url=$P/ProxyBridge-Linux-arm64-v9.9.9.tar.gz"
    eq "aarch64 gets its own digest" "$(grep '^digest=' <<<"$out")" "digest=sha256:aaaa"
    out="$(sel arm64 "$W/api.json" $m)"
    eq "arm64 is the same as aarch64" "$(grep '^url=' <<<"$out")" "url=$P/ProxyBridge-Linux-arm64-v9.9.9.tar.gz"
    out="$(sel aarch64 "$W/api_x86_only.json" $m)"
    eq "no arm64 archive in the release: an error, never the x86_64 one" "$(grep -c 'ERROR: Could not find' <<<"$out")" "1"
    out="$(sel x86_64 "$W/api_x86_only.json" $m)"
    eq "x86_64 release without arm64 still works" "$(grep '^url=' <<<"$out")" "url=$P/ProxyBridge-Linux-v9.9.9.tar.gz"
done
echo "== other machines"
out="$(sel riscv64 "$W/api.json")"
eq "an unsupported machine is refused" "$(grep -c 'built for x86_64 and arm64' <<<"$out")" "1"

echo
if [ "$fails" = 0 ]; then echo "deploy select test: all passed"; else echo "deploy select test: $fails failed"; fi
[ "$fails" = 0 ]
