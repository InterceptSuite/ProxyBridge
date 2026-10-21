#!/bin/bash
# Audits the built binaries: portability (glibc floor, no libbpf dependency) and hardening.
#   tests/check_binaries.sh [dir]        MAX_GLIBC=2.34 (default) is the highest glibc symbol version allowed
set -u
DIR="${1:-$(dirname "$(dirname "${BASH_SOURCE[0]}")")/output}"
MAX_GLIBC="${MAX_GLIBC:-2.34}"
fails=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

audit() { # file kind(lib|exe) allowed-NEEDED-regex
    local f="$DIR/$1" kind="$2" needed_ok="$3"
    [ -f "$f" ] || { [ "$1" = ProxyBridgeGUI ] && { echo "== $1 (not built)"; return; }; bad "$1 is missing"; return; }
    echo "== $1"
    local hdr prog dyn syms need
    hdr=$(readelf -h "$f"); prog=$(readelf -lW "$f"); dyn=$(readelf -d "$f"); syms=$(nm -D "$f" 2>/dev/null)
    if [ "$kind" = exe ]; then check "position independent executable" 'grep -q "Position-Independent" <<<"$hdr"'
    else check "shared object" 'grep -q "DYN" <<<"$hdr"'; fi
    check "full RELRO (GNU_RELRO + BIND_NOW)" 'grep -q GNU_RELRO <<<"$prog" && grep -q -E "BIND_NOW|FLAGS.*NOW" <<<"$dyn"'
    check "non-executable stack" 'grep GNU_STACK <<<"$prog" | grep -vq "RWE"'
    check "no writable+executable segments" '! grep -E "LOAD" <<<"$prog" | grep -q "RWE"'
    check "no text relocations" '! grep -q TEXTREL <<<"$dyn"'
    check "stack protector in use" 'grep -q __stack_chk_fail <<<"$syms"'
    check "fortified libc calls in use" 'grep -q "_chk" <<<"$syms"'
    if [ "$(uname -m)" = x86_64 ]; then check "CET (IBT + SHSTK) marked" 'readelf -n "$f" | grep -q IBT && readelf -n "$f" | grep -q SHSTK'; fi
    need=$(grep NEEDED <<<"$dyn" | sed 's/.*\[\(.*\)\]/\1/' | tr '\n' ' ')
    check "dependencies are only portable libraries ($need)" '! tr " " "\n" <<<"$need" | grep -v "^$" | grep -q -v -E "$needed_ok"'
    local top
    top=$(objdump -T "$f" 2>/dev/null | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
    check "needs glibc ${top:-none} (limit $MAX_GLIBC, see issue #146)" '[ -z "$top" ] || [ "$(printf "%s\n%s\n" "$top" "$MAX_GLIBC" | sort -V | tail -1)" = "$MAX_GLIBC" ]'
    if [ -n "$top" ] && [ "$(printf '%s\n%s\n' "$top" "$MAX_GLIBC" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then
        objdump -T "$f" | grep -E "GLIBC_(2\.(3[5-9]|[4-9][0-9])|[3-9])" | awk '{print "          "$NF" "$(NF-1)}' | head -5
    fi
}

LIBBPF_DEP=''; [ "${ALLOW_DYNAMIC_LIBBPF:-0}" = 1 ] && LIBBPF_DEP='|libbpf\.so\.1'
# libbpf, libelf and zlib are linked in: the library and the command line program depend on glibc alone
audit libproxybridge.so lib "^(libc\.so\.6|libm\.so\.6|ld-linux.*$LIBBPF_DEP)\$"
exports=$(nm -D --defined-only "$DIR/libproxybridge.so" 2>/dev/null | awk '$2=="T"{print $3}' | grep -v '^ProxyBridge_' | tr '\n' ' ')
check "library exports only the ProxyBridge_* API${exports:+ (also: $exports)}" '[ -z "$exports" ]'
if [ "${ALLOW_DYNAMIC_LIBBPF:-0}" = 1 ]; then CLI_DEP='|libproxybridge\.so|libbpf\.so\.1|libelf\.so\.1|libz\.so\.1'; else CLI_DEP=''; fi
audit ProxyBridge exe "^(libc\.so\.6|libpthread\.so\.0|libm\.so\.6|ld-linux.*$CLI_DEP)\$"
audit ProxyBridgeGUI exe '^(libc\.so\.6|libproxybridge\.so|libpthread\.so\.0|libm\.so\.6|libgtk-3\.so\.0|libgdk-3\.so\.0|libglib-2\.0\.so\.0|libgobject-2\.0\.so\.0|libgio-2\.0\.so\.0|libcairo\.so\.2|libgdk_pixbuf-2\.0\.so\.0|libpango-1\.0\.so\.0|libpangocairo-1\.0\.so\.0|libatk-1\.0\.so\.0|ld-linux.*)$'

echo
if [ "$fails" = 0 ]; then echo "binary audit: all checks passed"; else echo "binary audit: $fails check(s) failed"; fi
[ "$fails" = 0 ]
