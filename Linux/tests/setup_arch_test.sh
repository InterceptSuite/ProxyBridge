#!/bin/bash
# setup.sh refuses programs built for the other architecture (ELF e_machine) instead of installing them.   tests/setup_arch_test.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }

# the function under test, taken from setup.sh itself
sed -n '/^check_architecture() {/,/^}/p' "$HERE/../setup.sh" > "$W/fn.sh"
[ -s "$W/fn.sh" ] || { bad "check_architecture not found in setup.sh"; exit 1; }

elf() { # e_machine byte -> file with a minimal ELF header
    printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00' > "$2"
    printf "\\x$1\\x00" >> "$2"
}
run() { # machine of the host (as uname -m prints it), machine byte of the program -> output and status
    mkdir -p "$W/d"; elf "$2" "$W/d/ProxyBridge"
    mkdir -p "$W/bin"; printf '#!/bin/sh\necho %s\n' "$1" > "$W/bin/uname"; chmod +x "$W/bin/uname"
    PATH="$W/bin:$PATH" SCRIPT_DIR="$W/d" bash -c ". '$W/fn.sh'; check_architecture"
}

out="$(run x86_64 3e)";  [ $? = 0 ] && [ -z "$out" ] && ok "x86_64 program on an x86_64 machine" || bad "x86_64 on x86_64: $out"
out="$(run aarch64 b7)"; [ $? = 0 ] && [ -z "$out" ] && ok "arm64 program on an arm64 machine" || bad "arm64 on arm64: $out"
out="$(run aarch64 3e)"; st=$?
[ $st != 0 ] && grep -q 'these programs are for x86_64, this machine is aarch64' <<<"$out" && ok "x86_64 program on an arm64 machine is refused" || bad "x86_64 on arm64 ($st): $out"
out="$(run x86_64 b7)"; st=$?
[ $st != 0 ] && grep -q 'these programs are for aarch64, this machine is x86_64' <<<"$out" && ok "arm64 program on an x86_64 machine is refused" || bad "arm64 on x86_64 ($st): $out"
grep -q 'ProxyBridge-Linux-arm64-v' <<<"$out" && ok "the message names the archive to download" || bad "no download hint: $out"
out="$(run riscv64 3e)"; st=$?
[ $st != 0 ] && ok "an unsupported machine is refused" || bad "riscv64 accepted: $out"

echo
if [ "$fails" = 0 ]; then echo "setup arch test: all passed"; else echo "setup arch test: $fails failed"; fi
[ "$fails" = 0 ]
