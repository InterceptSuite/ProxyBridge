#!/bin/bash
# Finds a working bpftool for the CI runners and exports it as BPFTOOL (through $GITHUB_ENV). The build only needs bpftool to generate
# the eBPF skeleton from the running kernel's BTF, so any version that runs will do.
#
# On Ubuntu "bpftool" is not a package of its own: /usr/sbin/bpftool is a wrapper that runs the copy for the running kernel, and that copy
# lives in a folder named after the kernel (/usr/lib/linux-tools/<release>/ or, for HWE and cloud kernels, /usr/lib/linux-*-tools-<release>/).
# A runner image can ship a kernel whose folder has no copy yet, so look in every place, check that the candidate runs, install the
# package for this kernel if none does, and say what is on the machine if that fails too.
#   Linux/ci/find-bpftool.sh            (BPFTOOL_ROOT=/some/root searches under that root: used by the test)
set -u
ROOT="${BPFTOOL_ROOT:-}"

find_working() {
    shopt -s nullglob
    local c
    for c in "$ROOT"/usr/lib/linux-tools/"$(uname -r)"/bpftool "$ROOT"/usr/lib/linux-tools/*/bpftool "$ROOT"/usr/lib/linux-*tools-*/bpftool \
             "$ROOT"/usr/lib/linux-tools-*/bpftool "$ROOT"/usr/local/sbin/bpftool "$ROOT"/usr/sbin/bpftool "$ROOT"/usr/bin/bpftool; do
        if [ -x "$c" ] && [ ! -d "$c" ] && "$c" version >/dev/null 2>&1; then echo "$c"; return 0; fi
    done
    return 1
}

found="$(find_working)"
if [ -z "$found" ] && [ -z "$ROOT" ] && command -v apt-get >/dev/null 2>&1; then
    echo "no working bpftool yet; installing the tools for $(uname -r)"
    sudo apt-get update -qq >/dev/null 2>&1 || true
    for pkg in "linux-tools-$(uname -r)" linux-tools-generic bpftool; do
        sudo apt-get install -y "$pkg" >/dev/null 2>&1 && echo "  installed $pkg" || echo "  could not install $pkg"
        found="$(find_working)" && [ -n "$found" ] && break
    done
fi

if [ -z "$found" ]; then
    echo "ERROR: no working bpftool found. What is on this machine:"
    echo "kernel: $(uname -r)"
    ls -la "$ROOT"/usr/lib/linux-tools 2>&1 | head -20
    ls -d "$ROOT"/usr/lib/linux*tools* 2>&1 | head
    find "$ROOT"/usr "$ROOT"/lib -name 'bpftool*' 2>/dev/null | head -20
    dpkg -l 2>/dev/null | grep -E 'linux-.*tools|bpftool' | awk '{print $1, $2, $3}' | head -20
    exit 1
fi
echo "bpftool: $found"
"$found" version 2>&1 | head -1
[ -n "${GITHUB_ENV:-}" ] && echo "BPFTOOL=$found" >> "$GITHUB_ENV"
exit 0
