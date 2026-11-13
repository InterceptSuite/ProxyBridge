#!/bin/bash
# Programs that live on Btrfs (Fedora's default). Btrfs gives every subvolume its own device number in stat(), different from the file
# system's own, which is what the kernel side records. ProxyBridge used to compare the two, so a program on Btrfs was never recognised:
#   issue 281: UDP datagrams of such a program were dropped by the sender check ("datagram from a process other than the flow's")
#   issue 283: a DIRECT rule did not apply: the program was sent to the local relay instead of straight out
# Builds a Btrfs image on a loop device, runs a small client from it. Skips where Btrfs, loop devices or mkfs.btrfs are missing. Needs root, gcc.
#   sudo Linux/tests/e2e_btrfs.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first (Linux/build.sh) or set PB_DIR"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ ! -S /run/proxybridge/ctl.sock ] || { echo "SKIP: a ProxyBridge service is running here (stop it first: sudo systemctl stop proxybridge)"; exit 0; }
command -v mkfs.btrfs >/dev/null && command -v losetup >/dev/null && command -v ss >/dev/null && command -v gcc >/dev/null || { echo "SKIP: needs mkfs.btrfs, losetup, ss and gcc"; exit 0; }
modprobe btrfs 2>/dev/null; grep -qw btrfs /proc/filesystems || { echo "SKIP: this kernel has no Btrfs"; exit 0; }
WORK="$(mktemp -d)"; MNT="$WORK/mnt"; PASS=0; FAIL=0; PB=""; FAKE=""; LOOP=""
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup() { kill $PB $FAKE 2>/dev/null; sleep 0.5; umount "$MNT" 2>/dev/null; [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
export PB_DIR LD_LIBRARY_PATH="$PB_DIR"
mkdir -p "$MNT"; truncate -s 300M "$WORK/img"
LOOP=$(losetup -f --show "$WORK/img" 2>/dev/null) || { echo "SKIP: no loop device"; exit 0; }
mkfs.btrfs -q "$LOOP" 2>/dev/null && mount "$LOOP" "$MNT" 2>/dev/null || { echo "SKIP: cannot make or mount a Btrfs image here"; exit 0; }
btrfs subvolume create "$MNT/sub" >/dev/null 2>&1 || mkdir -p "$MNT/sub"
btrfs subvolume create "$MNT/other" >/dev/null 2>&1 || mkdir -p "$MNT/other"
gcc -O1 -o "$WORK/client" "$HERE/btrfs_client.c" || { echo "cannot build the client"; exit 1; }
cp "$WORK/client" "$MNT/sub/pbbtrfs"; cp "$WORK/client" "$MNT/other/pbbtrfs2"; install -m 755 "$WORK/client" "$WORK/pbplain"
sdev=$(stat -c '%Hd:%Ld' "$MNT/sub/pbbtrfs"); mdev=$(awk -v m="$MNT" '$5==m {print $3}' /proc/self/mountinfo)
echo "program on $(stat -f -c %T "$MNT/sub/pbbtrfs"): stat() says device $sdev, the mount (file system) is $mdev"
[ "$sdev" != "$mdev" ] && echo "  (they differ here: this run can tell the old behaviour from the fixed one)" || echo "  (they are equal on this kernel: the run cannot tell, but must still pass)"

python3 "$HERE/fake_proxies.py" "$WORK/proxy.log" >/dev/null 2>&1 & FAKE=$!; sleep 1
stdbuf -oL "$HERE/pbl" --verbose 3 --proxy a=socks5://127.0.0.1:19080 \
   --rule "pbbtrfs:192.0.2.77:80:TCP:DIRECT" --rule "pbbtrfs:192.0.2.0/24:*:UDP:PROXY=a" \
   --rule "pbbtrfs2:192.0.2.0/24:*:UDP:PROXY=a" --rule "pbplain:192.0.2.0/24:*:UDP:PROXY=a" > "$WORK/pb.out" 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
grep -q "ProxyBridge started" "$WORK/pb.out" && ok "ProxyBridge started" || { bad "start"; cat "$WORK/pb.out"; }

echo "== UDP through a proxy rule (issue 281)"
out=$("$WORK/pbplain" udp 192.0.2.9 5300);              [[ "$out" == *"UDP-A 192.0.2.9:5300 ping"* ]] && ok "a program on an ordinary file system (control)" || bad "control: '$out'"
for i in 1 2 3; do
  out=$("$MNT/sub/pbbtrfs" udp 192.0.2.9 5300);         [[ "$out" == *"UDP-A 192.0.2.9:5300 ping"* ]] && ok "a program on Btrfs gets its answer ($i of 3)" || bad "Btrfs datagram $i: '$out'"
done
out=$("$MNT/other/pbbtrfs2" udp 192.0.2.9 5300);        [[ "$out" == *"UDP-A 192.0.2.9:5300 ping"* ]] && ok "a program in another subvolume of the same file system" || bad "other subvolume: '$out'"
n=$(grep -c "other than the flow" "$WORK/pb.out");       [ "$n" = 0 ] && ok "no datagram was dropped by the sender check" || bad "$n datagrams dropped as 'from a process other than the flow's'"
n=$(grep -c ' UDP ' "$WORK/proxy.log");                  [ "$n" -ge 5 ] && ok "the proxy received all of them ($n)" || bad "the proxy saw only $n datagrams"

echo "== a DIRECT rule (issue 283)"
for i in 1 2 3; do
  "$MNT/sub/pbbtrfs" tcp 192.0.2.77 80 2500 & CJ=$!; sleep 1
  relay=$(ss -tnp 2>/dev/null | grep pbbtrfs | grep -c ':24010'); straight=$(ss -tnp 2>/dev/null | grep pbbtrfs | grep -c '192.0.2.77:80')
  [ "$relay" = 0 ] && [ "$straight" -ge 1 ] && ok "connection $i goes straight to its destination, not through the relay" || bad "connection $i: to the relay=$relay, straight=$straight"
  wait $CJ 2>/dev/null
done
n=$(grep -c 'direct connect to 192.0.2.77' "$WORK/pb.out"); [ "$n" = 0 ] && ok "the relay never made a connection on the program's behalf" || bad "the relay connected out $n times for a DIRECT program"
echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "---- ProxyBridge output"; tail -20 "$WORK/pb.out"; exit 1; }
