#!/bin/bash
# Interoperability with a REAL third-party SOCKS5 server: OpenSSH's `ssh -D`. Needs root, sshd, ssh, curl, python3.
#   sudo tests/e2e_openssh.sh
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ROOT="$(dirname "$HERE")"
PB_DIR="${PB_DIR:-$ROOT/output}"   # directory holding the built ProxyBridge + libproxybridge.so (run ../build.sh first)
[ -x "$PB_DIR/ProxyBridge" ] && [ -f "$PB_DIR/libproxybridge.so" ] || { echo "Build first: (cd Linux && ./build.sh), or set PB_DIR to a directory containing ProxyBridge and libproxybridge.so"; exit 1; }
HERE="${HERE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"; PBL="$HERE/pbl"; export PB_DIR   # starts the real program from compact --proxy/--rule arguments (see pbl.py)
WORK="$(mktemp -d)"; PASS=0; FAIL=0; ORIGIN=10.77.0.5
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup() { kill $SSHD $SSH $WWW $PB 2>/dev/null; wait 2>/dev/null; ip addr del $ORIGIN/32 dev lo 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
export LD_LIBRARY_PATH="$PB_DIR"
command -v sshd >/dev/null && command -v ssh >/dev/null || { echo "SKIP: openssh not installed"; exit 0; }
ip addr add $ORIGIN/32 dev lo 2>/dev/null

ssh-keygen -q -t ed25519 -N '' -f "$WORK/hostkey"; ssh-keygen -q -t ed25519 -N '' -f "$WORK/clientkey"
cp "$WORK/clientkey.pub" "$WORK/authorized_keys"; chmod 600 "$WORK/authorized_keys"
cat > "$WORK/sshd_config" <<CFG
Port 22222
ListenAddress 127.0.0.1
HostKey $WORK/hostkey
AuthorizedKeysFile $WORK/authorized_keys
PermitRootLogin yes
PasswordAuthentication no
UsePAM no
PidFile $WORK/sshd.pid
StrictModes no
AllowTcpForwarding yes
LogLevel VERBOSE
CFG
mkdir -p /run/sshd
/usr/sbin/sshd -D -e -f "$WORK/sshd_config" 2> "$WORK/sshd.log" & SSHD=$!
sleep 1
ssh -N -D 127.0.0.1:19090 -p 22222 -i "$WORK/clientkey" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes root@127.0.0.1 2> "$WORK/ssh.log" & SSH=$!
for _ in $(seq 30); do ss -ltn 2>/dev/null | grep -q ":19090" && break; sleep 0.3; done
ss -ltn | grep -q ":19090" && ok "OpenSSH SOCKS5 server is up (ssh -D 19090)" || { bad "ssh -D did not start: $(tail -3 $WORK/ssh.log)"; exit 1; }

# a real origin on a non-loopback local address, serving a 40MB file and a small page
head -c 41943040 /dev/urandom > "$WORK/big.bin"; echo "real-origin-page" > "$WORK/index.html"
python3 -m http.server 18500 --bind $ORIGIN --directory "$WORK" >/dev/null 2>&1 & WWW=$!
sleep 1
SUM=$(sha256sum "$WORK/big.bin" | cut -d' ' -f1)

stdbuf -oL "$PBL" --verbose 1 --proxy ossh=socks5://127.0.0.1:19090 \
   --rule "curl:$ORIGIN:18500:TCP:PROXY=ossh" > "$WORK/pb.out" 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done

out=$(curl -s -m 8 http://$ORIGIN:18500/index.html)
[[ "$out" == *real-origin-page* ]] && ok "small request through OpenSSH's SOCKS5 server" || bad "small request (got: ${out:0:100})"
GOT=$(curl -s -m 60 http://$ORIGIN:18500/big.bin | sha256sum | cut -d' ' -f1)
[ "$GOT" = "$SUM" ] && ok "40 MB download through OpenSSH SOCKS5: checksum identical" || bad "40MB checksum mismatch"
pids=(); for i in $(seq 40); do curl -s -m 20 http://$ORIGIN:18500/index.html > "$WORK/c$i.out" & pids+=($!); done; wait "${pids[@]}" 2>/dev/null
n=$(grep -l real-origin-page "$WORK"/c*.out 2>/dev/null | wc -l); [ "$n" = 40 ] && ok "40 parallel connections through OpenSSH SOCKS5" || bad "only $n/40 parallel requests succeeded"
# upload (client -> origin) integrity
python3 - "$WORK" <<'PY' &
import http.server, socketserver, sys, hashlib, threading
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers["Content-Length"]); h = hashlib.sha256(); left = n
        while left:
            b = self.rfile.read(min(65536, left)); h.update(b); left -= len(b)
        body = h.hexdigest().encode(); self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("10.77.0.5", 18501), H).serve_forever()
PY
UP=$!; sleep 1
kill -INT $PB; wait $PB 2>/dev/null
stdbuf -oL "$PBL" --proxy ossh=socks5://127.0.0.1:19090 --rule "curl:$ORIGIN:18500-18501:TCP:PROXY=ossh" > "$WORK/pb.out" 2>&1 & PB=$!
for _ in $(seq 40); do grep -q "ProxyBridge started" "$WORK/pb.out" && break; sleep 0.25; done
GOT=$(curl -s -m 60 --data-binary @"$WORK/big.bin" http://$ORIGIN:18501/ )
[ "$GOT" = "$SUM" ] && ok "40 MB upload through OpenSSH SOCKS5: origin received identical bytes" || bad "upload checksum mismatch (got ${GOT:0:20})"
kill $UP 2>/dev/null
# negative control: with the SSH proxy gone, the redirected request must FAIL (it would succeed if it bypassed the proxy)
kill $SSH 2>/dev/null; sleep 1
out=$(curl -s -m 4 http://$ORIGIN:18500/index.html 2>&1; echo "rc=$?")
[[ "$out" != *real-origin-page* ]] && ok "negative control: with the proxy killed the request fails, so it really went through the proxy" || bad "request succeeded without the proxy: traffic bypassed it"
echo; echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ] || { echo "--- pb"; tail -15 "$WORK/pb.out"; echo "--- sshd"; tail -10 "$WORK/sshd.log"; exit 1; }
