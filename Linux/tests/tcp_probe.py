#!/usr/bin/env python3
"""Client for the fault tests: connects to <ip>:<port> (ProxyBridge redirects it) and prints one RESULT line.

usage: tcp_probe.py <ip> <port> <mode> [timeout_s]
  get      send a GET, read until the end        RESULT DATA <n> <first bytes> | CLOSED | ERROR <errno> | TIMEOUT
  pattern  read until the end, compare with the 4 MiB pattern of fault_proxies.py        RESULT PATTERN ok|bad <n>
  echo     send 2 MiB while reading the echo back, compare                               RESULT ECHO ok|bad <n>
"""
import os, random, socket, sys, threading

ip, port, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 15.0
PATTERN = bytes((i * 7 + 3) & 0xFF for i in range(65536))

s = socket.socket()
s.settimeout(timeout)
try:
    s.connect((ip, port))
except socket.timeout:
    print("RESULT TIMEOUT connect"); sys.exit(0)
except OSError as e:
    print("RESULT ERROR", e.errno, "connect"); sys.exit(0)

def read_all():
    got = b""
    try:
        while True:
            d = s.recv(1 << 16)
            if not d:
                return got, "eof"
            got += d
    except socket.timeout:
        return got, "timeout"
    except OSError as e:
        return got, "error%d" % e.errno

if mode == "get":
    try:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    except OSError:
        pass
    got, end = read_all()
    if got:
        print("RESULT DATA", len(got), got[:140].replace(b"\r", b"").replace(b"\n", b"|").decode("latin1"))
    elif end == "timeout":
        print("RESULT TIMEOUT read")
    else:
        print("RESULT CLOSED", end)
elif mode == "pattern":
    got, end = read_all()
    expect = (PATTERN * 64)[: 4 << 20]
    print("RESULT PATTERN", "ok" if got == expect else "bad", len(got), end)
elif mode == "echo":
    data = random.Random(7).randbytes(2 << 20)
    def writer():
        try:
            for i in range(0, len(data), 65536):
                s.sendall(data[i:i + 65536])
        except OSError:
            pass
    t = threading.Thread(target=writer); t.start()
    got = b""
    try:
        while len(got) < len(data):
            d = s.recv(1 << 16)
            if not d:
                break
            got += d
    except OSError:
        pass
    t.join(timeout)
    print("RESULT ECHO", "ok" if got == data else "bad", len(got))
