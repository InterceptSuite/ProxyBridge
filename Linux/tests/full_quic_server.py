#!/usr/bin/env python3
"""A UDP server that speaks the first step of QUIC (RFC 9000 section 17.2.1, Version Negotiation), for the end-to-end tests.

A real QUIC stack answers a long-header packet that carries a version it does not know with a Version Negotiation packet. That is
a genuine QUIC exchange (first datagram >= 1200 bytes, long header, connection ids, a reply that mirrors them), so it exercises
UDP the way HTTP/3 does without needing a TLS stack. Packets that are not QUIC long headers are answered with "NOTQUIC" + the
first 8 bytes so the client can tell the server saw them.

usage: full_quic_server.py <ip> [<ip> ...]      (listens on UDP port 4433 (QUIC) and 4434 (datagram counter) of each address)
"""
import os, socket, struct, sys, threading, time

SUPPORTED = (1,)


def version_negotiation(pkt):
    # long header: 1 byte flags, 4 bytes version, dcid len + dcid, scid len + scid
    if len(pkt) < 7 or not pkt[0] & 0x80:
        return None
    version = struct.unpack("!I", pkt[1:5])[0]
    if version == 0 or version in SUPPORTED:
        return None
    dl = pkt[5]
    if len(pkt) < 6 + dl + 1:
        return None
    dcid = pkt[6:6 + dl]
    sl = pkt[6 + dl]
    scid = pkt[7 + dl:7 + dl + sl]
    if len(scid) != sl:
        return None
    # the reply mirrors the connection ids: its DCID is the client's SCID and its SCID is the client's DCID
    out = bytes([0x80 | (os.urandom(1)[0] & 0x7F)]) + struct.pack("!I", 0)
    out += bytes([len(scid)]) + scid + bytes([len(dcid)]) + dcid
    for v in SUPPORTED:
        out += struct.pack("!I", v)
    return out


def counter(ip):
    """UDP port 4434: counts datagrams "FF:<tag>:<n>" per tag and answers "COUNT:<tag>" with the number received. Lets a test
    prove that datagrams of senders that closed their socket right after sending still arrived."""
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    c.bind((ip, 4434))
    counts = {}

    def loop():
        while True:
            d, a = c.recvfrom(2000)
            if d.startswith(b"FF:"):
                tag = d.split(b":", 2)[1]
                counts[tag] = counts.get(tag, 0) + 1
            elif d.startswith(b"COUNT:"):
                try:
                    c.sendto(str(counts.get(d[6:], 0)).encode(), a)
                except OSError:
                    pass
    threading.Thread(target=loop, daemon=True).start()


def serve(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((ip, 4433))

    def loop():
        while True:
            d, a = s.recvfrom(70000)
            r = version_negotiation(d) or (b"NOTQUIC" + d[:8])
            try:
                s.sendto(r, a)
            except OSError:
                pass
    threading.Thread(target=loop, daemon=True).start()


for ip in sys.argv[1:]:
    serve(ip)
    counter(ip)
print("quic servers up", flush=True)
while True:
    time.sleep(3600)
