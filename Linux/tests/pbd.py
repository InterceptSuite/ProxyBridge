"""Client for the ProxyBridge service protocol (src/pb_ipc.h), used by the tests.

    d = Daemon.connect(path)
    status, fields = d.req("proxy.add", "name", "1", "127.0.0.1", "1080", "", "")
    d.events      # list of ("log", msg) / ("conn", process, pid, ip, port, proto, via)
"""
import socket, struct, threading, queue, itertools


def encode(fields):
    body = struct.pack(">H", len(fields))
    for f in fields:
        b = f if isinstance(f, bytes) else str(f).encode()
        body += struct.pack(">I", len(b)) + b
    return struct.pack(">I", len(body)) + body


def read_frame(sock):
    hdr = b""
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c:
            return None
        hdr += c
    (n,) = struct.unpack(">I", hdr)
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf += c
    (cnt,) = struct.unpack(">H", buf[:2])
    pos, out = 2, []
    for _ in range(cnt):
        (l,) = struct.unpack(">I", buf[pos:pos + 4])
        pos += 4
        out.append(buf[pos:pos + l])
        pos += l
    return out


class Daemon:
    def __init__(self, sock):
        self.sock = sock
        self.ids = itertools.count(1)
        self.events = []
        self.pending = {}
        self.lines = {}
        self.cv = threading.Condition()
        self.dead = False
        self.first = None        # a response with id 0 (refusal) arrives before any request
        threading.Thread(target=self._read, daemon=True).start()

    @classmethod
    def connect(cls, path, timeout=10):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(timeout)
        s.connect(path)
        s.settimeout(None)
        return cls(s)

    def _read(self):
        while True:
            try:
                f = read_frame(self.sock)
            except OSError:
                f = None
            if f is None:
                with self.cv:
                    self.dead = True
                    self.cv.notify_all()
                return
            kind = f[0].decode(errors="replace")
            with self.cv:
                if kind == "e":
                    self.events.append(tuple(x.decode(errors="replace") for x in f[1:]))
                elif kind == "r":
                    rid = f[1].decode()
                    if len(f) > 2 and f[2] == b"line":
                        self.lines.setdefault(rid, []).append(f[3].decode(errors="replace"))
                    else:
                        self.pending[rid] = f[2:]
                self.cv.notify_all()

    def req(self, cmd, *args, timeout=20, raw=False):
        rid = str(next(self.ids))
        try:
            self.sock.sendall(encode([b"q", rid.encode(), cmd.encode()] + [a if isinstance(a, bytes) else str(a).encode() for a in args]))
        except OSError:
            pass                    # the service may already have refused us and closed; its refusal is waiting to be read
        return self._wait(rid, timeout, raw)

    def _wait(self, rid, timeout, raw=False):
        with self.cv:
            if not self.cv.wait_for(lambda: rid in self.pending or self.dead or "0" in self.pending, timeout):
                raise TimeoutError("no answer to request " + rid)
            r = self.pending.pop(rid, None) or self.pending.get("0")
            if r is None:
                raise ConnectionError("connection closed")
        status = r[0].decode()
        return status, (r[1:] if raw else [x.decode(errors="replace") for x in r[1:]])

    def ok(self, cmd, *args, **kw):
        st, f = self.req(cmd, *args, **kw)
        if st != "ok":
            raise AssertionError("%s failed: %s" % (cmd, f))
        return f

    def wait_event(self, pred, timeout=10):
        with self.cv:
            end = [None]

            def check():
                return any(pred(e) for e in self.events) or self.dead
            if not self.cv.wait_for(check, timeout):
                return None
            for e in self.events:
                if pred(e):
                    return e
        return None

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)      # the reader thread is blocked in recv(): close() alone would not end the connection
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
