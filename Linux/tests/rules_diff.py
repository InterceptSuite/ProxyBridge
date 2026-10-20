#!/usr/bin/env python3
"""Differential test of the rule engine against the live datapath.

For several seeds: generate a random rule set (single IPs, CIDR, ranges, octet wildcards, long host lists, port lists and many port
ranges, TCP/UDP/BOTH, PROXY/DIRECT/BLOCK, matching and non-matching process names), start ProxyBridge with it, make this process
connect() to hundreds of random destinations over TCP and UDP, and compare the decision ProxyBridge reports for each one with an
independent reference evaluation written here. The kernel fast path and the user-space slow path (long lists and many ranges
cannot be decided in the kernel) are both exercised. Needs root.

usage: rules_diff.py <PB_DIR> [seeds] [probes_per_proto]
"""
import ipaddress, os, random, re, signal, socket, subprocess, sys, time

PB_DIR = sys.argv[1]
SEEDS = int(sys.argv[2]) if len(sys.argv) > 2 else 8
PROBES = int(sys.argv[3]) if len(sys.argv) > 3 else 300
PROXY = "a=socks5://127.0.0.1:19080"

# 198.18.0.0/15 is the benchmarking range; the wrapper script routes it to "unreachable" so direct connects fail at once
OCT = {1: [18, 19], 2: [0, 1, 2, 3], 3: [0, 1, 2, 5, 100, 254, 255]}
PORTS = [1, 22, 80, 81, 443, 1000, 1500, 2000, 5000, 8080, 9000, 65535, 20, 25, 110, 143]


def rand_ip(rng):
    return "198.%d.%d.%d" % (rng.choice(OCT[1]), rng.choice(OCT[2]), rng.choice(OCT[3]))


def ip_int(s):
    return int(ipaddress.IPv4Address(s))


class Host:
    """One host pattern: text for the CLI and a predicate for the reference."""
    def __init__(self, rng):
        kind = rng.choice(["any", "ip", "ip", "cidr", "cidr", "range", "wild", "wild2"])
        a = rand_ip(rng)
        if kind == "any":
            self.text, self.fn = "*", lambda ip: True
        elif kind == "ip":
            self.text, self.fn = a, lambda ip, v=ip_int(a): ip == v
        elif kind == "cidr":
            net = ipaddress.ip_network("%s/%d" % (a, rng.choice([15, 16, 20, 24, 28, 32])), strict=False)
            self.text, self.fn = str(net), lambda ip, n=net: ipaddress.IPv4Address(ip) in n
        elif kind == "range":
            b = rand_ip(rng)
            lo, hi = sorted((ip_int(a), ip_int(b)))
            self.text = "%s-%s" % (ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi))
            self.fn = lambda ip, lo=lo, hi=hi: lo <= ip <= hi
        elif kind == "wild":
            o = a.split(".")
            k = rng.choice([1, 2, 3])
            self.text = ".".join(o[:4 - k] + ["*"] * k)
            self.fn = lambda ip, o=o, k=k: [(ip >> s) & 255 for s in (24, 16, 8, 0)][:4 - k] == [int(x) for x in o[:4 - k]]
        else:   # per-octet range such as 10.1-2.*.5
            o = a.split(".")
            lo = 18; hi = rng.choice([18, 19])
            self.text = "%s.%d-%d.*.%s" % (o[0], lo, hi, o[3])
            self.fn = lambda ip, o=o, lo=lo, hi=hi: (ip >> 24) == int(o[0]) and lo <= ((ip >> 16) & 255) <= hi and (ip & 255) == int(o[3])


class Rule:
    def __init__(self, rng):
        n = rng.choice([1, 1, 1, 2, 3, 6, 7])           # more than 4 address ranges do not fit in the kernel: slow path
        self.hosts = [Host(rng) for _ in range(n)]
        pk = rng.choice(["any", "one", "list", "range", "many"])
        if pk == "any":
            self.ports_text, self.ports = "*", None
        elif pk == "one":
            p = rng.choice(PORTS); self.ports_text, self.ports = str(p), [(p, p)]
        elif pk == "list":
            ps = rng.sample(PORTS, rng.choice([2, 3, 4])); self.ports_text, self.ports = ";".join(map(str, ps)), [(p, p) for p in ps]
        elif pk == "range":
            lo = rng.choice([1, 20, 1000, 5000]); hi = lo + rng.choice([0, 100, 5000, 60000]); hi = min(hi, 65535)
            self.ports_text, self.ports = "%d-%d" % (lo, hi), [(lo, hi)]
        else:                                           # more port ranges than the kernel stores
            rs = []; t = 1
            for _ in range(rng.choice([5, 6])):
                lo = t + rng.choice([0, 3]); hi = lo + rng.choice([0, 10, 400]); rs.append((lo, hi)); t = hi + 40
            self.ports_text, self.ports = ";".join("%d-%d" % r for r in rs), rs
        self.proto = rng.choice(["TCP", "UDP", "BOTH", "BOTH"])
        self.proc = rng.choice(["python3*", "python3*", "python3*", "*", "nomatch*"])
        self.action = rng.choices(["PROXY", "DIRECT", "BLOCK"], [45, 25, 30])[0]

    def cli(self):
        return "%s:%s:%s:%s:%s" % (self.proc, ";".join(h.text for h in self.hosts), self.ports_text, self.proto,
                                   "PROXY=a" if self.action == "PROXY" else self.action)

    def matches(self, ip, port, proto):
        if self.proc == "nomatch*" or self.proto not in (proto, "BOTH"):
            return False
        if self.ports is not None and not any(lo <= port <= hi for lo, hi in self.ports):
            return False
        return any(h.fn(ip) for h in self.hosts)


def expected(rules, ip, port, proto):
    for r in rules:
        if r.matches(ip_int(ip), port, proto):
            return r.action
    return "DIRECT"


def probes(rng, n):
    seen, out = set(), []
    while len(out) < n:
        k = (rand_ip(rng), rng.choice(PORTS + [rng.randint(1024, 65000)]))
        if k not in seen:
            seen.add(k); out.append(k)
    return out


def connect(proto, ip, port, keep):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "TCP" else socket.SOCK_DGRAM)
    if proto == "UDP":
        keep.append(s)              # open until the batch has been read: a closed socket's port could be taken by another process
    try:
        if proto == "TCP":
            s.setblocking(False)
            err = s.connect_ex((ip, port))
            return None if err in (0, 115) else err
        s.connect((ip, port))
        try:
            s.send(b"x")            # a decision the kernel cannot make alone is reported when the relay sees the first datagram
        except OSError:
            pass                    # unreachable destinations: the send fails after the decision was made
    except OSError as e:
        return e.errno
    finally:
        if proto != "UDP":
            s.close()
    return None


def run_seed(seed):
    rng = random.Random(seed)
    rules = [Rule(rng) for _ in range(rng.choice([8, 12, 16, 24]))]
    env = dict(os.environ, LD_LIBRARY_PATH=PB_DIR, PB_DIR=PB_DIR)
    args = ["stdbuf", "-oL", os.path.join(os.path.dirname(os.path.abspath(__file__)), "pbl"), "--verbose", "2", "--proxy", PROXY]
    for r in rules:
        args += ["--rule", r.cli()]
    out = open("/tmp/rules_diff.%d.out" % os.getpid(), "w+")
    pb = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT, env=env)
    try:
        for _ in range(80):
            out.seek(0)
            if "ProxyBridge started" in out.read(): break
            if pb.poll() is not None: break
            time.sleep(0.25)
        out.seek(0)
        text = out.read()
        if "ProxyBridge started" not in text:
            print("seed %d: ProxyBridge did not start:\n%s" % (seed, text[-1500:])); return 0, 1
        time.sleep(0.5)
        bad = total = 0
        for proto in ("TCP", "UDP"):
            batch = probes(rng, PROBES)
            out.seek(0, 2); start = out.tell()
            errs, keep = {}, []
            for ip, port in batch:
                errs[(ip, port)] = connect(proto, ip, port, keep)
            time.sleep(1.0)
            out.seek(start)
            seen = {}
            for line in out:
                m = re.search(r"\[CONN\] .*\(PID:%d\) -> ([0-9.]+):(\d+) via (.*)" % os.getpid(), line)
                if not m: continue
                info = re.sub(r" \(UDP\)$", "", m.group(3).strip())     # UDP flows carry a "(UDP)" marker
                act = "BLOCK" if info == "BLOCK" else "DIRECT" if info == "DIRECT" else "PROXY"
                seen.setdefault((m.group(1), int(m.group(2))), set()).add(act)
            for k in keep:
                k.close()
            for ip, port in batch:
                total += 1
                want = expected(rules, ip, port, proto)
                got = seen.get((ip, port), set())
                ok = got == {want}          # a BLOCK decided in the slow path closes the connection after connect(), so errno is not compared
                if not ok:
                    bad += 1
                    if bad <= 5:
                        print("seed %d MISMATCH %s %s:%d want %s got %s errno %s" % (seed, proto, ip, port, want, sorted(got), errs[(ip, port)]))
        if bad:
            print("seed %d rule set:" % seed)
            for i, r in enumerate(rules): print("   %2d %s" % (i + 1, r.cli()))
        return total, bad
    finally:
        pb.send_signal(signal.SIGINT)
        try: pb.wait(10)
        except subprocess.TimeoutExpired: pb.kill()
        out.close(); os.unlink(out.name)


tot = bad = 0
for seed in range(int(os.environ.get("SEED_START", 1)), int(os.environ.get("SEED_START", 1)) + SEEDS):
    t, b = run_seed(seed)
    tot += t; bad += b
    print("seed %d: %d decisions, %d mismatches" % (seed, t, b), flush=True)
print("RESULT %d decisions compared, %d mismatches" % (tot, bad))
sys.exit(1 if bad else 0)
