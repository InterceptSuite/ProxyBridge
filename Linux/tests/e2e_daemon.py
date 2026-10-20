#!/usr/bin/env python3
"""End-to-end test of the ProxyBridge service. Needs root (it loads the eBPF programs)."""
import os, sys, time, json, socket, struct, subprocess, tempfile, shutil, random, signal, threading, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pbd

PB = os.path.join(os.environ["PB_DIR"], "ProxyBridge")
WORK = tempfile.mkdtemp(prefix="pbdaemon.")
os.chmod(WORK, 0o755)             # the socket folder must be reachable by the unprivileged user of the access tests
CFG = os.path.join(WORK, "cfg")
SOCK = os.path.join(WORK, "run", "ctl.sock")
PASS = FAIL = 0
procs = []


def ok(name):
    global PASS
    PASS += 1
    print("  PASS  " + name, flush=True)


def bad(name, why=""):
    global FAIL
    FAIL += 1
    print("  FAIL  %s %s" % (name, why), flush=True)


def check(name, cond, why=""):
    ok(name) if cond else bad(name, why)


def start_daemon(extra=()):
    env = dict(os.environ, PROXYBRIDGE_CONFIG_DIR=CFG)
    p = subprocess.Popen([PB, "--daemon", "--socket", SOCK, "--verbose", "1"] + list(extra), env=env,
                         stdout=open(os.path.join(WORK, "daemon.out"), "ab"), stderr=subprocess.STDOUT)
    procs.append(p)
    for _ in range(80):
        if os.path.exists(SOCK):
            try:
                pbd.Daemon.connect(SOCK, 2).close()
                return p
            except OSError:
                pass
        if p.poll() is not None:
            break
        time.sleep(0.1)
    raise RuntimeError("daemon did not start: " + open(os.path.join(WORK, "daemon.out")).read())


def stop_daemon(p):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def conn():
    d = pbd.Daemon.connect(SOCK)
    d.ok("hello", "1")
    return d


def curl(url, t=5):
    r = subprocess.run(["curl", "-s", "-m", str(t), url], capture_output=True, text=True)
    return r.returncode, r.stdout


def cleanup():
    for p in procs:
        try:
            p.kill()
        except OSError:
            pass
    shutil.rmtree(WORK, ignore_errors=True)


profile = lambda name, extra="": json.dumps({"Version": "1.0", "Name": name, "ProxyConfigs": [], "ProxyRules": []})

try:
    fake_log = os.path.join(WORK, "fake.log")
    procs.append(subprocess.Popen([sys.executable, os.path.join(HERE, "fake_proxies.py"), fake_log], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1)
    d0 = start_daemon()

    print("== a fresh service is idle")
    d = pbd.Daemon.connect(SOCK)
    st, f = d.req("hello", "1")
    check("with Start at Boot off the engine is not started until a window asks", st == "ok" and f[1] == "0", (st, f))
    check("Start at Boot is off by default", d.ok("boot.get") == ["0"])
    d.close()
    d0.send_signal(signal.SIGTERM); d0.wait(10)
    d0 = start_daemon()

    print("== socket and protocol")
    st = os.stat(SOCK)
    check("socket is reachable by everyone (access is decided by the service)", st.st_mode & 0o777 == 0o666, oct(st.st_mode))
    check("socket folder is 0755", os.stat(os.path.dirname(SOCK)).st_mode & 0o777 == 0o755)
    d = pbd.Daemon.connect(SOCK)
    st, f = d.req("hello", "1")
    check("hello answers with the version", st == "ok" and f[0].startswith("4."), (st, f))
    st, f = d.req("hello", "999")
    check("a different protocol version is refused with a clear message", st == "err" and "protocol mismatch" in f[0], (st, f))
    st, f = d.req("no.such.command")
    check("an unknown command is an error, not a crash", st == "err" and "unknown" in f[0], (st, f))
    st, f = d.req("proxy.add", "only-one-arg")
    check("wrong argument count is an error", st == "err" and "number of arguments" in f[0], (st, f))
    st, f = d.req("proxy.delete", "abc")
    check("a non-numeric id is an error", st == "err", (st, f))
    d.close()

    s = socket.socket(socket.AF_UNIX); s.connect(SOCK)
    s.sendall(struct.pack(">I", 0x7fffffff) + b"junk")
    s.settimeout(3)
    try:
        r = s.recv(10)
    except OSError:
        r = b""
    check("an oversized frame closes the connection", r == b"")
    s.close()
    rnd = random.Random(7)
    for i in range(60):
        s = socket.socket(socket.AF_UNIX); s.connect(SOCK)
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(1, 300)))
        if i % 3 == 0:                      # a valid length header around garbage
            blob = struct.pack(">I", len(blob)) + blob
        try:
            s.sendall(blob)
        except OSError:
            pass
        s.close()
    time.sleep(1)                           # the limit is on windows connected at once; let the storm drain
    d = conn()
    check("the service survives random garbage on 60 connections", d.req("log.history")[0] == "ok")
    d.close()
    d = pbd.Daemon.connect(SOCK)
    d.sock.sendall(pbd.encode([b"q", b"1", b"hello", b"1"])[:7])    # truncated frame, then a vanished peer
    d.close()
    d = conn()
    check("the service survives a truncated frame", True)
    d.close()
    time.sleep(0.3)

    print("== too many windows")
    many = []
    for i in range(16):
        try:
            many.append(conn())
        except Exception as e:
            bad("window %d of 16 is accepted" % (i + 1), e)
            break
    try:
        extra = pbd.Daemon.connect(SOCK)
        st, f = extra.req("hello", "1")
        check("the 17th connection is refused", st == "err" and "too many" in f[0], (st, f))
        extra.close()
    except Exception as e:
        check("the 17th connection is refused", False, e)
    for m in many: m.close()
    time.sleep(0.5)
    d = conn(); check("slots are free again after they disconnect", True); d.close()

    print("== access control")
    code = (
        "import os,sys,socket\nsys.path.insert(0,%r)\nimport pbd\nos.setgid(65534);os.setgroups([]);os.setuid(65534)\n"
        "d=pbd.Daemon.connect(%r)\nst,f=d.req('hello','1')\nprint(st,f[0] if f else '')\n" % (HERE, SOCK))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    check("an ordinary user is refused", r.stdout.startswith("err") and "not allowed" in r.stdout, r.stdout + r.stderr)
    made_group = subprocess.run(["getent", "group", "proxybridge"], capture_output=True).returncode != 0
    if made_group:
        subprocess.run(["groupadd", "-r", "proxybridge"], check=True)
    try:
        subprocess.run(["usermod", "-aG", "proxybridge", "nobody"], check=True)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        check("a member of the group 'proxybridge' is accepted at once, without logging in again", r.stdout.startswith("ok"), r.stdout + r.stderr)
        subprocess.run(["gpasswd", "-d", "nobody", "proxybridge"], capture_output=True)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        check("removed from the group, the user is refused again", r.stdout.startswith("err"), r.stdout + r.stderr)
    finally:
        subprocess.run(["gpasswd", "-d", "nobody", "proxybridge"], capture_output=True)
        if made_group:
            subprocess.run(["groupdel", "proxybridge"], capture_output=True)
    d = conn(); check("root is always accepted", True); d.close()

    print("== profile store")
    d = conn()
    check("an empty store lists no profiles", d.ok("store.list") == [])
    st, f = d.req("store.put", "bad", "this is not json")
    check("a file that is not a profile is rejected", st == "err", (st, f))
    st, f = d.req("store.put", "bad", '{"ProxyConfigs":[{"Type":"SOCKS5","Host":"h","Port":"70000"}]}')
    check("a profile with a bad port is rejected", st == "err", (st, f))
    st, f = d.req("store.put", "big", "x" * (5 << 20))
    check("a profile over 4 MiB is rejected", st == "err", (st, f)[:2])
    d.ok("store.put", "Work", profile("Work"))
    d.ok("store.put", "Test/lab", profile("Test/lab"))
    check("profiles are listed, sorted, with their real names", d.ok("store.list") == sorted(["Work", "Test/lab"]), d.ok("store.list"))
    got = d.ok("store.get", "Test/lab")[0]
    check("a profile reads back unchanged", json.loads(got)["Name"] == "Test/lab")
    mode = os.stat(os.path.join(CFG, "profiles", "Test%2Flab.pbprofile")).st_mode & 0o777
    check("profile files are private (0600) and a slash in a name is encoded", mode == 0o600, oct(mode))
    check("the config folder is private (0700)", os.stat(CFG).st_mode & 0o777 == 0o700)
    st, f = d.req("store.get", "../../etc/passwd")
    check("a path in a profile name cannot escape the folder", st == "err" and not os.path.exists(os.path.join(CFG, "..", "..", "etc")), (st, f))
    st, f = d.req("store.get", "nosuch")
    check("an unknown profile is an error", st == "err")
    d.ok("store.delete", "Work")
    check("a deleted profile is gone", d.ok("store.list") == ["Test/lab"])
    d.ok("store.delete", "Work")
    check("deleting twice is harmless", True)
    d.ok("store.settings.set", "Test/lab", "0", "1")
    check("settings round-trip", d.ok("store.settings.get") == ["Test/lab", "0", "1"], d.ok("store.settings.get"))
    d.ok("store.settings.set", "", "1", "0")
    d.ok("store.delete", "Test/lab")
    for i in range(520):
        st, f = d.req("store.put", "p%03d" % i, profile("p"))
        if st == "err":
            break
    check("the number of profiles is bounded", st == "err" and "too many" in f[0] and i <= 512, (i, st, f))
    for i in range(520):
        d.req("store.delete", "p%03d" % i)
    d.close()

    print("== engine: proxies, rules, traffic")
    d = conn()
    pid_a = int(d.ok("proxy.add", "fakeA", "1", "127.0.0.1", "19080", "", "")[0])
    pid_b = int(d.ok("proxy.add", "fakeB", "1", "127.0.0.1", "19081", "bob", "pw")[0])
    check("proxy ids are returned", pid_a > 0 and pid_b > 0 and pid_a != pid_b)
    st, f = d.req("proxy.add", "x", "1", "", "1080", "", "")
    check("an empty proxy host is refused", st == "err", (st, f))
    rid = int(d.ok("rule.add", "curl", "192.0.2.0/24", "*", "0", "0", str(pid_a))[0])
    rid2 = int(d.ok("rule.add", "curl", "198.51.100.0/24", "80;8080", "0", "0", str(pid_b))[0])
    st, f = d.req("rule.add", "curl", "999.1.1.1", "*", "0", "0", str(pid_a))
    check("a bad address is refused with the reason", st == "err" and f[0], (st, f))
    check("rule.validate accepts a good rule", d.req("rule.validate", "curl", "10.0.0.0/8", "80")[0] == "ok")
    check("rule.validate refuses a bad port", d.req("rule.validate", "curl", "*", "99999")[0] == "err")
    d.ok("cfg.logging", "1")
    d.ok("engine.start")
    rc, out = curl("http://192.0.2.7/")
    check("a rule routes curl through proxy A", "hello-from-A dst=192.0.2.7:80" in out, (rc, out))
    rc, out = curl("http://198.51.100.7:8080/")
    check("another rule routes through proxy B (with login)", "hello-from-B dst=198.51.100.7:8080" in out, (rc, out))
    ev = d.wait_event(lambda e: e[0] == "conn" and e[1] == "curl" and e[4] == "80", 5)
    check("connection events reach the window", ev is not None, d.events[-5:])
    check("the event carries process, pid, address, port, protocol and route", ev and ev[2].isdigit() and ev[3] == "192.0.2.7" and ev[5] == "TCP" and "SOCKS5" in ev[6], ev)
    d.ok("rule.disable", str(rid))
    rc, out = curl("http://192.0.2.7/", 3)
    check("a disabled rule stops routing", "hello-from" not in out, (rc, out))
    d.ok("rule.enable", str(rid))
    rc, out = curl("http://192.0.2.7/")
    check("re-enabling routes again", "hello-from-A" in out, (rc, out))
    d.ok("rule.edit", str(rid), "curl", "192.0.2.0/24", "*", "0", "0", str(pid_b))
    rc, out = curl("http://192.0.2.7/")
    check("editing a rule changes its proxy", "hello-from-B" in out, (rc, out))
    d.ok("rule.move", str(rid2), "0")
    d.ok("rule.delete", str(rid))
    rc, out = curl("http://192.0.2.7/", 3)
    check("a deleted rule stops routing", "hello-from" not in out, (rc, out))
    rid3 = int(d.ok("rule.add", "curl", "203.0.113.0/24", "*", "0", "2", "0")[0])
    rc, out = curl("http://203.0.113.5/", 3)
    check("a Block rule refuses the connection", rc == 7 or "hello-from" not in out, (rc, out))
    d.ok("rule.delete", str(rid3))

    print("== live connections")
    d.ok("rule.add", "python3*", "192.0.2.0/24", "8888", "0", "0", str(pid_a))
    hold = socket.create_connection(("192.0.2.9", 8888), timeout=5)
    hold.sendall(b"x")
    time.sleep(1.5)
    flows = d.ok("flows.get")
    mine = [f.split("\t") for f in flows if f.split("\t")[1] == str(os.getpid())]
    check("an open proxied connection is listed with its process, port and proxy", len(mine) == 1 and mine[0][6] == "8888" and mine[0][2] == str(pid_a), flows)
    hold.sendall(b"y" * 5000); time.sleep(1.2)
    again = [f.split("\t") for f in d.ok("flows.get") if f.split("\t")[1] == str(os.getpid())]
    check("bytes sent are counted", again and int(again[0][4]) >= 5000, again)
    hold.close()
    time.sleep(1.5)
    after = [f for f in d.ok("flows.get") if f.split("\t")[1] == str(os.getpid())]
    check("a closed connection leaves the list", not after, after)

    print("== batch")
    d2 = conn()
    d2.ok("batch.begin")
    nid = int(d2.ok("rule.add", "curl", "192.0.2.0/24", "*", "0", "0", str(pid_a))[0])
    rc, out = curl("http://192.0.2.7/", 3)
    check("inside a batch a change does not reach the kernel yet", "hello-from" not in out, (rc, out))
    d2.ok("batch.end")
    rc, out = curl("http://192.0.2.7/")
    check("when the batch ends the whole change arrives at once", "hello-from-A" in out, (rc, out))
    d2.ok("rule.delete", str(nid))
    d2.ok("batch.begin")
    nid = int(d2.ok("rule.add", "curl", "192.0.2.0/24", "*", "0", "0", str(pid_a))[0])
    d2.close()                                   # the window dies in the middle of a batch
    time.sleep(1)
    rc, out = curl("http://192.0.2.7/")
    check("a window that vanishes mid-batch does not leave the update held back", "hello-from-A" in out, (rc, out))
    d.ok("rule.delete", str(nid))

    print("== proxy test over the service")
    st, f = d.req("proxy.test", str(pid_a), "example.com", "80", raw=False)
    lines = d.lines.get(str(d.ids and (next(iter([k for k in d.lines])) )), [])
    allines = [l for ls in d.lines.values() for l in ls]
    check("the proxy test streams its report and returns a result", st == "ok" and any("Connecting to the proxy" in l for l in allines) and f[0] in ("0",), (st, f, allines[:3]))

    print("== switches")
    check("DNS via proxy switch", d.req("cfg.dns", "0")[0] == "ok" and d.req("cfg.dns", "1")[0] == "ok")
    check("log every connection switch", d.req("cfg.logEvery", "1")[0] == "ok")
    check("enable switch pauses the rules", d.req("cfg.enabled", "0")[0] == "ok")
    rc, out = curl("http://198.51.100.7:8080/", 3)
    check("while paused nothing is routed", "hello-from" not in out, (rc, out))
    d.ok("cfg.enabled", "1")
    rc, out = curl("http://198.51.100.7:8080/")
    check("after resuming the rules apply again", "hello-from-B" in out, (rc, out))
    check("a bad boolean is refused", d.req("cfg.dns", "yes")[0] == "err")
    d.ok("engine.stop")
    rc, out = curl("http://198.51.100.7:8080/", 3)
    check("with the engine stopped traffic is direct (fail-open)", "hello-from" not in out, (rc, out))
    d.ok("engine.start")
    rc, out = curl("http://198.51.100.7:8080/")
    check("the engine starts again with the same rules", "hello-from-B" in out, (rc, out))
    h = d.ok("log.history")
    check("the service keeps its recent log lines for windows that connect later", any("started" in l for l in h), h[-3:])
    d.close()

    print("== the service applies the active profile by itself at start")
    stop_daemon(d0)
    check("the socket is removed on a clean stop", not os.path.exists(SOCK))
    rc, out = curl("http://198.51.100.7:8080/", 3)
    check("after the service stops, traffic is direct", "hello-from" not in out, (rc, out))
    prof = {"Version": "1.0", "Name": "boot", "DnsViaProxy": True,
            "ProxyConfigs": [{"Id": 1, "Name": "A", "Type": "SOCKS5", "Host": "127.0.0.1", "Port": "19080", "Username": "", "Password": "", "SendDomainToProxy": True}],
            "ProxyRules": [{"Name": "r", "ProcessName": "curl", "TargetHosts": "192.0.2.0/24", "TargetPorts": "*", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": True, "ProxyConfigId": 1},
                           {"Name": "off", "ProcessName": "curl", "TargetHosts": "203.0.113.0/24", "TargetPorts": "*", "Protocol": "TCP", "Action": "PROXY", "IsEnabled": False, "ProxyConfigId": 1}]}
    os.makedirs(os.path.join(CFG, "profiles"), exist_ok=True)
    with open(os.path.join(CFG, "profiles", "boot.pbprofile"), "w") as fh:
        json.dump(prof, fh)
    os.chmod(os.path.join(CFG, "profiles", "boot.pbprofile"), 0o600)
    with open(os.path.join(CFG, "settings.json"), "w") as fh:
        json.dump({"ActiveProfileName": "boot", "CheckForUpdatesOnStartup": True, "StartAtBoot": True}, fh)
    d1 = start_daemon()
    time.sleep(1)
    rc, out = curl("http://192.0.2.7/")
    check("with no window open, the active profile is already routing", "hello-from-A dst=192.0.2.7:80" in out, (rc, out, open(os.path.join(WORK, "daemon.out")).read()[-600:]))
    rc, out = curl("http://203.0.113.5/", 3)
    check("a disabled rule of that profile is not applied", "hello-from" not in out, (rc, out))
    d = conn()
    h = d.ok("log.history")
    check("a window that connects later can read what the service did at boot", any("profile 'boot' loaded" in l for l in h), h)
    d.close()
    stop_daemon(d1)

    print("== a broken active profile does not stop the service")
    with open(os.path.join(CFG, "profiles", "boot.pbprofile"), "w") as fh:
        fh.write("{ not json")
    d1 = start_daemon()
    d = conn()
    check("the service stays up and answers", d.req("log.history")[0] == "ok")
    check("it says why in its log", any("cannot be loaded" in l for l in d.ok("log.history")))
    d.close()
    stop_daemon(d1)

    print("== Start at Boot is a setting of the service")
    with open(os.path.join(CFG, "profiles", "boot.pbprofile"), "w") as fh:
        json.dump(prof, fh)
    d1 = start_daemon()
    d = conn()
    d.ok("boot.set", "0")
    check("boot.set stores the choice and boot.get reads it", d.ok("boot.get") == ["0"] and json.load(open(os.path.join(CFG, "settings.json")))["StartAtBoot"] is False)
    check("the active profile name is kept when only the boot switch changes", json.load(open(os.path.join(CFG, "settings.json")))["ActiveProfileName"] == "boot")
    d.close()
    stop_daemon(d1)
    d1 = start_daemon()
    time.sleep(1)
    rc, out = curl("http://192.0.2.7/", 3)
    check("with Start at Boot off the service does not route by itself", "hello-from" not in out, (rc, out))
    d = conn()
    st, f = d.req("hello", "1")
    check("and its engine is not running", f[1] == "0", f)
    d.ok("boot.set", "1")
    check("turned on", d.ok("boot.get") == ["1"])
    d.close()
    stop_daemon(d1)
    d1 = start_daemon()
    time.sleep(1)
    rc, out = curl("http://192.0.2.7/")
    check("with Start at Boot on it routes at once after a restart", "hello-from-A" in out, (rc, out))
    d = conn()
    check("and reports its engine as running", d.req("hello", "1")[1][1] == "1")
    d.close()
    stop_daemon(d1)

    print("== the daemon refuses to run as a normal user and rejects --profile")
    r = subprocess.run([PB, "--daemon", "--profile", "x"], capture_output=True, text=True)
    check("--daemon with --profile is refused", r.returncode == 1 and "does not take --profile" in r.stderr, r.stderr)
finally:
    cleanup()
print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
