#!/usr/bin/env python3
import os, sys, time, json, shutil, subprocess, tempfile, signal
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pbd

PB = os.path.join(os.environ["PB_DIR"], "ProxyBridge")
UNIT = "proxybridge-e2e.service"
UNIT_PATH = "/run/systemd/system/" + UNIT
INSTALL = "/opt/pbtest-e2e"
CFG = "/var/lib/pbtest-e2e-cfg"
SOCK = "/run/proxybridge/ctl.sock"
PASS = FAIL = 0
procs = []


def check(name, cond, why=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print("  PASS  " + name, flush=True)
    else:
        FAIL += 1; print("  FAIL  %s %s" % (name, why), flush=True)


def sc(*a):
    return subprocess.run(["systemctl"] + list(a), capture_output=True, text=True)


def wait_sock(gone=False, t=15):
    for _ in range(int(t * 10)):
        if os.path.exists(SOCK) != gone:
            return True
        time.sleep(0.1)
    return False


def curl(url, t=5):
    r = subprocess.run(["curl", "-s", "-m", str(t), url], capture_output=True, text=True)
    return r.stdout


def cleanup():
    sc("stop", UNIT)
    for p in procs:
        p.kill()
    for p in (UNIT_PATH,):
        try: os.unlink(p)
        except OSError: pass
    sc("daemon-reload")
    shutil.rmtree(INSTALL, ignore_errors=True)
    shutil.rmtree(CFG, ignore_errors=True)


try:
    os.makedirs(INSTALL, mode=0o755, exist_ok=True)
    shutil.copy(PB, INSTALL + "/ProxyBridge")
    os.chmod(INSTALL + "/ProxyBridge", 0o755)
    os.makedirs(CFG, mode=0o700, exist_ok=True)
    unit = subprocess.run([INSTALL + "/ProxyBridge", "--print-unit", INSTALL + "/ProxyBridge"], capture_output=True, text=True, check=True).stdout
    check("--print-unit gives a unit that starts the daemon", "ExecStart=\"%s/ProxyBridge\" --daemon" % INSTALL in unit and "[Install]" in unit)
    # the test's own configuration folder instead of /etc/proxybridge; every other line is the installer's
    unit = unit.replace("ReadWritePaths=/etc/proxybridge", "ReadWritePaths=" + CFG).replace("[Service]\n", "[Service]\nEnvironment=PROXYBRIDGE_CONFIG_DIR=%s\n" % CFG)
    open(UNIT_PATH, "w").write(unit)
    r = subprocess.run(["systemd-analyze", "verify", UNIT_PATH], capture_output=True, text=True)
    check("systemd accepts the unit without complaints about its settings", "Unknown" not in r.stderr and "Failed" not in r.stderr, r.stderr[:300])
    sc("daemon-reload")

    fake_log = tempfile.mktemp()
    procs.append(subprocess.Popen([sys.executable, os.path.join(HERE, "fake_proxies.py"), fake_log], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(1)

    print("== start")
    r = sc("start", UNIT)
    check("systemctl start succeeds", r.returncode == 0, r.stderr)
    check("the socket appears in /run/proxybridge (RuntimeDirectory)", wait_sock())
    st = os.stat(os.path.dirname(SOCK)).st_mode & 0o777
    check("the folder is 0755 and the socket reachable by every user", st == 0o755 and os.stat(SOCK).st_mode & 0o777 == 0o666, oct(st))
    check("the unit is active", sc("is-active", UNIT).stdout.strip() == "active")

    d = pbd.Daemon.connect(SOCK)
    st, f = d.req("hello", "1")
    check("a client can talk to it", st == "ok", (st, f))

    print("== the sandbox does not get in the way")
    d.ok("store.put", "svc", json.dumps({"Version": "1.0", "Name": "svc", "ProxyConfigs": [], "ProxyRules": []}))
    check("it can write its configuration folder", os.path.exists(CFG + "/profiles/svc.pbprofile"))
    d.ok("boot.set", "1")
    check("it can write settings.json", os.path.exists(CFG + "/settings.json"))
    pid = int(d.ok("proxy.add", "A", "1", "127.0.0.1", "19080", "", "")[0])
    d.ok("rule.add", "curl", "192.0.2.0/24", "*", "0", "0", str(pid))
    d.ok("engine.start")
    out = curl("http://192.0.2.7/")
    check("it loads the eBPF programs and routes traffic under ProtectSystem=strict and NoNewPrivileges", "hello-from-A dst=192.0.2.7:80" in out, out)
    out = subprocess.run(["systemctl", "show", UNIT, "-p", "MainPID", "--value"], capture_output=True, text=True).stdout.strip()
    mainpid = int(out)
    check("it runs as root", os.stat("/proc/%d" % mainpid).st_uid == 0)
    nofile = [l for l in open("/proc/%d/limits" % mainpid) if l.startswith("Max open files")][0].split()
    check("the raised open-file limit applies (LimitNOFILE)", int(nofile[3]) >= 1048576, nofile)
    status = dict(l.split(":\t") for l in open("/proc/%d/status" % mainpid).read().splitlines() if ":\t" in l)
    check("it cannot gain privileges (NoNewPrivileges)", status.get("NoNewPrivs", "").strip() == "1", status.get("NoNewPrivs"))
    d.close()

    print("== crash and restart")
    os.kill(mainpid, signal.SIGKILL)
    time.sleep(0.5)
    out = curl("http://192.0.2.7/", 3)
    check("when the service dies traffic goes direct at once (fail-open)", "hello-from" not in out, out)
    check("systemd restarts it (Restart=on-failure)", wait_sock(t=20) and sc("is-active", UNIT).stdout.strip() == "active")
    time.sleep(1)
    d = pbd.Daemon.connect(SOCK)
    check("its profiles survived the crash", "svc" in d.ok("store.list"))
    check("and so did the Start at Boot choice", d.ok("boot.get") == ["1"])
    d.close()

    print("== stop")
    r = sc("stop", UNIT)
    check("systemctl stop succeeds quickly", r.returncode == 0)
    check("the socket is removed", wait_sock(gone=True))
    check("the unit is inactive", sc("is-active", UNIT).stdout.strip() == "inactive")
    out = curl("http://192.0.2.7/", 3)
    check("traffic is direct after stop", "hello-from" not in out, out)
finally:
    cleanup()
print("\nPASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
