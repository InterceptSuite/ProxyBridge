#!/usr/bin/env python3
"""Test helper: runs the real command line program from "--proxy / --rule" style arguments.

The program itself takes only --profile, --verbose, --version, --update and --help, like the Windows one. The test suites describe their
set-ups with compact arguments; this script turns them into a .pbprofile (held in an unlinked file) and then execs
`ProxyBridge --profile <that file>`, so the process that runs is the real program and the pid stays the same.

  --proxy [name=]type://[user:pass@]host:port[?dns=local|proxy]     (also type://host:port:user:pass, [ipv6] hosts)
  --rule process:hosts:ports:protocol:action[=proxy][+localhost]    (proxy = name or 1-based index)
  --dns-via-proxy true|false   --log-every-connection true|false   --verbose N
  --profile FILE-OR-NAME       a profile to start from; the other arguments are added to it
  --write FILE                 write the profile to FILE (mode 0600) and exit instead of running the program
PB_DIR selects the build (default: Linux/output).
"""
import json, os, re, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PB_DIR = os.environ.get("PB_DIR", os.path.join(os.path.dirname(HERE), "output"))


def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(1)


def parse_proxy(spec):
    m = re.match(r"^(?:([^=:/]*)=)?([A-Za-z0-9]+)://(.*)$", spec)
    if not m:
        die("bad proxy " + spec)
    name, scheme, rest = m.groups()
    scheme = scheme.lower()
    if scheme not in ("socks5", "http"):
        die("bad proxy type " + scheme)
    dns = True
    if "?" in rest.rsplit("@", 1)[-1]:
        head, _, query = rest.rpartition("?")
        rest = head
        dns = query.lower() != "dns=local"
    user = pw = ""
    if "@" in rest:
        cred, _, rest = rest.rpartition("@")
        user, _, pw = cred.partition(":")
    if rest.startswith("["):
        host, _, tail = rest[1:].partition("]")
        port = tail.lstrip(":").split(":")[0]
    else:
        parts = rest.split(":")
        host, port = parts[0], parts[1] if len(parts) > 1 else ""
        if len(parts) >= 4 and not user:          # legacy host:port:user:pass
            user, pw = parts[2], ":".join(parts[3:])
    return {"Name": name or host, "Type": scheme.upper() if scheme == "socks5" else "HTTP", "Host": host, "Port": port,
            "Username": user, "Password": pw, "SendDomainToProxy": dns}


def parse_rule(spec):
    first = spec.index(":")
    proc, rest = spec[:first], spec[first + 1:]
    head, proto, action = rest.rsplit(":", 2)
    hosts, ports = head.rsplit(":", 1) if head.count(":") else (head, "*")
    localhost = False
    if action.lower().endswith("+localhost"):
        action, localhost = action[:-len("+localhost")], True
    proxy = ""
    if "=" in action:
        action, proxy = action.split("=", 1)
    return {"ProcessName": proc or "*", "TargetHosts": hosts or "*", "TargetPorts": ports or "*", "Protocol": proto.upper(),
            "Action": action.upper(), "IsEnabled": True, "LocalhostViaProxy": localhost, "_proxy": proxy}


def boolean(v):
    return v.lower() in ("1", "true")


def main():
    args = sys.argv[1:]
    prof = {"Version": "1.0", "ProxyConfigs": [], "ProxyRules": []}
    verbose = None
    base = None
    write_to = None
    proxies, rules = [], []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--proxy", "--rule", "--profile", "--verbose", "--dns-via-proxy", "--log-every-connection", "--write") and i + 1 < len(args):
            v = args[i + 1]
            i += 2
            if a == "--proxy": proxies.append(parse_proxy(v))
            elif a == "--rule": rules.append(parse_rule(v))
            elif a == "--profile": base = v
            elif a == "--verbose": verbose = v
            elif a == "--write": write_to = v
            elif a == "--dns-via-proxy": prof["DnsViaProxy"] = boolean(v)
            else: prof["LogEveryConnection"] = boolean(v)
        else:
            die("unsupported by the test helper: " + a)

    if base:
        sys.path.insert(0, HERE)
        path = base
        if "/" not in base and not os.path.exists(base):
            cfg = os.environ.get("PROXYBRIDGE_CONFIG_DIR", "/etc/proxybridge")
            from urllib.parse import quote
            path = os.path.join(cfg, "profiles", quote(base, safe=" ") + ".pbprofile")
        with open(path) as f:
            loaded = json.load(f)
        loaded.update({k: v for k, v in prof.items() if k not in ("ProxyConfigs", "ProxyRules")})
        prof = loaded
        prof.setdefault("ProxyConfigs", []); prof.setdefault("ProxyRules", [])

    next_id = max([c.get("Id", 0) for c in prof["ProxyConfigs"]] + [0]) + 1
    names = []
    for p in proxies:
        p["Id"] = next_id; next_id += 1
        prof["ProxyConfigs"].append(p)
    for c in prof["ProxyConfigs"]:
        names.append((c.get("Name"), c["Id"]))
    for r in rules:
        ref = r.pop("_proxy")
        if ref:
            if ref.isdigit() and 1 <= int(ref) <= len(prof["ProxyConfigs"]):
                r["ProxyConfigId"] = prof["ProxyConfigs"][int(ref) - 1]["Id"]
            else:
                hit = [i for n, i in names if n == ref]
                if not hit:
                    die("rule refers to unknown proxy '%s'" % ref)
                r["ProxyConfigId"] = hit[0]
        prof["ProxyRules"].append(r)

    if write_to:
        fdw = os.open(write_to, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fdw, json.dumps(prof, indent=2).encode())
        os.close(fdw)
        return
    fd, tmp = tempfile.mkstemp(prefix="pbl-", suffix=".pbprofile")
    os.write(fd, json.dumps(prof).encode())
    os.unlink(tmp)                                   # the exec'd program reads it through /proc/self/fd/<fd>
    os.set_inheritable(fd, True)
    cmd = [os.path.join(PB_DIR, "ProxyBridge"), "--profile", "/proc/self/fd/%d" % fd]
    if verbose is not None:
        cmd += ["--verbose", verbose]
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = PB_DIR + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    os.execve(cmd[0], cmd, env)


main()
