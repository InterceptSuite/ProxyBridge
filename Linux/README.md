# ProxyBridge for Linux

Universal proxy client for Linux applications - Route any application through SOCKS5/HTTP proxies.

## Table of Contents

- [Installation](#installation)
  - [Quick Install (Recommended)](#quick-install-recommended)
  - [Manual Installation](#manual-installation)
- [Usage](#usage)
  - [GUI Application](#gui-application)
  - [Command Line Interface (CLI)](#command-line-interface-cli)
    - [Basic Usage](#basic-usage)
    - [Command Line Options](#command-line-options)
    - [Rule Format](#rule-format)
  - [Profiles](#profiles)
- [Use Cases](#use-cases)
- [Current Limitations](#current-limitations)
- [Things to Note](#things-to-note)
- [How It Works](#how-it-works)
- [Build from Source](#build-from-source)
- [Uninstallation](#uninstallation)
- [License](#license)

## Installation

### Quick Install (Recommended)

**One-command automatic installation:**

```bash
curl -Lo deploy.sh https://raw.githubusercontent.com/InterceptSuite/ProxyBridge/refs/heads/master/Linux/deploy.sh && sudo bash deploy.sh
```

This script will:
- Download the latest release from GitHub into a private temporary directory and check its SHA-256 against the `.sha256` file of the release (it stops if they differ, or if the release has none, unless run as `sudo env PB_ALLOW_UNVERIFIED=1 bash deploy.sh`)
- Refuse an archive with absolute paths or `..`
- Run the archive's own `setup.sh`, which does the rest (so there is one installer): detect your distribution, install GTK3 if the GUI is included and it is missing, copy the programs and library, create the group and the service, update the library cache and verify
- `sudo env PB_NO_GROUP_USER=1 ./setup.sh` keeps the installer from adding the invoking user to the group `proxybridge`

**Supported distributions:**
- Debian/Ubuntu/Mint/Pop!_OS/Elementary/Zorin/Kali/Raspbian
- Fedora
- RHEL/CentOS/Rocky/AlmaLinux
- Arch/Manjaro/EndeavourOS/Garuda
- openSUSE/SLES
- Void Linux

### Manual Installation

**From GitHub Releases:**

1. Download the latest `ProxyBridge-Linux-vX.X.X.tar.gz` from the [Releases](https://github.com/InterceptSuite/ProxyBridge/releases) page
2. Extract the archive:
   ```bash
   tar -xzf ProxyBridge-Linux-vX.X.X.tar.gz
   cd ProxyBridge-Linux-vX.X.X
   ```
3. Run the setup script with root privileges:
   ```bash
   sudo ./setup.sh
   ```

The setup script will:
- Install GTK3 if the GUI is included and it is missing (the command line program is a single self-contained file)
- Copy binaries to `/usr/local/bin` (ProxyBridge CLI and GUI)
- Copy library to `/usr/local/lib` (libproxybridge.so)
- Update library cache
- Create the group `proxybridge`, add the user who ran `sudo` to it, and install, enable and start `proxybridge.service` (the root part of ProxyBridge, see [The service](#the-service-and-the-window))
- Verify installation

**What gets installed:**
- `/usr/local/bin/ProxyBridge` - Command-line interface, and the service (`ProxyBridge --daemon`)
- `/usr/local/bin/ProxyBridgeGUI` - Graphical interface (if GTK3 available); **it needs no root**
- `/usr/local/lib/libproxybridge.so` - Core library
- `/etc/systemd/system/proxybridge.service` - The service
- `/etc/proxybridge/` - Configuration directory (profiles and settings, root only)

### The service and the window

Loading eBPF programs needs root, but the window does not. ProxyBridge is split like the Windows app (a service plus a window):

- **`proxybridge.service`** (`ProxyBridge --daemon`, runs as root) owns the engine, the profile files and the settings. It listens on `/run/proxybridge/ctl.sock`.
- **`ProxyBridgeGUI`** runs as you. Everything it does (add a proxy, edit a rule, switch profile, start the engine, read the live connections and the logs) is a request to the service over that socket; its file choosers, browser and clipboard are your own.
- **Who may use the service:** root and the members of the group `proxybridge`. The group is read at every connection, so `sudo usermod -aG proxybridge <user>` takes effect at once, without logging in again. Everyone else is refused (and the refusal is logged). The socket is owned by root and the window refuses to talk to a socket whose owner is not root.
- **Start at Boot** (Settings menu) is a setting of the service. *On:* the service applies the active profile when the machine starts and keeps routing after the window is closed. *Off* (default): the service sits idle until a window opens, and closing the window stops routing, as it always did.
- A window started as **root without a service** (for example on a system without systemd) still works: it runs the engine inside itself, like before. `sudo ProxyBridge --profile <name>` is unchanged and stays the way to run headless without the service.
- If the service restarts (an update, a crash), the window reconnects by itself and sends its configuration again.
- Lines the service wrote before the window connected (what it loaded at boot) are shown in the Activity Logs.

## Usage

### GUI Application

**Launch GUI (requires GTK3 and the service, which the installer sets up):**

```bash
ProxyBridgeGUI              # as yourself; no sudo
```

The GTK3-based GUI provides:
- Proxy configuration (SOCKS5/HTTP with authentication)
- Visual rule management with process selection
- Font zoom, auto-clear logs, connection-log filters, *Start at Boot* and an update check on startup (see [Appearance, logs and start-up](#appearance-logs-and-start-up))
- The same four menus as the Windows app: **Proxy** (Enable ProxyBridge, Proxy Settings, Proxy Rules, Log Filters, and the Linux-only Start/Stop Engine and Exit), **Profile**, **Settings** (traffic logging, start at boot, auto-clear, log every connection, update check on startup, zoom) and **Help** (Documentation, Check for Updates, About)
- Real-time connection monitoring (UDP flows are marked `(UDP)`), a **Live Connections** tab (every proxied TCP connection and UDP flow with its process, destination, proxy, age and bytes), a *Log Every Connection* switch in the Settings menu and the *Enable ProxyBridge* switch in the Proxy menu
- Profiles: create, switch, duplicate, rename, delete, **import and export** `.pbprofile` files (the Windows/macOS format, see [Profiles](#profiles))
- Import/Export rules (JSON format compatible with Windows/macOS)
- DNS via proxy is chosen per proxy in the proxy settings (no global switch), like the Windows app
- One *Action* choice per rule: Direct, Block, or one of your proxies; the rule list shows `Proxy: <name>`


### Command Line Interface (CLI)

The CLI takes the same options as the Windows CLI. Everything else (proxies, rules, DNS via proxy, connection-log setting) lives in a **profile**, which you build in the GUI (or write by hand) and run with `--profile`.

```
sudo ProxyBridge --profile work                          # a profile saved by the GUI (the Profile menu)
sudo ProxyBridge --profile ./myconfig.pbprofile --verbose 2   # any .pbprofile, e.g. exported from the Windows or macOS app
ProxyBridge --update                                     # look for a newer version (no root)
```

#### Command Line Options

```
  --profile <path>     Path to a .pbprofile file, or the name of a profile saved by the GUI
  --verbose <0-3>      Logging verbosity: 0 silent (default), 1 log messages, 2 connections, 3 both
  --version            Show the version
  -?, -h, --help       Show help
  --update             Check for a newer version and exit (needs no root; nothing is downloaded or run)
```

`--profile` is required to start the engine, which needs root and a Linux kernel >= 5.11 with BTF and cgroup v2. A profile must contain at least one enabled rule, and a rule that uses a proxy needs a proxy in the profile; otherwise the CLI says so and exits with status 1. Press `Ctrl+C` to stop; the kernel hooks are removed automatically, even if ProxyBridge crashes.

Update check: the feed is `https://download.interceptsuite.com/proxybridge.json`; only `https` links from it are shown. The GUI can check on start-up (Settings).

#### Rule Format

Rules are the `ProxyRules` of the profile (the GUI Rules dialog edits the same fields). A rule has:

- **ProcessName** - Name or path glob(s): `curl`, `curl;wget;firefox`, `fire*`, `*chrome*`, `/usr/bin/*`, or `*`. Matched against the executable's file name and full path, case-sensitive
- **TargetHosts** - `*`, IPv4/IPv6 addresses, CIDR (`10.0.0.0/8`, `2001:db8::/32`), ranges (`10.10.1.1-10.10.255.255`), octet patterns (`192.168.*.*`, `10.1-5.*.*`), **domain names** (`github.com`, `*.github.com`, `api?.example.org`), or a list mixing any of these separated by `;` or `,`. A plain domain matches exactly that name; use `*.` for subdomains. See [Domain rules](#domain-rules)
- **TargetPorts** - `*`, `443`, `80;443;8080`, `80-8000`, or `80;443;8000-9000`
- **Protocol** - `TCP`, `UDP`, or `BOTH`
- **Action** - `PROXY`, `DIRECT`, or `BLOCK`; a `PROXY` rule uses the proxy named by `ProxyConfigId` (`0`: the default proxy)
- **LocalhostViaProxy** - also proxy this application's localhost traffic (e.g. to intercept it in a local proxy tool)

Rules are evaluated **in order and the first match wins** (put specific rules before general ones).

**Notes:**
- Process names are case-sensitive on Linux
- Interpreted programs (python, node, java) are identified by the interpreter binary, e.g. `python3.12`
- A `PROXY` rule whose proxy does not exist is treated as `BLOCK` (traffic never leaks around a missing proxy)
- A local proxy is never proxied through itself: processes that listen on a configured proxy address (for example Burp, mitmproxy, Tor or `ssh -D` on 127.0.0.1) are exempted automatically, so a rule with process `*` cannot create a loop. The exemption is per process, not per program, and is refreshed every two seconds
- Press `Ctrl+C` to stop ProxyBridge; the kernel hooks are removed automatically, even if ProxyBridge crashes

### Profiles

A profile is a named set of proxies and rules. The GUI keeps any number of them, in a **Profile** menu of its own like the Windows app (New, Duplicate, Rename, Delete, **Import**, **Export**, and **Switch Profile** with the active profile checked); every item works on the active profile at once, with no list dialog, and the CLI runs one with `--profile`.
Profiles are stored in the **same `.pbprofile` JSON format as the Windows and macOS apps**, so a file exported on one platform imports on the others:

```bash
sudo ProxyBridge --profile work                    # a profile saved by the GUI
sudo ProxyBridge --profile ~/exported.pbprofile    # any .pbprofile file, e.g. exported from the Windows GUI
```

```json
{
  "Version": "1.0",
  "Name": "work",
  "IsTrafficLoggingEnabled": true,
  "DnsViaProxy": true,
  "DefaultProxyId": 1,
  "ProxyConfigs": [
    { "Id": 1, "Name": "corp", "Type": "SOCKS5", "Host": "proxy.corp", "Port": "1080", "Username": "", "Password": "", "SendDomainToProxy": true },
    { "Id": 2, "Name": "web",  "Type": "HTTP",   "Host": "10.0.0.2",   "Port": "8080", "Username": "bob", "Password": "secret" }
  ],
  "ProxyRules": [
    { "Name": "Browsers", "ProcessName": "firefox;chrome", "TargetHosts": "*", "TargetPorts": "80;443", "TargetDomains": "*.github.com",
      "Protocol": "TCP", "Action": "PROXY", "IsEnabled": true, "ProxyConfigId": 2, "LocalhostViaProxy": false }
  ]
}
```

- Rules point at proxies by `ProxyConfigId`; `0` means the default proxy (`DefaultProxyId`, otherwise the first proxy). A rule that names a proxy that is not in the file makes the profile invalid, rather than silently routing somewhere else.
- Linux keeps domain names in the host list. On export they are written to `TargetDomains` (as the Windows app does) and merged back on import.
- Fields this version has no use for (`LogFilters`, ...) are ignored on import. `DnsViaProxy` and `DefaultProxyId` are Linux additions that other apps ignore. `LogEveryConnection` is the same per-profile setting as in the Windows app. `Name` (proxies and rules), `SendDomainToProxy` (per proxy, default `true`) and `LocalhostViaProxy` (per rule, default `false`) mean the same as in the Windows app; a top-level `LocalhostViaProxy` from older profiles is the default for rules that have none of their own. The CLI takes DNS-via-proxy and the connection-log setting from the profile, and uses `--verbose` instead of the logging flag.
- Disabled rules (`"IsEnabled": false`) are kept in the GUI and skipped by the CLI.
- **GUI storage:** `/etc/proxybridge/profiles/<name>.pbprofile` (one file per profile) and `/etc/proxybridge/settings.json`, which holds only the name of the active profile. Everything else, including the *Enable Traffic Logging* switch, is saved inside the profile, so switching profiles switches those too. The directory is `0700` and the files `0600`, because they hold proxy passwords; exported files are `0600` as well, and the CLI warns when a profile with credentials is readable by others. The `config.ini` of earlier versions is converted on the first start and kept as `config.ini.bak`.
- Files are limited to 4 MiB, 256 proxies and 4096 rules; malformed files are rejected with the reason, never partly applied.

## Domain rules

Applications resolve a name themselves and then connect to an IP address, so the kernel only ever sees the address. To apply domain rules ProxyBridge builds, like the macOS version, an **IP → domain-name map from the DNS answers the application received**:

1. When at least one enabled rule contains a domain pattern, the DNS traffic (UDP and TCP, port 53) of every process covered by such a rule is routed through ProxyBridge's relay, which forwards it to the original resolver unchanged (directly, or through a proxy if your rules say so) and reads the answers.
2. A and CNAME records are recorded (`www.shop.test -> cdn.edge.net -> 198.51.100.7` makes the address match rules for **either** name). The mapping is installed in the kernel **before** the answer is delivered to the application, so even the very first connection already matches.
3. Names are also loaded from `/etc/hosts` at start.
4. The map is bounded (32,768 addresses, oldest evicted first). It has no TTL: an address keeps its names until it is evicted, so applications that cache DNS answers keep matching.

Cost: DNS from covered processes takes one extra loopback hop (about +90 µs per query measured on a loopback test server); processes not covered by any domain rule are not touched at all.

**What domain rules cannot match** (the application never reveals the name to the system):
- DNS-over-HTTPS / DNS-over-TLS (Firefox "Secure DNS", Chrome "Secure DNS", systemd-resolved with DoT): the answers are encrypted. Turn them off in the application or use IP rules
- Addresses that are hard-coded or taken from a config file instead of being resolved
- IPv6 destinations (`AAAA` records are not mapped yet)
- Shared hosting: if two names share one IP, whichever name was resolved last matches; a rule for the other name matches too

## Options shared with the Windows and macOS apps

- **Names.** Every proxy and every rule can carry a name (the GUI shows it, profiles store it).
- **DNS via proxy, per proxy** (*SendDomainToProxy*, on by default, like Windows and macOS). When a connection goes to an address whose name the application resolved, the proxy is asked for the *name* (SOCKS5 domain address, or `CONNECT host:port`), so the proxy does the resolving. Off sends the IP address (`?dns=local` on the command line). The name comes from the application's own unencrypted DNS answers (the DNS tap that already powers domain rules; DoH/DoT bypass it), the most recent lookup for that address wins, and without a known name the IP is sent. UDP datagrams always carry the IP. Names are checked before they reach a proxy, so a hostile DNS answer cannot inject anything into a request. Whether DNS queries themselves follow your rules is not a menu switch any more: DNS (port 53) follows the rules like other traffic (the profile field `DnsViaProxy`, default `true`, still controls it; the CLI honours it).
- **Also proxy localhost traffic, per rule** (*LocalhostViaProxy*, off by default, PROXY rules only). Without it a PROXY rule leaves connections to this computer (`127.0.0.0/8`, `::1`) direct, as on Windows, which is usually what you want. With it, matching loopback TCP and UDP connections go to the proxy, for example to inspect a local application in an intercepting proxy. First match still wins: a PROXY rule without the option stops the walk and the connection stays local. Differences from Windows: BLOCK and DIRECT rules never touch loopback, and DNS to a local resolver (port 53, e.g. `127.0.0.53`) is never proxied, so a broad rule cannot break name resolution.

## Connection log, live connections and the main switch

- **Connection log.** By default a connection is listed once per application, destination, port, protocol and action, so a program that opens 50 connections to one server gets one line. *Log Every Connection* (the per-profile setting) lists every new TCP connection and every new UDP flow instead; a UDP flow is listed again after 30 seconds of silence. Each decision appears exactly once, whether the kernel or the relay made it.
- **Live Connections** (GUI tab, `ProxyBridge_GetFlows()` in the library): the TCP connections and UDP flows being relayed through a proxy right now, newest first, with process, PID, destination (the name the application resolved when known), proxy, age and payload bytes in each direction. Direct and blocked traffic never reaches the relay and is not listed.
- **Enable ProxyBridge** (Proxy menu, `ProxyBridge_SetEnabled()`): the main switch. Off pauses every rule for *new* connections; connections already relayed keep running.
- **Testing a proxy.** The Test button in the proxy settings runs five steps: reach the proxy, open a tunnel and log in, load a page (port 80), time three more tunnels, and probe UDP ASSOCIATE. Only the first two decide success; a page, latency or UDP problem is a warning. The exit code is 0 only when every configured proxy works.

## Appearance, logs and start-up

- **Font zoom** (Settings menu, `Ctrl` + `+` / `-` / `0`): 60-300 % in steps of 10, saved in the profile (`FontZoom`).
- **Auto-clear Logs** (Settings menu, on by default, saved in the profile as `AutoClearConnectionLogs`): a log is wiped once it grows past 500 lines. Switched off, each log keeps its recent history (1000 lines for activity, 2000 for connections).
- **Log Filters...** (Proxy menu): rules for what the connection log shows, saved in the profile as `LogFilters`. A filter has a mode (*Include* or *Exclude*) and optional patterns for process, IP address, port, protocol (*All*/*TCP*/*UDP*) and action (*All*/*Direct*/*Proxy*/*Blocked*); patterns are case-insensitive globs (`*`, `?`), empty or `All` matches anything. Excludes run first (any match hides a line); if there are Include filters, a line must match one of them. Filters apply to new connections as they happen; the traffic itself is not affected.
- **Start at Boot** (Settings menu, stored in `settings.json`): the service applies the **active profile** when the machine starts and keeps routing after the window is closed (see [The service and the window](#the-service-and-the-window)). Off (default): the service waits for a window, and routing ends when the last window closes. A window without a service (started as root) writes and enables the unit itself instead (`ProxyBridge --print-unit` prints it).
- **Check for Updates on Startup** (Settings menu, on by default, stored in `settings.json`): asks the update feed in the background when the GUI starts. It stays quiet unless a newer version exists, then offers *Open in Browser*, *Close* or *Don't Check at Startup*. Only an `https` page is ever opened.

## Compared with the Windows app (4.3.0)

| Feature | Linux |
|---|---|
| Multiple proxies, per-rule proxy, default proxy | yes |
| TCP and UDP (SOCKS5 UDP ASSOCIATE), IPv4 and IPv6 destinations | yes (UDP: IPv4, or connected IPv6 sockets; unconnected IPv6 UDP fails closed) |
| Rules by process, address, CIDR, range, wildcard, port, protocol, domain | yes |
| Rule names, proxy names, enable/disable, reorder, import/export | yes |
| Per-proxy *DNS via proxy* (`SendDomainToProxy`) | yes |
| Per-rule *Also proxy localhost traffic* (`LocalhostViaProxy`) | yes (BLOCK/DIRECT never touch loopback) |
| Profiles in the `.pbprofile` format, CLI `--profile` | yes |
| Detailed proxy check (reach, login, page, latency, UDP) | yes (GUI Test button) |
| Live connections | yes (GUI tab, `ProxyBridge_GetFlows`) |
| Log Every Connection, main on/off switch | yes |
| Connection-log filters (`LogFilters`), auto-clear logs (`AutoClearConnectionLogs`), font zoom (`FontZoom`) | yes, per profile |
| Service plus window, no admin rights for the window | yes: `proxybridge.service` (root) and `ProxyBridgeGUI` (you), group `proxybridge` |
| Start with the OS | yes (Settings menu, *Start at Boot*): the service applies the active profile at boot |
| Update check on start-up | yes (*Check for Updates on Startup*, on by default, quiet unless a newer version exists) |
| Language selection, close to tray | not implemented |

## Multiple proxies

Add as many proxies as you need (GUI or profile); each rule chooses its own. Proxy hosts may be IP addresses or **host names** (resolved with a 5 s deadline and a cache, so a slow resolver cannot stall traffic). A rule that references a proxy that no longer exists blocks instead of leaking.

## Security model

- **Redirected TCP connections** are bound to the client's source address and port. A process that connects to the relay from a different loopback address (for example `127.0.0.2`) cannot claim another process's pending flow, and an entry is consumed on first use.
- **Redirected UDP flows** are addressed by a loopback flow address that the relay maps back to the original destination and to the process that opened it. These addresses are not secret (they are visible in `/proc/net/udp`), so for every new client port the relay checks the owner of the socket bound to it (the uid column of `/proc/net/udp`): a datagram is dropped when that socket belongs to another user than the flow's owner (root excepted), i.e. one user sending into another user's flow. This is best effort, not a proof, and it never walks descriptor tables, so it costs the same for any process: when nobody holds the port any more (a program that sends one datagram, closes its socket or exits) nothing can be told and the datagram is delivered, which also means an attacker that closes its socket immediately after sending is not caught. Programs of one user are not separated from each other. One process can hold at most 2048 of the 4096 UDP sessions; past that it displaces only its own oldest session, never another program's.
- **Decisions made in user space** (long host lists, domain rules) use the executable the kernel recorded when the connection was opened, not `/proc/<pid>/exe` looked up later, so a process that exits and has its PID reused cannot change a pending decision.
- **The DNS tap** only learns from answer records that belong to the question (the asked name, CNAMEs chained from it, and A records owned by those names); unrelated records in a response are ignored. Note that any local process whose DNS passes through the relay can still teach the engine a name→address mapping for *its own* lookups, and domain rules are matched by address, so on a shared host another user's resolver answers can influence which addresses a domain rule matches. Run ProxyBridge on machines you trust locally.
- **A local proxy is exempted** (its own connections go direct) when a process listens on the configured proxy address and port. While that port is free, for example because the proxy is not running yet, any local process that binds it is treated as the proxy. Point rules at proxies that are running, or at a proxy on another host, when other users share the machine.
- **Fail-open on exit.** The kernel removes the eBPF programs when ProxyBridge stops or crashes. From that moment traffic flows normally: `BLOCK` rules no longer block and nothing is proxied. ProxyBridge is a routing tool, not a firewall; use the "start at boot" service (which restarts it on failure) and a real firewall for enforcement.
- A rule that needs a proxy that does not exist **blocks** instead of letting traffic through. A connection whose proxy handshake fails is closed, never sent direct.
- **The service** (`proxybridge.service`) runs as root, limited to the capabilities the engine needs (`CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`: no chown, kill, setuid, modules, raw I/O, mount or time), with `NoNewPrivileges`, `ProtectSystem=strict` (only `/etc/proxybridge` is writable), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernelModules/Logs/Tunables`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictAddressFamilies` (unix, inet, inet6, netlink), `RestrictNamespaces`, `RestrictSUIDSGID`, `RestrictRealtime`, `LockPersonality`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute`, `UMask=0077`, `MemoryMax=1G` and `TasksMax=512`. `systemd-analyze security` rates it well below the default for a root service, and the tests run the real engine under exactly this sandbox. Its socket accepts connections from every user, but a connection is served only for root and the members of the group `proxybridge` (peer credentials from the kernel, group read at each connection); anyone else gets a refusal. Refusals are cheap (a user refused a moment ago is not looked up again; one journal line per user per minute; nothing is written to the log that windows show), so a local user cannot flood the journal or the accept queue. Limits for authorized windows: frames are checked against 8 MiB before anything is read and must arrive within 30 s of their header, at most 16 windows, a window that lets 64 MiB of answers pile up without reading them is disconnected, events a slow window cannot take are dropped (and it is told how many) instead of blocking the engine, a batch left open is applied after 10 s so one window cannot hold back everyone's changes, and one proxy test runs at a time. A session also ends within seconds when its user leaves the group. Profile names cannot contain control characters, the active profile must exist, and the profile store is limited to 512 profiles and 256 MiB. Membership of the group is administrative power: such a user can route, block and read the proxy credentials of every user's traffic, so add only people you would give `sudo` for ProxyBridge. The window checks that the socket belongs to root before it sends anything. A window started as root without a service installs its unit only when the program and every directory above it belong to root and are writable by root only (an install under `/usr/local/bin`, not a copy run from a home directory).
- Anything shown in the log that another local user controls (an executable's name, a DNS name) has control characters replaced before it reaches the terminal or the GUI, and profiles that contain control characters in any field are rejected.
- The relay listens on loopback only (UDP is additionally bound to the `lo` device). Other network namespaces (containers) are never redirected.
- Proxy passwords are kept in the profile files under `/etc/proxybridge/profiles/` (mode 0600, directory 0700, root). Credentials are never taken from the command line, so they cannot show up in the process list or shell history.

## Use Cases

- Redirect proxy-unaware applications (games, desktop apps) through InterceptSuite/Burp Suite for security testing
- Route specific applications through Tor, SOCKS5, or HTTP proxies
- Intercept and analyze traffic from applications that don't support proxy configuration
- Test application behavior under different network conditions
- Analyze protocols and communication patterns
- Penetration testing of Linux applications
- Network traffic monitoring and debugging

## Current Limitations

- **Needs a recent kernel**: Linux 5.11+ with BTF (`/sys/kernel/btf/vmlinux`) and cgroup v2 mounted (default on current Ubuntu, Debian, Fedora, Arch). Older kernels are not supported
- **Root privileges required for the engine** - loading the eBPF programs needs root (CAP_BPF/CAP_SYS_ADMIN); the installed service has it, so the window does not
- **Native IPv6 UDP to a PROXY rule fails closed** - an unconnected UDP socket sending to a native IPv6 address cannot be redirected (kernel limitation); the `sendto()` returns `EPERM` and applications fall back to IPv4/TCP. Connected IPv6 UDP sockets, IPv6 TCP and UDP to IPv4 destinations through dual-stack sockets all work
- **IPv4 is the fully supported path**; IPv6 (TCP, connected UDP) works for IP rules but has no domain matching and the limits above
- **IPv6-only (`IPV6_V6ONLY`) sockets** connecting to a proxied destination fail (the redirect uses a v4-mapped loopback address)
- **Domain rules only see names the application resolved through DNS that ProxyBridge could observe** - see [Domain rules](#domain-rules) for what that means (DoH/DoT and hard-coded IPs are not matched)
- **Only new connections are affected** - connections that were already open when a rule was added/changed keep their route until they reconnect
- **WSL is not supported** - WSL1/WSL2 kernels do not ship BTF/cgroup-BPF. Use native Linux, VMs, cloud instances or bare metal
- **GUI requires GTK3** - the command-line interface works without GUI dependencies

## Things to Note

- **UDP rules the kernel cannot decide go through the relay, which re-sends the datagram from its own socket.** The kernel decides up to 4 port entries, 4 IPv4 ranges and simple host lists per rule; a longer port list, a domain rule or an IPv6 pattern makes every datagram of a matching process take this slow path. For DIRECT decisions there the peer then sees the relay's source port instead of the application's, and a UDP *server* that matches the same process pattern has its replies re-sent as well, so they reach the client from a different source port. Keep rules for UDP servers narrow (list ports as ranges, name the destination), or put them in a rule of their own.
- **UDP sessions outlive the socket.** A proxied UDP session (and the TCP control connection it holds to the proxy) stays open until it has been idle for 60 seconds, because the engine cannot see an application close its socket. A program that opens a new socket for every lookup (most resolvers) therefore keeps one proxy connection per lookup for a minute; a proxy that limits connections per client (Nexus Proxy: 500) refuses the rest, and ProxyBridge then drops that flow's datagrams for 5 seconds before it tries again.

- **Stalled proxies do not hold everything up.** Connections that need a handshake with their proxy are served by a pool of workers that starts with 8 and grows to 64 while handshakes queue up (extra workers leave after 20 idle seconds). No single proxy may occupy more than 48 workers at once, so a proxy that accepts connections and then never answers (up to the 10 s handshake timeout each) cannot delay connections that use another proxy.

- **DNS Traffic Handling**: by default DNS (port 53) follows your rules like any other traffic; a profile with `"DnsViaProxy": false` makes DNS always use a direct connection regardless of rules.

- **Automatic Direct Routing**: Certain IP addresses and ports automatically use direct connection regardless of proxy rules:
  - **Loopback** (127.0.0.0/8, ::1) and **0.0.0.0/8**, unless a PROXY rule has *Also proxy localhost traffic* (then only that rule's matches are proxied, and never port 53 or the relay itself)
  - **Multicast / broadcast / reserved** (224.0.0.0 and above, ff00::/8) and IPv6 link-local (fe80::/10)
  - **DHCP ports** (UDP 67, 68) - Dynamic Host Configuration Protocol

  These addresses and ports are used by system components, network discovery, and essential Linux services.

- **UDP Proxy Requirements**: UDP traffic only works through a SOCKS5 proxy. A rule that sends UDP to an HTTP proxy cannot be honoured, so that UDP traffic goes DIRECT; ProxyBridge logs a warning naming the rule when it is created or the engine starts. Use a SOCKS5 proxy, or a TCP-only rule plus a separate `UDP ... BLOCK` rule, if direct UDP is not acceptable. This limitation does not affect UDP rules with BLOCK or DIRECT actions.

  **Important UDP Considerations**:
  - Configuring a SOCKS5 proxy does not guarantee UDP will work. Most SOCKS5 proxies do not support UDP traffic, including SSH SOCKS5 proxies.
  - The SOCKS5 proxy must support UDP ASSOCIATE command. If ProxyBridge fails to establish a UDP association with the SOCKS5 proxy, packets will fail to connect.
  - Many UDP applications use HTTP/3 and DTLS protocols. Even if your SOCKS5 proxy supports UDP ASSOCIATE, ensure it can handle DTLS and HTTP/3 UDP traffic, as they require separate handling beyond raw UDP packets.
  - **Testing UDP/HTTP3/DTLS Support**: If you need to test UDP, HTTP/3, and DTLS support with a SOCKS5 proxy, try [Nexus Proxy](https://github.com/InterceptSuite/nexus-proxy) - a proxy application created specifically to test ProxyBridge with advanced UDP protocols.

- **Root Privileges**: the engine requires root access to:
  - Load the eBPF programs and attach them to the root cgroup
  - Listen on its local relay ports (24010 for TCP, 24011 for UDP; the next free pair is used if they are taken)

  That is the job of `proxybridge.service`; the window does not need root (see [The service and the window](#the-service-and-the-window)). `ProxyBridge --profile` and a window without a service must be started with `sudo`. (A window run with `sudo` is a root program like any other: its file dialogs act as root. The unprivileged window does not have that property, which is a reason to prefer the service.)

- **Process Name Matching**: Linux process names are case-sensitive. Use exact process names or wildcard patterns:
  - Exact: `firefox` matches only "firefox"
  - Wildcard: `fire*` matches "firefox", "firebird", "firestorm", etc.
  - All: `*` matches all processes

## How It Works

ProxyBridge hooks the **socket calls** (`connect()`, `sendmsg()`, `recvmsg()`) with eBPF programs attached to the root cgroup. It never inspects or queues packets, so the TCP data path of every application is untouched.

```
 application           kernel (eBPF, cgroup sock_addr hooks)              ProxyBridge (userspace)
 -----------           --------------------------------------              -----------------------
 connect(dst) ───────► which executable is this? ─► which rules apply?
                         no rule / DIRECT  ─────► unchanged (zero extra cost on the data path)
                         BLOCK             ─────► connect() fails with EPERM
                         PROXY(id)         ─────► destination rewritten to 127.0.0.1:relay,
                                                  original destination saved ──────────────► relay reads it,
                                                                                              talks SOCKS5 / HTTP CONNECT
                         cannot decide     ─────► sent to the relay as "decide"  ───────────► full rule engine decides
                                                                                              (and teaches the kernel)
```

**Kernel side** ([src/bpf/proxybridge.bpf.c](src/bpf/proxybridge.bpf.c))
- Identifies the calling process by its executable's `(device, inode)` and looks up a precompiled **class** (the ordered list of rules whose process pattern matches that binary). Rules are compiled to bounded map lookups: port ranges, IPv4 ranges and protocol are evaluated in the kernel; anything it cannot express (octet patterns, IPv6 patterns, many ranges) is handled by the relay
- TCP: rewrites the destination to the local relay and passes the original destination via a `sockops` hook keyed by the client's source port
- UDP: encodes the original destination as a loopback **flow address** (`127.x.y.z`); the relay replies from that address and a `recvmsg` hook restores the real source, so one socket can talk to many destinations
- `getpeername()` on redirected sockets returns the original destination
- Memory is bounded: fixed-size maps (about a few MB in total), LRU maps for per-flow state

**Userspace side** ([src/pb_relay.c](src/pb_relay.c), [src/pb_rules.c](src/pb_rules.c), [src/pb_bpf.c](src/pb_bpf.c))
- Rule engine: validation, globs, IPv4/IPv6, CIDR, ranges, first-match-wins; the reference semantics for everything the kernel cannot decide
- epoll based relay with bounded resources: SOCKS5 (with user/pass) and HTTP CONNECT for TCP, SOCKS5 UDP ASSOCIATE for UDP, direct forwarding for the slow path, idle timeouts, connection cap
- Several proxies can be configured; every rule chooses its own
- Binaries the kernel has not seen yet take a one-time slow path through the relay; the result is cached in the kernel so later connections skip it

**Why this design:** an earlier eBPF attempt (3.1.0) evaluated rules per packet in the kernel and was abandoned for memory and latency reasons. This design avoids both problems: decisions are made once per connection (not per packet), rules are compiled into small bounded maps, and everything the kernel cannot express goes to userspace once per connection.

**Cleanup:** the programs are attached through BPF links, so the kernel removes them automatically when ProxyBridge exits or crashes. There are no iptables rules or system settings to restore.

## Build from Source

### Requirements

- Linux kernel 5.11+ with BTF and cgroup v2 (to run); GCC, Make, **clang** and **bpftool** (to build the eBPF object and skeleton)
- Development libraries:
  - curl and bzip2 (the first build downloads pinned, checksum-verified libbpf, libelf (elfutils) and zlib sources, builds them
    as static libraries into `~/.cache/proxybridge`, and links them in: the library and the command line program need only glibc
    at run time, no libelf, zlib or libbpf package)
  - libgtk-3-dev (optional, for GUI) or gtk3-devel (Fedora/RHEL)
  - pkg-config

Binaries are built against a glibc 2.34 baseline (Ubuntu 22.04, Debian 12, RHEL 9 and newer run them), with LTO, FORTIFY_SOURCE=3,
full RELRO, BIND_NOW, PIE, stack protector and CET flags; `Linux/tests/check_binaries.sh` audits this on every build (issue #146).

### Building

1. **Install build dependencies:**

   **Debian/Ubuntu/Mint:**
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential gcc make clang bpftool \
       curl bzip2 libgtk-3-dev pkg-config
   ```

   **Fedora:**
   ```bash
   sudo dnf install gcc make clang bpftool \
       curl bzip2 gtk3-devel pkg-config
   ```

   **Arch/Manjaro:**
   ```bash
   sudo pacman -S base-devel gcc make clang bpf \
       curl bzip2 gtk3 pkg-config
   ```

2. **Clone or download ProxyBridge source code:**
   ```bash
   git clone https://github.com/InterceptSuite/ProxyBridge.git
   cd ProxyBridge/Linux
   ```

3. **Build using the build script:**
   ```bash
   chmod +x build.sh
   ./build.sh
   ```

   This will compile:
   - `libproxybridge.so` - Core library
   - `ProxyBridge` - CLI application
   - `ProxyBridgeGUI` - GUI application (if GTK3 is available)

4. **Install to system paths:**
   ```bash
   sudo ./setup.sh
   ```

   Or manually copy binaries:
   ```bash
   sudo cp output/libproxybridge.so /usr/local/lib/
   sudo cp output/ProxyBridge /usr/local/bin/
   sudo cp output/ProxyBridgeGUI /usr/local/bin/  # If GUI was built
   sudo ldconfig
   ```

### Build Output

After successful build, binaries will be in the `output/` directory:
- `output/libproxybridge.so` - Shared library
- `output/ProxyBridge` - CLI binary
- `output/ProxyBridgeGUI` - GUI binary (if GTK3 available)

### Manual Compilation

**Library:**
```bash
cd src
make            # builds bpf/proxybridge.bpf.o, proxybridge.skel.h and libproxybridge.so
make test-rules # parser/matcher unit tests (ASan + UBSan)
```

**CLI:**
```bash
cd cli
gcc -Wall -Wextra -O3 -I../src \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE \
    -Wformat -Wformat-security -Werror=format-security \
    -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv \
    -c main.c -o main.o

gcc -o ProxyBridge main.o \
    -L../src -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -s \
    -Wl,-rpath,/usr/local/lib \
    -lproxybridge -lpthread
```

**Full end-to-end suite (`tests/e2e_full.sh`).** Runs the installed or built CLI with real `.pbprofile` files in front of two Nexus instances and compares **engine off with engine on**: the same Python client (TCP, UDP, real DNS packets over UDP and TCP, QUIC Version Negotiation datagrams, load) must get identical results either way, and the proxy logs must show the traffic went through the proxy, or did not for DIRECT and BLOCK rules. Phases: baseline, all proxied, TCP-only, UDP-only, all direct, UDP blocked, DNS via proxy on vs off (host name vs address sent to the proxy), load (500 TCP connections, 1000 UDP sockets, 700 one-shot resolver sockets, datagram rate ramp), **real HTTP/3** with a curl that supports it (QUIC over SOCKS5 UDP ASSOCIATE, skipped when offline), and failure handling (wrong password, dead proxy, restarted proxy). It prints throughput, latency and loss for both modes. `sudo NODE=... NEXUS_JS=... PB_BIN=/usr/local/bin/ProxyBridge tests/e2e_full.sh`; `PHASES="2 8"`, `CLIENT_SCENARIOS`, `KEEP_PROFILES`, `KEEP_LOGS` select and keep things (see the script header). It needs root, node, python3 and the Nexus script; it adds one line to `/etc/hosts` for the DNS-via-proxy phase and removes it on exit.

**Testing against Nexus Proxy.** [Nexus Proxy](https://github.com/InterceptSuite/nexus-proxy) is a Node.js SOCKS5 server that really forwards TCP and UDP. `tests/e2e_nexus.sh` runs ProxyBridge in front of two Nexus instances (one with a username/password) with real origin servers and a real DNS server, and checks rules by IP, port, port range, process, CIDR and domain, TCP and UDP, 200 MB / 100 MB checksummed transfers, 100 parallel and 1,500 sequential connections, 300 concurrent UDP sockets, 59 KB datagrams, a sustained UDP stream, and recovery after the proxy restarts. Nexus Proxy 1.1 and later does UDP ASSOCIATE on Linux; older copies cannot (their IPv6 relay socket binds `0.0.0.0`, IPv4 destinations are not sent as `::ffff:` addresses, and mapped replies are not matched), `tests/nexus-linux-udp.patch` fixes such a copy, and without it the UDP checks are skipped. Nexus limits each client IP to 500 connections by default (`--max-per-ip` raises it), so the 10,000-connection scale test uses a different server.

**Config location:** the GUI stores profiles, proxies and rules in `/etc/proxybridge/config.ini` (mode 0600). Set `PROXYBRIDGE_CONFIG_DIR` to use another directory (used by the tests).

## Uninstallation

To remove ProxyBridge from your system, run `sudo ./setup.sh --uninstall` from the extracted release (add `--purge` to delete the profiles under `/etc/proxybridge` too), or by hand:

```bash
# Stop and remove the service
sudo systemctl disable --now proxybridge.service 2>/dev/null
sudo rm -f /etc/systemd/system/proxybridge.service
sudo systemctl daemon-reload

# Remove the launcher entry and icon
sudo rm -f /usr/share/applications/proxybridge.desktop /usr/share/icons/hicolor/*/apps/proxybridge.png

# Remove binaries
sudo rm -f /usr/local/bin/ProxyBridge
sudo rm -f /usr/local/bin/ProxyBridgeGUI

# Remove library
sudo rm -f /usr/local/lib/libproxybridge.so

# Remove configuration
sudo rm -rf /etc/proxybridge

# Update library cache
sudo ldconfig

# Remove ld.so.conf entry (if exists)
sudo rm -f /etc/ld.so.conf.d/proxybridge.conf
sudo ldconfig
```

**Cleanup after crash:** nothing to do. ProxyBridge attaches its eBPF programs through BPF links, which the kernel removes when the process exits or crashes (traffic then flows normally, see [Security model](#security-model)). To check: `sudo bpftool cgroup tree /sys/fs/cgroup` should list no `pb_*` programs.

**Verifying a download:** every release carries a `.sha256` file next to the tarball: `sha256sum -c ProxyBridge-Linux-v*.tar.gz.sha256`.

## License

MIT License - See LICENSE file for details

---

**Author:** Sourav Kalal / InterceptSuite
**GitHub:** https://github.com/InterceptSuite/ProxyBridge
**Documentation:** https://github.com/InterceptSuite/ProxyBridge/tree/master/Linux

## Testing

```bash
cd Linux && ./build.sh                            # builds in a temp dir, final files land in Linux/output/
cd src && make test-rules BUILD_DIR=/tmp/pbt      # rule engine + DNS parser tests (no root needed)
profile/tests/run_tests.sh                        # .pbprofile reader/writer incl. fuzzing, under ASan/UBSan (no root needed)
cd tests && ./run_relay_test.sh both              # relay tests, plain and ASan/UBSan (no root needed)
cd ../../tests && sudo ./e2e.sh                   # end-to-end with real kernel hooks (root); uses Linux/output, override with PB_DIR=
sudo ./e2e_domains.sh                             # domain rules with a real resolver client (root, needs dig)
sudo ./e2e_rules.sh                               # every rule form + every proxy type, incl. HTTP auth and UDP rules (root)
sudo ./e2e_profile.sh                             # `ProxyBridge --profile`: Windows-format profiles on the live datapath (root)
sudo ./e2e_faults.sh                              # misbehaving SOCKS5/HTTP proxies: every failure code, stalls, early closes, 255-byte logins, 4 MiB integrity, a dead proxy cannot starve a healthy one (root)
sudo ./e2e_udp.sh                                 # UDP through SOCKS5 UDP ASSOCIATE: normal and malformed proxies, sizes, many sockets, BLOCK/DIRECT/HTTP, IPv6 (root)
sudo ./e2e_rules_diff.sh                          # random rule sets vs an independent reference: kernel fast path and slow path, TCP and UDP (root)
sudo ./e2e_logging.sh                             # connection log: de-duplication, log-every-connection, one line per decision (root)
./e2e_checker.sh                                  # the proxy check against working and broken proxies (no root)
sudo ./gui_ui.sh                                  # drives the real windows and dialogs: proxies, rules, profiles, file choosers, menus, engine - once with its own engine and once through a service (root, needs broadwayd)
sudo ./e2e_daemon.sh                              # the service: protocol and random garbage, access control by group, profile store, engine control, live connections, batch, Start at Boot (root)
sudo ./e2e_service.sh                             # the service under real systemd with the installer's exact unit: sandbox, eBPF, crash and restart, stop (root, systemd)
sudo ./gui_service.sh                             # the shipped GUI run by an unprivileged user in front of a real service (root, needs broadwayd and setpriv)
sudo ./coverage.sh                                # line coverage of everything above plus the unit tests; `./coverage.sh unit` needs no root
sudo ./e2e_parity.sh                              # per-proxy host-name sending and per-rule localhost, incl. a hostile DNS name (root, needs dig)
sudo ./api_live.sh                                # library API: edit/move/disable/delete rules and proxies on the live datapath (root)
sudo BPFTOOL=$(command -v bpftool) ./e2e_security.sh   # relay hand-off cannot be hijacked from another loopback address (root)
sudo ./churn.sh 3000                              # rule/proxy churn with live traffic: memory, fds and threads must stay flat (root)
sudo ./e2e_openssh.sh                             # interoperability with a real third-party SOCKS5 server (OpenSSH ssh -D), 40 MB each way (root)
sudo NODE=$(command -v node) NEXUS_JS=/path/to/nexus-proxy/script.js ./e2e_nexus.sh   # against Nexus Proxy, a real forwarding SOCKS5 server with UDP (root)
sudo ./scale.sh 10000                             # 10,000 concurrent proxied connections (root)
sudo ./gui_headless.sh <ProxyBridgeGUI> <libdir>  # the real GTK GUI under the Broadway backend (root, needs broadwayd)
gui/tests/run_tests.sh                            # GUI config/profile storage, JSON and event-queue tests (ASan, UBSan, TSan; no root needed)
```
