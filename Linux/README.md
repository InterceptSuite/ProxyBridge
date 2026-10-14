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
- Download the latest release from GitHub automatically
- Detect your Linux distribution
- Install all required dependencies (libelf, zlib, GTK3)
- Install ProxyBridge CLI, GUI, and library to system paths
- Update library cache (ldconfig)
- Verify installation

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
- Install runtime dependencies (libelf, zlib, GTK3)
- Copy binaries to `/usr/local/bin` (ProxyBridge CLI and GUI)
- Copy library to `/usr/local/lib` (libproxybridge.so)
- Update library cache
- Verify installation

**What gets installed:**
- `/usr/local/bin/ProxyBridge` - Command-line interface
- `/usr/local/bin/ProxyBridgeGUI` - Graphical interface (if GTK3 available)
- `/usr/local/lib/libproxybridge.so` - Core library
- `/etc/proxybridge/` - Configuration directory

## Usage

### GUI Application

**Launch GUI (requires GTK3):**

```bash
sudo ProxyBridgeGUI
```

The GTK3-based GUI provides:
- Proxy configuration (SOCKS5/HTTP with authentication)
- Visual rule management with process selection
- Real-time connection monitoring
- Import/Export rules (JSON format compatible with Windows/macOS)
- DNS via Proxy toggle


### Command Line Interface (CLI)

The CLI provides powerful automation and scripting capabilities with rule-based traffic control.

#### Basic Usage

```bash
# Help menu
ProxyBridge --help

# Route curl through SOCKS5 proxy
sudo ProxyBridge --proxy socks5://127.0.0.1:1080 --rule "curl:*:*:TCP:PROXY"

# Route multiple processes in single rule (semicolon-separated)
sudo ProxyBridge --proxy http://127.0.0.1:8080 --rule "curl;wget;firefox:*:*:TCP:PROXY"

# Multiple rules with verbose connection logging
sudo ProxyBridge --proxy http://127.0.0.1:8080 \
    --rule "curl:*:*:TCP:PROXY" \
    --rule "wget:*:*:TCP:PROXY" \
    --verbose 2

# Block specific application from internet access
sudo ProxyBridge --rule "malware:*:*:BOTH:BLOCK"

# Route specific apps through proxy, block everything else
sudo ProxyBridge --proxy socks5://127.0.0.1:1080 \
    --rule "curl:*:*:TCP:PROXY" \
    --rule "firefox:*:*:TCP:PROXY" \
    --rule "*:*:*:BOTH:BLOCK"

# Route all through proxy except proxy app itself
sudo ProxyBridge --proxy socks5://127.0.0.1:1080 \
    --rule "*:*:*:TCP:PROXY" \
    --rule "burpsuite:*:*:TCP:DIRECT"

# Target specific IPs and ports
sudo ProxyBridge --proxy socks5://127.0.0.1:1080 \
    --rule "curl:192.168.*.*;10.10.*.*:80;443;8080:TCP:PROXY"

# IP range support
sudo ProxyBridge --proxy socks5://192.168.1.4:4444 \
    --rule "curl:3.19.110.0-3.19.115.255:*:TCP:PROXY"

# Several proxies, each rule picks its own (name=type://[user:pass@]host:port)
sudo ProxyBridge \
    --proxy tor=socks5://127.0.0.1:9050 \
    --proxy burp=http://127.0.0.1:8080 \
    --rule "firefox:*:*:BOTH:PROXY=tor" \
    --rule "curl;wget:*:*:TCP:PROXY=burp" \
    --rule "*:10.0.0.0/8:*:BOTH:DIRECT"

# IPv6 and CIDR targets
sudo ProxyBridge --rule "curl:2001:db8::/32;10.0.0.0/8:443:TCP:PROXY"
```

#### Command Line Options

```
sudo ProxyBridge --help


  ____                        ____       _     _            
 |  _ \ _ __ _____  ___   _  | __ ) _ __(_) __| | __ _  ___ 
 | |_) | '__/ _ \ \/ / | | | |  _ \| '__| |/ _` |/ _` |/ _ \
 |  __/| | | (_) >  <| |_| | | |_) | |  | | (_| | (_| |  __/
 |_|   |_|  \___/_/\_\\__, | |____/|_|  |_|\__,_|\__, |\___|
                      |___/                      |___/  V4.0

  Universal proxy client for Linux applications

	Author: Sourav Kalal/InterceptSuite
	GitHub: https://github.com/InterceptSuite/ProxyBridge

USAGE:
  cli/ProxyBridge [OPTIONS]

OPTIONS:
  --proxy <spec>         Add a proxy (repeatable). The first one is the default.
                         Format: [name=]type://[user:pass@]host:port
                         Examples: socks5://127.0.0.1:1080
                                   work=http://alice:secret@proxy.corp:8080
                                   tor=socks5://[::1]:9050
                         Legacy form type://host:port:user:pass is still accepted.
                         Default: socks5://127.0.0.1:4444

  --rule <rule>          Traffic routing rule (repeatable, first match wins)
                         Format: process:hosts:ports:protocol:action[=proxy]
                           process  - name or path glob(s): curl, chrom*, *, or several separated by ; or ,
                           hosts    - IPv4/IPv6, CIDR (10.0.0.0/8), ranges (1.2.3.4-1.2.3.9),
                                      octet patterns (192.168.*.*) or *; several separated by ; or ,
                           ports    - *, 443, 80;8080, 8000-9000
                           protocol - TCP, UDP, or BOTH
                           action   - PROXY, DIRECT, or BLOCK; PROXY=name (or PROXY=2) picks a specific proxy
                         Examples:
                           curl:*:*:TCP:PROXY
                           firefox:*:*:BOTH:PROXY=work
                           curl;wget:10.0.0.0/8:*:TCP:DIRECT
                           *:*:53:UDP:PROXY=tor

  --dns-via-proxy <bool> Route DNS queries through the proxy (true/false/1/0, default true)

  --verbose <level>      0 none (default), 1 logs, 2 connections, 3 both

  --cleanup              No-op, kept for compatibility: the eBPF programs detach automatically

  --help, -h             Show this help message

EXAMPLES:
  sudo cli/ProxyBridge --rule curl:*:*:TCP:PROXY

  sudo cli/ProxyBridge --proxy socks5://192.168.1.10:1080 --proxy work=http://proxy.corp:8080 \
       --rule firefox:*:*:BOTH:PROXY --rule curl:*:*:TCP:PROXY=work --verbose 2

NOTE:
  ProxyBridge needs root and a Linux kernel >= 5.11 with BTF and cgroup v2 (eBPF datapath).
  Credentials given on the command line are visible to other users via ps.
```

#### Rule Format

**Format:** `process:hosts:ports:protocol:action[=proxy]`

- **process** - Name or path glob(s): `curl`, `curl;wget;firefox`, `fire*`, `*chrome*`, `/usr/bin/*`, or `*`. Matched against the executable's file name and full path, case-sensitive
- **hosts** - `*`, IPv4/IPv6 addresses, CIDR (`10.0.0.0/8`, `2001:db8::/32`), ranges (`10.10.1.1-10.10.255.255`), octet patterns (`192.168.*.*`, `10.1-5.*.*`), **domain names** (`github.com`, `*.github.com`, `api?.example.org`), or a list mixing any of these separated by `;` or `,`. A plain domain matches exactly that name; use `*.` for subdomains. See [Domain rules](#domain-rules)
- **ports** - `*`, `443`, `80;443;8080`, `80-8000`, or `80;443;8000-9000`
- **protocol** - `TCP`, `UDP`, or `BOTH`
- **action** - `PROXY`, `DIRECT`, or `BLOCK`. `PROXY=name` (or `PROXY=2`, the 1-based position of a `--proxy`) uses a specific proxy; plain `PROXY` uses the first one

Rules are evaluated **in order and the first match wins** (put specific rules before general ones).

**Examples:**
```bash
# Single process to proxy
--rule "curl:*:*:TCP:PROXY"

# Multiple processes in one rule
--rule "curl;wget;firefox:*:*:TCP:PROXY"

# Wildcard process names
--rule "fire*:*:*:TCP:PROXY"  # Matches firefox, firebird, etc.

# Target specific IPs and ports
--rule "curl:192.168.*.*;10.10.*.*:80;443;8080:TCP:PROXY"

# Specific proxy per rule
--rule "firefox:*:*:BOTH:PROXY=tor"

# Domain names (exact and wildcard), each rule with its own proxy
--rule "firefox:*.github.com;github.com:443:TCP:PROXY=work"
--rule "*:*.internal.corp:*:BOTH:PROXY=burp"

# IP range / CIDR / IPv6
--rule "curl:3.19.110.0-3.19.115.255:*:TCP:PROXY"
--rule "curl:10.0.0.0/8:*:TCP:DIRECT"
--rule "curl:2001:db8::/32:443:TCP:PROXY"

# Allow direct connection (bypass proxy)
--rule "burpsuite:*:*:TCP:DIRECT"
```

**Notes:**
- Process names are case-sensitive on Linux
- Interpreted programs (python, node, java) are identified by the interpreter binary, e.g. `python3.12`
- A `PROXY` rule whose proxy does not exist is treated as `BLOCK` (traffic never leaks around a missing proxy)
- A local proxy is never proxied through itself: processes that listen on a configured proxy address (for example Burp, mitmproxy, Tor or `ssh -D` on 127.0.0.1) are exempted automatically, so a rule with process `*` cannot create a loop. The exemption is per process, not per program, and is refreshed every two seconds
- Press `Ctrl+C` to stop ProxyBridge; the kernel hooks are removed automatically, even if ProxyBridge crashes

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

## Multiple proxies

Add as many `--proxy` entries (CLI) or proxies (GUI) as you need; each rule chooses its own with `PROXY=name`. Proxy hosts may be IP addresses or **host names** (resolved with a 5 s deadline and a cache, so a slow resolver cannot stall traffic). A rule that references a proxy that no longer exists blocks instead of leaking.

## Security model

- **Redirected TCP connections** are bound to the client's source address and port. A process that connects to the relay from a different loopback address (for example `127.0.0.2`) cannot claim another process's pending flow, and an entry is consumed on first use.
- **Redirected UDP flows** are addressed by a loopback flow address that the relay maps back to the original destination. These addresses are not secret (they are visible in `/proc/net/udp`), so on a **multi-user host** another local user can send datagrams to the relay's UDP port and have them forwarded to a destination that some other process is already talking to, through the same proxy. Run ProxyBridge on machines you trust locally.
- A rule that needs a proxy that does not exist **blocks** instead of letting traffic through.
- The relay listens on loopback only (UDP is additionally bound to the `lo` device). Other network namespaces (containers) are never redirected.
- Proxy passwords are kept in `/etc/proxybridge/config.ini` (mode 0600, root). On the command line, `--proxy user:pass@host` is wiped from the process list after parsing, but a shell history can still keep it; prefer the GUI or a config file for secrets.

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
- **Root privileges required** - loading the eBPF programs needs root (CAP_BPF/CAP_SYS_ADMIN)
- **Native IPv6 UDP to a PROXY rule fails closed** - an unconnected UDP socket sending to a native IPv6 address cannot be redirected (kernel limitation); the `sendto()` returns `EPERM` and applications fall back to IPv4/TCP. Connected IPv6 UDP sockets, IPv6 TCP and UDP to IPv4 destinations through dual-stack sockets all work
- **IPv4 is the fully supported path**; IPv6 (TCP, connected UDP) works for IP rules but has no domain matching and the limits above
- **IPv6-only (`IPV6_V6ONLY`) sockets** connecting to a proxied destination fail (the redirect uses a v4-mapped loopback address)
- **Domain rules only see names the application resolved through DNS that ProxyBridge could observe** - see [Domain rules](#domain-rules) for what that means (DoH/DoT and hard-coded IPs are not matched)
- **Only new connections are affected** - connections that were already open when a rule was added/changed keep their route until they reconnect
- **WSL is not supported** - WSL1/WSL2 kernels do not ship BTF/cgroup-BPF. Use native Linux, VMs, cloud instances or bare metal
- **GUI requires GTK3** - the command-line interface works without GUI dependencies

## Things to Note

- **DNS Traffic Handling**: with `--dns-via-proxy true` (default) DNS (port 53) follows your rules like any other traffic; with `false`, DNS always uses a direct connection regardless of rules.

- **Automatic Direct Routing**: Certain IP addresses and ports automatically use direct connection regardless of proxy rules:
  - **Loopback** (127.0.0.0/8, ::1) and **0.0.0.0/8**
  - **Multicast / broadcast / reserved** (224.0.0.0 and above, ff00::/8) and IPv6 link-local (fe80::/10)
  - **DHCP ports** (UDP 67, 68) - Dynamic Host Configuration Protocol

  These addresses and ports are used by system components, network discovery, and essential Linux services.

- **UDP Proxy Requirements**: UDP traffic only works through a SOCKS5 proxy. A rule that sends UDP to an HTTP proxy cannot be honoured, so that UDP traffic goes DIRECT; ProxyBridge logs a warning naming the rule when it is created or the engine starts. Use a SOCKS5 proxy, or a TCP-only rule plus a separate `UDP ... BLOCK` rule, if direct UDP is not acceptable. This limitation does not affect UDP rules with BLOCK or DIRECT actions.

  **Important UDP Considerations**:
  - Configuring a SOCKS5 proxy does not guarantee UDP will work. Most SOCKS5 proxies do not support UDP traffic, including SSH SOCKS5 proxies.
  - The SOCKS5 proxy must support UDP ASSOCIATE command. If ProxyBridge fails to establish a UDP association with the SOCKS5 proxy, packets will fail to connect.
  - Many UDP applications use HTTP/3 and DTLS protocols. Even if your SOCKS5 proxy supports UDP ASSOCIATE, ensure it can handle DTLS and HTTP/3 UDP traffic, as they require separate handling beyond raw UDP packets.
  - **Testing UDP/HTTP3/DTLS Support**: If you need to test UDP, HTTP/3, and DTLS support with a SOCKS5 proxy, try [Nexus Proxy](https://github.com/InterceptSuite/nexus-proxy) - a proxy application created specifically to test ProxyBridge with advanced UDP protocols.

- **Root Privileges**: ProxyBridge requires root access to:
  - Load the eBPF programs and attach them to the root cgroup
  - Listen on its local relay ports (24010 for TCP, 24011 for UDP; the next free pair is used if they are taken)

  Always run with `sudo` or as root user.

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
  - libelf-dev + zlib1g-dev (Debian/Ubuntu) or elfutils-libelf-devel + zlib-devel (Fedora/RHEL). libbpf itself is built from a pinned
    release and linked statically, so it is not needed at run time
  - curl (fetches the pinned libbpf source on first build)
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
       libelf-dev zlib1g-dev curl libgtk-3-dev pkg-config
   ```

   **Fedora:**
   ```bash
   sudo dnf install gcc make clang bpftool \
       elfutils-libelf-devel zlib-devel curl gtk3-devel pkg-config
   ```

   **Arch/Manjaro:**
   ```bash
   sudo pacman -S base-devel gcc make clang bpf \
       libelf zlib curl gtk3 pkg-config
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

**Testing against Nexus Proxy.** [Nexus Proxy](https://github.com/InterceptSuite/nexus-proxy) is a Node.js SOCKS5 server that really forwards TCP and UDP. `tests/e2e_nexus.sh` runs ProxyBridge in front of two Nexus instances (one with a username/password) with real origin servers and a real DNS server, and checks rules by IP, port, port range, process, CIDR and domain, TCP and UDP, 200 MB / 100 MB checksummed transfers, 100 parallel and 1,500 sequential connections, 300 concurrent UDP sockets, 59 KB datagrams, a sustained UDP stream, and recovery after the proxy restarts. Stock Nexus cannot do UDP ASSOCIATE on Linux (its IPv6 relay socket binds `0.0.0.0`, IPv4 destinations are not sent as `::ffff:` addresses, and mapped replies are not matched); `tests/nexus-linux-udp.patch` fixes that, and without it the UDP checks are skipped. Nexus limits each client IP to 500 connections, so it cannot be used for the 10,000-connection scale test.

**Config location:** the GUI stores profiles, proxies and rules in `/etc/proxybridge/config.ini` (mode 0600). Set `PROXYBRIDGE_CONFIG_DIR` to use another directory (used by the tests).

## Uninstallation

To remove ProxyBridge from your system:

```bash
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

**Cleanup after crash:** nothing to do. ProxyBridge attaches its eBPF programs through BPF links, which the kernel removes when the process exits or crashes. To check: `sudo bpftool cgroup tree /sys/fs/cgroup` should list no `pb_*` programs.

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
cd tests && ./run_relay_test.sh both              # relay tests, plain and ASan/UBSan (no root needed)
cd ../../tests && sudo ./e2e.sh                   # end-to-end with real kernel hooks (root); uses Linux/output, override with PB_DIR=
sudo ./e2e_domains.sh                             # domain rules with a real resolver client (root, needs dig)
sudo ./e2e_rules.sh                               # every rule form + every proxy type, incl. HTTP auth and UDP rules (root)
sudo ./api_live.sh                                # library API: edit/move/disable/delete rules and proxies on the live datapath (root)
sudo BPFTOOL=$(command -v bpftool) ./e2e_security.sh   # relay hand-off cannot be hijacked from another loopback address (root)
sudo ./churn.sh 3000                              # rule/proxy churn with live traffic: memory, fds and threads must stay flat (root)
sudo ./e2e_openssh.sh                             # interoperability with a real third-party SOCKS5 server (OpenSSH ssh -D), 40 MB each way (root)
sudo NODE=$(command -v node) NEXUS_JS=/path/to/nexus-proxy/script.js ./e2e_nexus.sh   # against Nexus Proxy, a real forwarding SOCKS5 server with UDP (root)
sudo ./scale.sh 10000                             # 10,000 concurrent proxied connections (root)
sudo ./gui_headless.sh <ProxyBridgeGUI> <libdir>  # the real GTK GUI under the Broadway backend (root, needs broadwayd)
cd ../gui/tests && gcc -I../../src -I.. -D_GNU_SOURCE $(pkg-config --cflags gtk+-3.0) config_test.c ../gui_config.c -o /tmp/config_test $(pkg-config --libs gtk+-3.0) && /tmp/config_test   # GUI config/profile tests
```
