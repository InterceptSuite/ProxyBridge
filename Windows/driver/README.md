# ProxyBridgeDrv — ProxyBridge WFP kernel driver

`ProxyBridgeDrv.sys` is the kernel-mode capture engine for ProxyBridge. It uses the
**Windows Filtering Platform (WFP)** to redirect a watched application's outbound connections
to the local ProxyBridge relay and to report every connection for the activity log. It is the
sole capture path — no packets are copied to user mode.

Coverage: **IPv4 + IPv6, TCP + UDP**, redirection plus full connection logging.

---

## What it is

A WDM WFP **callout driver** with two responsibilities, implemented as two sets of callouts:

| Callout | WFP layer | Role |
|---|---|---|
| **Redirect** | `ALE_CONNECT_REDIRECT_V4/V6` | For *watched* processes, rewrites the connection's destination to the relay and attaches the original destination + PID as a redirect context. A single layer covers both TCP and UDP. |
| **Monitor** | `ALE_AUTH_CONNECT_V4/V6` | Pure inspection — never changes the verdict. Records every outbound connect (application image, destination, port, protocol) into a ring buffer that user mode drains for the connection log. |

The driver holds **no proxy rules**. It knows only a **watch list** of process image names. The
full rule engine (process / IP / port / **domain** / per-config / block) runs in user mode, where
the DNS cache lives — the kernel only sees IP addresses and cannot evaluate domain rules.

---

## Compared to WinDivert

WinDivert intercepts **packets** at the network layer. ProxyBridgeDrv intercepts **connections**
at the ALE layer, which removes the machinery a packet-level approach requires:

| | WinDivert | ProxyBridgeDrv (WFP) |
|---|---|---|
| Interception point | Every packet (network layer) | Once per connection (ALE layer) |
| Owning PID | `GetExtendedTcpTable` scan + cache | Delivered in the classify metadata |
| Original destination | Source-port → connection table | Redirect context on the socket / UDP flow map |
| Per-packet work | Receive → mangle → re-checksum → re-inject | None — the kernel routes natively |
| Direct / unmatched traffic | Traverses the user-mode packet loop | Untouched in the kernel (zero overhead) |
| Blocking | Drop packets in the loop | Redirect to the relay, which refuses |
| Throughput / ordering | Bounded by the user-mode copy; requires a single ordered thread to avoid packet reordering | Native TCP path, no reordering |
| Distribution | `WinDivert.dll` + `WinDivert64.sys` | `ProxyBridgeDrv.sys` |

The result is the same feature set — IPv4/6, TCP/UDP, proxy/direct/block, domain rules, full
logging — with less work and no packet rewriting.

---

## How it works

```
app  connect(realDst)  /  first UDP sendto(realDst)
   |
   v  ALE_CONNECT_REDIRECT_V4/V6  --  redirect callout
   |    - PID + original destination come from WFP (no table scans)
   |    - watched process?   no  -> permit (direct, in kernel, zero overhead)
   |                         yes -> rewrite remote = relay; set localRedirectHandle,
   |                                localRedirectTargetPID = relay PID, and a context
   |                                holding {origDst, pid}. UDP also records src->origDst
   |                                in an in-kernel flow map (datagrams carry no context).
   |
   v  ALE_AUTH_CONNECT_V4/V6  --  monitor callout (all connects, inspection only)
   |    - queue {pid, dst, port, proto, image} into the event ring for the log
   |
   v  relay accept()  (TCP)  /  recvfrom()  (UDP)
   |    - TCP: WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT) -> {origDst, pid}
   |    - UDP: PBDRV_IOCTL_QUERY_UDP by datagram source -> {origDst, pid}
   |
   v  relay runs the full rule engine -> PROXY (SOCKS5/HTTP) . DIRECT . BLOCK (close)
```

WFP behaviour the driver depends on:

- **`localRedirectTargetPID` is required.** A loopback connect-redirect is only valid when the
  PID of the process handling the redirected flow (the relay) is set; otherwise WFP drops the
  connection.
- **WFP owns the redirect context.** Once assigned to `localRedirectContext` and applied, WFP
  frees it when the redirect record is torn down, so the callout must not free it.
- **Zone-safe target.** The redirect targets loopback only when the application has no bound local
  address; otherwise it targets the application's own local address, so the connection does not
  cross the loopback/real-address zone.
- **Loop prevention.** The relay's own connection to the upstream proxy re-enters the layer and is
  excluded via the shared redirect handle (`FwpsQueryConnectionRedirectState0`) and `selfPid`.
- **The local address/port is never modified** — that is unsupported at the connect-redirect layer.

---

## Security

The control device `\\.\ProxyBridgeDrv` is created with **`IoCreateDeviceSecure`** and a DACL that
grants access to **SYSTEM and Administrators only** (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`). The IOCTL
surface can reconfigure the redirect target and read the connection log, so a world-openable
device would be a local privilege-escalation and information-disclosure risk. All IOCTL inputs are
length-validated before use, and the runtime configuration is snapshotted under a lock in the
classify path (it can be re-pushed live, for example by the "Localhost via Proxy" option).

---

## Files

```
driver/
  ProxyBridgeDrv.vcxproj      WDK build project
  build.bat                   one-command build (Release/Debug)
  src/
    ProxyBridgeDrv.c          DriverEntry, IOCTL dispatch, WFP registration, classify + monitor
    pbdrv_state.c / .h        UDP flow map + connection-event ring + loopback helpers
    ProxyBridgeDrv_ioctl.h    shared user/kernel contract (config, watch list, context, IOCTLs)
    ProxyBridgeDrv.rc / .inf  version resource + install information
  temp-sign/
    temp-sign.ps1             test-sign the .sys with a self-signed certificate (development)
```

The user-mode glue that talks to this driver (`ProxyBridgeDrv_user.c/.h`) ships with the core DLL
in `..\src\driver\`. `ProxyBridgeDrv_ioctl.h` is duplicated there and must remain byte-identical
to this copy — it is the kernel/user contract.

### IOCTL surface (`ProxyBridgeDrv_ioctl.h`)

| IOCTL | Direction | Purpose |
|---|---|---|
| `SET_CONFIG` | user -> driver | Relay endpoints (TCP/UDP x v4/v6), `selfPid`, UDP/IPv6/loopback toggles |
| `SET_WATCHLIST` | user -> driver | Image names that have any rule (re-pushed on every rule change) |
| `ENABLE` / `DISABLE` | user -> driver | Arm / disarm redirection |
| `QUERY_UDP` | user <-> driver | Recover a redirected UDP datagram's original destination by its source |
| `POP_EVENTS` | driver -> user | Drain the connection-event ring (feeds the connection log) |

---

## Build

Requires **Visual Studio Build Tools + WDK** with matching SDK/WDK versions (target
`10.0.28000`, which provides the `km` headers). Output: `x64\Release\ProxyBridgeDrv.sys`.

```
build.bat                 REM Release  - or:
msbuild ProxyBridgeDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:SignMode=Off
```

`SpectreMitigation=false` avoids the Spectre-mitigated CRT libraries; `SignMode=Off` leaves
signing to the step below. The driver links `fwpkclnt.lib`, `ndis.lib`, and `wdmsec.lib`.

---

## Sign & load

Production distribution requires an **EV certificate** (or attestation signing); a driver signed
that way loads on any machine without test mode. For a development or test VM, use test-signing:

1. In a throwaway VM with **Secure Boot off**: `bcdedit /set testsigning on`, then reboot.
2. From the folder containing `ProxyBridgeDrv.sys`, in an elevated shell:
   `powershell -ExecutionPolicy Bypass -File .\temp-sign.ps1`
   This creates and trusts a self-signed certificate, signs the driver, and clears any stale
   service.
3. Launch ProxyBridge as Administrator; it installs and starts the `ProxyBridgeDrv` kernel
   service. Confirm with `sc.exe query ProxyBridgeDrv` (expect `STATE : 4 RUNNING`).

Always bring a kernel driver up in a VM first — a fault is a bugcheck, not an exception. For
deeper debugging, build `build.bat Debug` for `ProxyBridgeDrv:` traces in DebugView and enable
**Driver Verifier** on `ProxyBridgeDrv` for soak runs.

---

## Notes & limitations

- IPv4/TCP proxying and full connection logging are the primary supported path.
- UDP (DNS/QUIC via SOCKS5 UDP ASSOCIATE) and IPv6 are implemented and should be validated with
  real traffic before relying on them in production.
- The `ProxyBridgeDrv` service is installed on demand and left registered between runs; the
  ProxyBridge installer removes it on uninstall.
