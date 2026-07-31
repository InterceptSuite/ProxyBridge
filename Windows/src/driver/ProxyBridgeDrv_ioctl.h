/*
 * ProxyBridgeDrv_ioctl.h - shared user/kernel contract for the ProxyBridge WFP driver.
 *
 * Included by BOTH the kernel driver (ProxyBridgeDrv.c) and the user-mode ProxyBridge core.
 * Keep it free of anything kernel- or user-only so both sides see the same layout.
 */
#ifndef PBDRV_IOCTL_H
#define PBDRV_IOCTL_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// Device / symlink names.
#define PBDRV_DEVICE_NAME   L"\\Device\\ProxyBridgeDrv"
#define PBDRV_SYMLINK_NAME  L"\\DosDevices\\ProxyBridgeDrv"
#define PBDRV_USER_PATH     L"\\\\.\\ProxyBridgeDrv"     // CreateFile path from user mode

// IOCTLs (user -> driver).
#define PBDRV_IOCTL_SET_CONFIG    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define PBDRV_IOCTL_SET_WATCHLIST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define PBDRV_IOCTL_ENABLE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define PBDRV_IOCTL_DISABLE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
// UDP has no accept()/redirect-context per datagram, so the relay recovers a redirected
// UDP flow's original destination by querying the driver with the datagram's source.
#define PBDRV_IOCTL_QUERY_UDP     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_DATA)
// Drain the connection-event ring (one entry per outbound connect the monitor callout saw).
// Lets user mode log EVERY connection - direct/unwatched included - not just redirected ones.
#define PBDRV_IOCTL_POP_EVENTS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_READ_DATA)

#define PBDRV_MAX_WATCH 1024
#define PBDRV_NAME_LEN  260     // max image-file-name chars we match against (WCHAR)

#pragma pack(push, 1)

// The watch list: image file-name suffixes whose outbound connections the driver redirects
// to the relay. The GUI-managed proxy rules stay entirely in user mode; user mode derives
// this list from "which processes have any rule" and pushes it. L"*" means "redirect all".
// The driver does NO proxy/direct/block decision - the relay does, using the full rule engine.
typedef struct _PBDRV_WATCH_ENTRY {
    WCHAR image[PBDRV_NAME_LEN];   // case-insensitive file-name suffix, e.g. L"chrome.exe"
} PBDRV_WATCH_ENTRY;

typedef struct _PBDRV_WATCHLIST {
    UINT32            count;                     // number of valid entries[]
    PBDRV_WATCH_ENTRY entries[PBDRV_MAX_WATCH];
} PBDRV_WATCHLIST;

// Where the driver redirects matched flows - the user-mode relay's listeners.
// Addresses are network byte order; ports are host byte order.
typedef struct _PBDRV_CONFIG {
    UINT32 tcpV4Addr;   UINT16 tcpV4Port;   // local TCP relay (IPv4), e.g. 127.0.0.1:34010
    UINT8  tcpV6Addr[16]; UINT16 tcpV6Port; // local TCP relay (IPv6), e.g. [::1]:34010
    UINT32 udpV4Addr;   UINT16 udpV4Port;   // local UDP relay (IPv4)
    UINT8  udpV6Addr[16]; UINT16 udpV6Port; // local UDP relay (IPv6)
    UINT32 selfPid;                          // ProxyBridge's own PID - never redirected (relay -> upstream)
    UINT32 redirectLoopbackApps;             // 1 = also redirect apps talking to 127.x/::1 (MITM), 0 = leave loopback alone
    UINT32 redirectUdp;                      // 0 = leave UDP direct (TCP-only mode)
    UINT32 redirectIpv6;                     // 0 = leave IPv6 direct (IPv4-only mode)
} PBDRV_CONFIG;

// Attached to each redirect as localRedirectContext; the relay reads it back with
// WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT) to recover the true destination + PID.
// The relay then runs the full rule engine (proxy/direct/block, domains, per-config).
typedef struct _PBDRV_REDIRECT_CTX {
    UINT16 family;      // AF_INET / AF_INET6
    UINT8  protocol;    // IPPROTO_TCP / IPPROTO_UDP
    UINT8  _pad;
    UINT16 origPort;    // host byte order original destination port
    UINT16 _pad2;
    UINT32 origV4;      // network byte order (family == AF_INET)
    UINT8  origV6[16];  // family == AF_INET6
    UINT32 pid;         // owning process id
} PBDRV_REDIRECT_CTX;

// UDP original-destination query: in = the datagram's source (as the relay sees it),
// out (same struct) = the original destination the driver redirected it away from.
typedef struct _PBDRV_UDP_QUERY {
    UINT16 family;      // in/out: AF_INET / AF_INET6
    UINT8  found;       // out: 1 if a mapping existed
    UINT8  _pad;
    UINT16 srcPort;     // in: datagram source port (host order)
    UINT16 origPort;    // out: original destination port (host order)
    UINT32 srcV4;       // in: datagram source (network order, family AF_INET)
    UINT32 origV4;      // out: original destination (network order)
    UINT8  srcV6[16];   // in: family AF_INET6
    UINT8  origV6[16];  // out
    UINT32 pid;         // out
} PBDRV_UDP_QUERY;

// One observed outbound connection, reported by the monitor callout (ALE_AUTH_CONNECT) for
// EVERY app, redirected or not. The relay drains these (PBDRV_IOCTL_POP_EVENTS) and runs the
// rule engine to label each as Proxy/Direct/Blocked in the connection log. Redirected flows
// (dest already rewritten to the loopback relay) are skipped here - the relay logs those with
// the true destination from the redirect context, so there is no double counting.
#define PBDRV_EVENT_NAME_LEN 64   // in-kernel captured image basename (WCHAR)

typedef struct _PBDRV_EVENT {
    UINT16 family;      // AF_INET / AF_INET6
    UINT8  protocol;    // IPPROTO_TCP / IPPROTO_UDP
    UINT8  _pad;
    UINT16 remotePort;  // host byte order
    UINT16 _pad2;
    UINT32 remoteV4;    // network byte order (family == AF_INET)
    UINT8  remoteV6[16];// family == AF_INET6
    UINT32 pid;
    // Image basename captured in the kernel at connect time. Used as the process name when the
    // PID has already exited by the time user mode drains the event (short-lived processes), so
    // the log never shows "unknown". Null-terminated; empty if the app id wasn't available.
    WCHAR  image[PBDRV_EVENT_NAME_LEN];
} PBDRV_EVENT;

#pragma pack(pop)

#endif // PBDRV_IOCTL_H
