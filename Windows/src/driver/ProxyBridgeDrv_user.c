/*
 * ProxyBridgeDrv_user.c - user-mode glue between ProxyBridge and the WFP driver.
 *
 * Two jobs:
 *   1) push config + watch list to the driver over IOCTL (pbdrv_configure / pbdrv_set_watchlist);
 *   2) recover the ORIGINAL destination of a redirected connection on the relay's
 *      accepted socket (pbdrv_get_original_dest), replacing the source-port lookup.
 *
 * This is drop-in for the existing relay: after accept(), call pbdrv_get_original_dest()
 * instead of get_connection_full(client_port, ...). No packet mangling, no correlation.
 *
 * Link with ws2_32 and fwpuclnt is NOT required for the query path (it is a plain WSAIoctl).
 */
#include <winsock2.h>
#include <ws2ipdef.h>
#include <mstcpip.h>       // SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / _CONTEXT
#include <ws2tcpip.h>
#include "ProxyBridgeDrv_ioctl.h"

// ---- driver handle / config ------------------------------------------------

HANDLE pbdrv_open(void)
{
    return CreateFileW(PBDRV_USER_PATH, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

BOOL pbdrv_configure(HANDLE h, const PBDRV_CONFIG *cfg)
{
    DWORD ret = 0;
    return DeviceIoControl(h, PBDRV_IOCTL_SET_CONFIG, (LPVOID)cfg, sizeof(*cfg), NULL, 0, &ret, NULL);
}

// Push the watch list (image-name suffixes to redirect). User mode derives this from the
// GUI rules ("which processes have any rule"); the proxy/direct/block decision stays in
// the relay's rule engine, not the driver.
BOOL pbdrv_set_watchlist(HANDLE h, const PBDRV_WATCHLIST *wl)
{
    DWORD ret = 0;
    DWORD len = (DWORD)(FIELD_OFFSET(PBDRV_WATCHLIST, entries) + (SIZE_T)wl->count * sizeof(PBDRV_WATCH_ENTRY));
    return DeviceIoControl(h, PBDRV_IOCTL_SET_WATCHLIST, (LPVOID)wl, len, NULL, 0, &ret, NULL);
}

BOOL pbdrv_enable(HANDLE h, BOOL on)
{
    DWORD ret = 0;
    return DeviceIoControl(h, on ? PBDRV_IOCTL_ENABLE : PBDRV_IOCTL_DISABLE, NULL, 0, NULL, 0, &ret, NULL);
}

// Query a redirected UDP flow's original destination by its source endpoint (in/out `q`).
BOOL pbdrv_udp_query(HANDLE h, PBDRV_UDP_QUERY *q)
{
    DWORD ret = 0;
    return DeviceIoControl(h, PBDRV_IOCTL_QUERY_UDP, q, sizeof(*q), q, sizeof(*q), &ret, NULL) && ret >= sizeof(*q);
}

// Drain the driver's connection-event ring into buf[0..maxCount). Returns the count via *got.
// Each event is one outbound connect the monitor callout observed (for the connection log).
BOOL pbdrv_pop_events(HANDLE h, PBDRV_EVENT *buf, DWORD maxCount, DWORD *got)
{
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(h, PBDRV_IOCTL_POP_EVENTS, NULL, 0,
                              buf, maxCount * (DWORD)sizeof(PBDRV_EVENT), &ret, NULL);
    *got = ok ? (ret / (DWORD)sizeof(PBDRV_EVENT)) : 0;
    return ok;
}

// ---- recover the original destination on a redirected socket ---------------
//
// `accepted` is the socket returned by accept() on the relay listener. On success,
// *ctx is filled with the true destination (and family/protocol/pid) the driver stashed.
BOOL pbdrv_get_original_dest(SOCKET accepted, PBDRV_REDIRECT_CTX *ctx)
{
    DWORD bytes = 0;
    // The driver set this via req->localRedirectContext; WFP returns it verbatim here.
    if (WSAIoctl(accepted, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, NULL, 0,
                 ctx, sizeof(*ctx), &bytes, NULL, NULL) == 0 && bytes >= sizeof(*ctx))
        return TRUE;
    return FALSE;
}

// For UDP: the relay's UDP socket receives redirected datagrams. Use
// SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS on the socket, or associate the per-datagram
// endpoint the same way; the driver's context carries the original dest either way.
// (Reply datagrams the relay sends back are un-redirected by WFP to appear from the
//  original destination, so the app's recvfrom() sees the expected source.)
