/*
 * ProxyBridgeDrv_user.h - user-mode API for talking to the ProxyBridge WFP driver.
 * Include from the ProxyBridge core; link ProxyBridgeDrv_user.c.
 */
#ifndef PBDRV_USER_H
#define PBDRV_USER_H

#include <winsock2.h>
#include "ProxyBridgeDrv_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

// Open \\.\ProxyBridgeDrv. Returns INVALID_HANDLE_VALUE if the driver isn't running.
HANDLE pbdrv_open(void);

// Push relay endpoints + selfPid (config) and the process watch list to the driver.
BOOL pbdrv_configure(HANDLE h, const PBDRV_CONFIG *cfg);
BOOL pbdrv_set_watchlist(HANDLE h, const PBDRV_WATCHLIST *wl);

// Arm / disarm redirection.
BOOL pbdrv_enable(HANDLE h, BOOL on);

// Recover a redirected UDP flow's original destination (fill q->family/src* first).
BOOL pbdrv_udp_query(HANDLE h, PBDRV_UDP_QUERY *q);

// Drain observed connection events for the log. *got receives the number returned.
BOOL pbdrv_pop_events(HANDLE h, PBDRV_EVENT *buf, DWORD maxCount, DWORD *got);

// On a socket returned by accept() on the relay listener, recover the original
// destination the driver redirected away from. Drop-in for get_connection_full().
BOOL pbdrv_get_original_dest(SOCKET accepted, PBDRV_REDIRECT_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif // PBDRV_USER_H
