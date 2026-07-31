/*
 * pbdrv_state.h - shared kernel state for the ProxyBridge driver: the UDP flow map, the
 * connection-event ring, and small address helpers. Implemented in pbdrv_state.c; used by
 * the main driver TU (IOCTL dispatch, unload) and the WFP callouts.
 */
#ifndef PBDRV_STATE_H
#define PBDRV_STATE_H

#include <ntddk.h>
#include "ProxyBridgeDrv_ioctl.h"

#define PB_TAG 'pfBP'   // 'PBfp' pool tag

// UDP flow map: src endpoint -> original destination, so the relay can recover the dest of a
// redirected connectionless datagram (which carries no per-datagram redirect context).
void    UdpMapPut(UINT16 family, UINT32 srcV4, const UINT8 *srcV6, UINT16 srcPort,
                  UINT32 origV4, const UINT8 *origV6, UINT16 origPort, UINT32 pid);
BOOLEAN UdpMapGet(PBDRV_UDP_QUERY *q);
void    UdpMapClear(void);

// Connection-event ring: the monitor callout pushes one entry per observed outbound connect;
// user mode drains it via PBDRV_IOCTL_POP_EVENTS. Bounded; oldest entry dropped when full.
void  EventPush(UINT16 family, UINT8 proto, UINT32 v4, const UINT8 *v6, UINT16 port, UINT32 pid,
                const WCHAR *image, ULONG imageChars);
ULONG EventPopMany(PBDRV_EVENT *out, ULONG maxCount);
void  ImageBasename(const WCHAR *path, ULONG chars, const WCHAR **outName, ULONG *outLen);

// Loopback address checks.
BOOLEAN IsLoopbackV4(UINT32 addrNbo);
BOOLEAN IsLoopbackV6(const UINT8 a[16]);

#endif // PBDRV_STATE_H
