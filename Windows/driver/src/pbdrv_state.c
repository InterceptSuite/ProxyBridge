/*
 * pbdrv_state.c - UDP flow map, connection-event ring, and loopback helpers for ProxyBridgeDrv.
 * Self-contained: no dependency on the WFP engine, config, or GUIDs.
 */
#define NDIS_SUPPORT_NDIS6 1
#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)
#include "ProxyBridgeDrv_ioctl.h"
#include "pbdrv_state.h"

// UDP flow map: src endpoint -> original destination, so the relay can recover the dest
// of a redirected connectionless datagram (which carries no per-datagram redirect context).
#define UDP_MAP_SIZE 2048
typedef struct UDP_ENTRY {
    UINT16 family, srcPort, origPort;
    UINT32 srcV4, origV4;
    UINT8  srcV6[16], origV6[16];
    UINT32 pid;
    struct UDP_ENTRY *next;
} UDP_ENTRY;
static UDP_ENTRY  *gUdpMap[UDP_MAP_SIZE];
static EX_SPIN_LOCK gUdpLock;

// Connection-event ring: the monitor callout pushes one entry per observed outbound connect;
// user mode drains it (PBDRV_IOCTL_POP_EVENTS) to log every connection. Bounded; when full the
// oldest entry is dropped (logging is best-effort and must never stall the connect path).
#define PB_EVENT_RING 2048
static PBDRV_EVENT gEvents[PB_EVENT_RING];
static ULONG        gEvHead = 0;   // next slot to write
static ULONG        gEvTail = 0;   // next slot to read
static EX_SPIN_LOCK gEvLock;

void EventPush(UINT16 family, UINT8 proto, UINT32 v4, const UINT8 *v6, UINT16 port, UINT32 pid,
                      const WCHAR *image, ULONG imageChars)
{
    KIRQL old = ExAcquireSpinLockExclusive(&gEvLock);
    ULONG next = (gEvHead + 1) % PB_EVENT_RING;
    if (next == gEvTail) gEvTail = (gEvTail + 1) % PB_EVENT_RING;   // full -> drop oldest
    PBDRV_EVENT *e = &gEvents[gEvHead];
    RtlZeroMemory(e, sizeof(*e));
    e->family = family; e->protocol = proto;
    e->remotePort = port; e->remoteV4 = v4; e->pid = pid;
    if (v6) RtlCopyMemory(e->remoteV6, v6, 16);
    if (image != NULL && imageChars > 0) {
        ULONG n = (imageChars < PBDRV_EVENT_NAME_LEN - 1) ? imageChars : (PBDRV_EVENT_NAME_LEN - 1);
        RtlCopyMemory(e->image, image, n * sizeof(WCHAR));
        e->image[n] = 0;
    }
    gEvHead = next;
    ExReleaseSpinLockExclusive(&gEvLock, old);
}

// Point *outName/*outLen at the file-name portion (after the last backslash) of an image path.
void ImageBasename(const WCHAR *path, ULONG chars, const WCHAR **outName, ULONG *outLen)
{
    ULONG start = 0;
    for (ULONG i = 0; i < chars; i++) if (path[i] == L'\\') start = i + 1;
    *outName = path + start;
    *outLen  = chars - start;
}

ULONG EventPopMany(PBDRV_EVENT *out, ULONG maxCount)
{
    ULONG n = 0;
    KIRQL old = ExAcquireSpinLockExclusive(&gEvLock);
    while (n < maxCount && gEvTail != gEvHead) {
        out[n++] = gEvents[gEvTail];
        gEvTail = (gEvTail + 1) % PB_EVENT_RING;
    }
    ExReleaseSpinLockExclusive(&gEvLock, old);
    return n;
}

BOOLEAN IsLoopbackV4(UINT32 addrNbo)
{
    return ((addrNbo & 0x000000FF) == 0x0000007F);   // 127.0.0.0/8 (network byte order: first octet is low byte)
}

BOOLEAN IsLoopbackV6(const UINT8 a[16])
{
    static const UINT8 one[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return RtlEqualMemory(a, one, 16);
}

void UdpMapPut(UINT16 family, UINT32 srcV4, const UINT8 *srcV6, UINT16 srcPort,
                      UINT32 origV4, const UINT8 *origV6, UINT16 origPort, UINT32 pid)
{
    UINT32 h = (UINT32)srcPort % UDP_MAP_SIZE;
    KIRQL old = ExAcquireSpinLockExclusive(&gUdpLock);
    for (UDP_ENTRY *e = gUdpMap[h]; e != NULL; e = e->next) {
        if (e->srcPort == srcPort && e->family == family &&
            (family == AF_INET ? e->srcV4 == srcV4 : RtlEqualMemory(e->srcV6, srcV6, 16))) {
            e->origV4 = origV4; e->origPort = origPort; e->pid = pid;
            if (family == AF_INET6 && origV6) RtlCopyMemory(e->origV6, origV6, 16);
            ExReleaseSpinLockExclusive(&gUdpLock, old);
            return;
        }
    }
    UDP_ENTRY *e = (UDP_ENTRY *)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*e), PB_TAG);
    if (e != NULL) {
        RtlZeroMemory(e, sizeof(*e));
        e->family = family; e->srcPort = srcPort; e->origPort = origPort; e->pid = pid;
        e->srcV4 = srcV4; e->origV4 = origV4;
        if (srcV6)  RtlCopyMemory(e->srcV6,  srcV6,  16);
        if (origV6) RtlCopyMemory(e->origV6, origV6, 16);
        e->next = gUdpMap[h];
        gUdpMap[h] = e;
    }
    ExReleaseSpinLockExclusive(&gUdpLock, old);
}

BOOLEAN UdpMapGet(PBDRV_UDP_QUERY *q)
{
    UINT32 h = (UINT32)q->srcPort % UDP_MAP_SIZE;
    BOOLEAN found = FALSE;
    KIRQL old = ExAcquireSpinLockShared(&gUdpLock);
    for (UDP_ENTRY *e = gUdpMap[h]; e != NULL; e = e->next) {
        if (e->srcPort == q->srcPort && e->family == q->family &&
            (q->family == AF_INET ? e->srcV4 == q->srcV4 : RtlEqualMemory(e->srcV6, q->srcV6, 16))) {
            q->origV4 = e->origV4; q->origPort = e->origPort; q->pid = e->pid;
            RtlCopyMemory(q->origV6, e->origV6, 16);
            found = TRUE;
            break;
        }
    }
    ExReleaseSpinLockShared(&gUdpLock, old);
    return found;
}

void UdpMapClear(void)
{
    KIRQL old = ExAcquireSpinLockExclusive(&gUdpLock);
    for (int i = 0; i < UDP_MAP_SIZE; i++) {
        while (gUdpMap[i] != NULL) { UDP_ENTRY *e = gUdpMap[i]; gUdpMap[i] = e->next; ExFreePoolWithTag(e, PB_TAG); }
    }
    ExReleaseSpinLockExclusive(&gUdpLock, old);
}
