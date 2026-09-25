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
#define UDP_MAP_MAX_ENTRIES 4096 // bounded pool use; never evict an existing mapping
typedef struct UDP_ENTRY {
    UINT16 family, srcPort, origPort;
    UINT32 srcV4, origV4;
    UINT8  srcV6[16], origV6[16];
    UINT32 pid;
    UINT64 endpoint;
    UINT64 generation;
    struct UDP_ENTRY *endpointNext;
    struct UDP_ENTRY *next;
} UDP_ENTRY;
static UDP_ENTRY  *gUdpMap[UDP_MAP_SIZE];
static EX_SPIN_LOCK gUdpLock;
static UINT32 gUdpCount;
static UDP_ENTRY *gUdpEndpoints[UDP_MAP_SIZE];
static UINT64 gUdpGeneration;
static volatile LONG gUdpAdmissionFailed;

BOOLEAN UdpMapHadFailure(void)
{
    return InterlockedCompareExchange(&gUdpAdmissionFailed, 0, 0) != 0;
}

// Connection-event ring: the monitor callout pushes one entry per observed outbound connect;
// user mode drains it (PBDRV_IOCTL_POP_EVENTS) to log every connection. Bounded; when full the
// oldest entry is dropped (logging is best-effort and must never stall the connect path).
#define PB_EVENT_RING 2048
static PBDRV_EVENT gEvents[PB_EVENT_RING];
static ULONG        gEvHead = 0;   // next slot to write
static ULONG        gEvTail = 0;   // next slot to read
static EX_SPIN_LOCK gEvLock;

void EventClear(void)
{
    KIRQL old = ExAcquireSpinLockExclusive(&gEvLock);
    gEvHead = gEvTail = 0;
    ExReleaseSpinLockExclusive(&gEvLock, old);
}

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

static UINT32 UdpEndpointBucket(UINT64 endpoint)
{
    return (UINT32)(endpoint ^ (endpoint >> 32)) % UDP_MAP_SIZE;
}

BOOLEAN UdpMapPut(UINT64 endpoint, UINT16 family, UINT32 srcV4, const UINT8 *srcV6, UINT16 srcPort,
                  UINT32 origV4, const UINT8 *origV6, UINT16 origPort, UINT32 pid)
{
    if (endpoint == 0) { InterlockedExchange(&gUdpAdmissionFailed, TRUE); return FALSE; }
    UINT32 h = (UINT32)srcPort % UDP_MAP_SIZE;
    KIRQL old = ExAcquireSpinLockExclusive(&gUdpLock);
    for (UDP_ENTRY *e = gUdpMap[h]; e != NULL; e = e->next) {
        if (e->srcPort == srcPort && e->family == family &&
            (family == AF_INET ? e->srcV4 == srcV4 : RtlEqualMemory(e->srcV6, srcV6, 16))) {
            // Reauthorization is idempotent. Never overwrite another live endpoint
            // or a different destination: queued datagrams cannot be distinguished.
            BOOLEAN same = e->endpoint == endpoint && e->pid == pid && e->origPort == origPort &&
                (family == AF_INET ? e->origV4 == origV4 : RtlEqualMemory(e->origV6, origV6, 16));
            ExReleaseSpinLockExclusive(&gUdpLock, old);
            if (!same) InterlockedExchange(&gUdpAdmissionFailed, TRUE);
            return same;
        }
    }
    if (gUdpCount >= UDP_MAP_MAX_ENTRIES || gUdpGeneration == ~(UINT64)0) {
        ExReleaseSpinLockExclusive(&gUdpLock, old);
        InterlockedExchange(&gUdpAdmissionFailed, TRUE);
        return FALSE;
    }
    UDP_ENTRY *e = (UDP_ENTRY *)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*e), PB_TAG);
    BOOLEAN inserted = e != NULL;
    if (e != NULL) {
        RtlZeroMemory(e, sizeof(*e));
        e->family = family; e->srcPort = srcPort; e->origPort = origPort; e->pid = pid;
        e->srcV4 = srcV4; e->origV4 = origV4;
        if (srcV6) RtlCopyMemory(e->srcV6, srcV6, 16);
        if (origV6) RtlCopyMemory(e->origV6, origV6, 16);
        e->endpoint = endpoint;
        e->generation = ++gUdpGeneration;
        e->next = gUdpMap[h]; gUdpMap[h] = e;
        UINT32 eh = UdpEndpointBucket(endpoint);
        e->endpointNext = gUdpEndpoints[eh]; gUdpEndpoints[eh] = e;
        ++gUdpCount;
    }
    ExReleaseSpinLockExclusive(&gUdpLock, old);
    if (!inserted) InterlockedExchange(&gUdpAdmissionFailed, TRUE);
    return inserted;
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
            q->mappingGeneration = e->generation;
            RtlCopyMemory(q->origV6, e->origV6, 16);
            found = TRUE;
            break;
        }
    }
    ExReleaseSpinLockShared(&gUdpLock, old);
    return found;
}

void UdpMapRemoveEndpoint(UINT64 endpoint)
{
    UDP_ENTRY *retired = NULL;
    KIRQL old = ExAcquireSpinLockExclusive(&gUdpLock);
    UDP_ENTRY **link = &gUdpEndpoints[UdpEndpointBucket(endpoint)];
    while (*link != NULL) {
        UDP_ENTRY *e = *link;
        if (e->endpoint != endpoint) { link = &e->endpointNext; continue; }
        *link = e->endpointNext;
        UDP_ENTRY **source = &gUdpMap[e->srcPort % UDP_MAP_SIZE];
        while (*source != e) source = &(*source)->next;
        *source = e->next;
        --gUdpCount;
        e->next = retired; retired = e;
    }
    ExReleaseSpinLockExclusive(&gUdpLock, old);
    while (retired != NULL) {
        UDP_ENTRY *e = retired; retired = e->next;
        ExFreePoolWithTag(e, PB_TAG);
    }
}

void UdpMapClear(void)
{
    UDP_ENTRY *retired = NULL;
    KIRQL old = ExAcquireSpinLockExclusive(&gUdpLock);
    for (int i = 0; i < UDP_MAP_SIZE; ++i) {
        while (gUdpMap[i] != NULL) {
            UDP_ENTRY *e = gUdpMap[i]; gUdpMap[i] = e->next;
            e->next = retired; retired = e;
        }
        gUdpEndpoints[i] = NULL;
    }
    gUdpCount = 0; // generation never reused during this driver load
    InterlockedExchange(&gUdpAdmissionFailed, FALSE);
    ExReleaseSpinLockExclusive(&gUdpLock, old);
    while (retired != NULL) {
        UDP_ENTRY *e = retired; retired = e->next;
        ExFreePoolWithTag(e, PB_TAG);
    }
}
