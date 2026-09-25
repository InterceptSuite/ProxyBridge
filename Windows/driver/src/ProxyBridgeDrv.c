/*
 * ProxyBridgeDrv.c - ProxyBridge WFP connect-redirect callout driver.
 *
 * Redirects outbound connections of watched processes to the user-mode relay at the
 * ALE_CONNECT_REDIRECT layer (one layer covers TCP+UDP; two callouts cover IPv4+IPv6), and
 * observes every connect at ALE_AUTH_CONNECT for the connection log. The relay recovers the
 * original destination from the redirect context - no packet mangling, PID delivered by WFP.
 * WFP and IOCTL payloads live here; KMDF lifecycle lives in pbdrv_device.c.
 */

#include <initguid.h>   // must precede includes so DEFINE_GUID allocates the GUID bytes

// fwpsk.h needs an NDIS version and pulls in ndis.h/ws2def.h/ws2ipdef.h - don't include those first.
#define NDIS_SUPPORT_NDIS6 1
#include <ntddk.h>
#include "pbdrv_device.h"
#pragma warning(push)
#pragma warning(disable: 4201)   // nameless struct/union in WFP headers
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)

#include "ProxyBridgeDrv_ioctl.h"
#include "pbdrv_state.h"

// Diagnostics: DebugView/WinDbg only in checked (DBG) builds; compiled out of Release.
#if DBG
#define PBTRACE(fmt, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "ProxyBridgeDrv: " fmt "\n", __VA_ARGS__)
#else
#define PBTRACE(fmt, ...) ((void)0)
#endif

// GUIDs (fixed + unique to this driver). Regenerate if you fork it.
DEFINE_GUID(PB_PROVIDER_GUID,      0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x01);
DEFINE_GUID(PB_SUBLAYER_GUID,      0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x02);
DEFINE_GUID(PB_CALLOUT_V4_GUID,    0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x03);  // redirect v4
DEFINE_GUID(PB_CALLOUT_V6_GUID,    0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x04);  // redirect v6
DEFINE_GUID(PB_MON_CALLOUT_V4_GUID,0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x05);  // monitor v4
DEFINE_GUID(PB_MON_CALLOUT_V6_GUID,0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x06);  // monitor v6

DEFINE_GUID(PB_CLOSE_V4_GUID,0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x09);
DEFINE_GUID(PB_CLOSE_V6_GUID,0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x0a);

// ---- Globals ----
static HANDLE      gEngine       = NULL;             // WFP engine session
static HANDLE      gRedirect     = NULL;             // shared redirect handle (loop detection)
// Native reference, independent of the KMDF context. A failed final teardown
// must not let PnP delete the FDO and unload code still registered with WFP.
static PDEVICE_OBJECT gWfpDeviceReference = NULL;
static UINT32 gCloseV4Id, gCloseV6Id;
static UINT64 gCloseFilterV4Id, gCloseFilterV6Id;
static UINT32      gCalloutV4Id  = 0;
static UINT32      gCalloutV6Id  = 0;
static UINT64      gFilterV4Id    = 0;
static UINT64      gFilterV6Id    = 0;
static UINT32      gMonCalloutV4Id = 0;
static UINT32      gMonCalloutV6Id = 0;
static UINT64      gMonFilterV4Id  = 0;
static UINT64      gMonFilterV6Id  = 0;


static EX_SPIN_LOCK  gCfgLock;                        // guards gConfig / gWatch
static PBDRV_CONFIG  gConfig;                         // redirect targets + exclusions
static PBDRV_WATCHLIST *gWatch   = NULL;             // heap copy of the process watch list
static volatile LONG gEnabled    = 0;                // 0 until user mode enables
static BOOLEAN gConfigured = FALSE;                 // guarded by gCfgLock
static UINT32 gWatchRevision = 0;                    // guarded by gCfgLock
static NTSTATUS gLastActivationStatus = STATUS_SUCCESS;

// Case-insensitive check: does `path` end with `suffix` (both null-terminated WCHAR)?
static BOOLEAN EndsWithI(const WCHAR *path, ULONG pathChars, const WCHAR *suffix)
{
    ULONG sl = 0;
    while (sl < PBDRV_NAME_LEN && suffix[sl] != L'\0') {
        sl++;
    }
    if (sl == 0 || sl > pathChars) return FALSE;
    const WCHAR *p = path + (pathChars - sl);
    for (ULONG i = 0; i < sl; i++) {
        WCHAR a = p[i], b = suffix[i];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
        if (a != b) return FALSE;
    }
    return TRUE;
}

// Is the connecting app on the watch list? If so its flows are redirected to the relay,
// which makes the actual proxy/direct/block decision. L"*" watches everything.
static BOOLEAN SnapshotPolicy(const WCHAR *imagePath, ULONG imageChars,
    UINT32 pid, UINT8 protocol, ADDRESS_FAMILY family, PBDRV_CONFIG *config)
{
    BOOLEAN watched = FALSE;
    KIRQL old = ExAcquireSpinLockShared(&gCfgLock);
    *config = gConfig;
    BOOLEAN eligible = (pid == 0 || pid != config->selfPid) &&
        (protocol != IPPROTO_UDP || config->redirectUdp) &&
        (family != AF_INET6 || config->redirectIpv6);
    if (eligible && gWatch != NULL) {
        for (UINT32 i = 0; i < gWatch->count; i++) {
            const WCHAR *name = gWatch->entries[i].image;
            if (name[0] == L'*' && name[1] == 0) { watched = TRUE; break; }
            if (imagePath && EndsWithI(imagePath, imageChars, name)) { watched = TRUE; break; }
        }
    }
    ExReleaseSpinLockShared(&gCfgLock, old);
    return watched;
}

static void ClassifyCore(
    ADDRESS_FAMILY family,
    const FWPS_INCOMING_VALUES0     *inFixed,
    const FWPS_INCOMING_METADATA_VALUES0 *inMeta,
    void                            *layerData,
    const void                      *classifyContext,
    const FWPS_FILTER1             *filter,
    FWPS_CLASSIFY_OUT0             *classifyOut,
    UINT32 idxProto, UINT32 idxAppId)
{
    UNREFERENCED_PARAMETER(layerData);

    classifyOut->actionType = FWP_ACTION_PERMIT;     // default: never break connectivity
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    if (InterlockedCompareExchange(&gEnabled, 1, 1) == 0) return;

    // Loop prevention: skip a flow we already redirected (the relay->upstream re-entry).
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        FWPS_CONNECTION_REDIRECT_STATE st =
            FwpsQueryConnectionRedirectState0(inMeta->redirectRecords, gRedirect, NULL);
        if (st == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
            st == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF)
            return;
    }

    if (inFixed->incomingValue[idxProto].value.type != FWP_UINT8) return;
    UINT8 protocol = inFixed->incomingValue[idxProto].value.uint8;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return;

    UINT32 pid = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_PROCESS_ID))
        pid = (UINT32)inMeta->processId;

    // Application image path (kernel device path), matched against the watch list.
    const WCHAR *imagePath = NULL; ULONG imageChars = 0;
    if (inFixed->incomingValue[idxAppId].value.type == FWP_BYTE_BLOB_TYPE) {
        FWP_BYTE_BLOB *blob = inFixed->incomingValue[idxAppId].value.byteBlob;
        if (blob && blob->data && blob->size >= sizeof(WCHAR)) {
            imagePath  = (const WCHAR *)blob->data;
            imageChars = (ULONG)(blob->size / sizeof(WCHAR));
            while (imageChars > 0 && imagePath[imageChars - 1] == 0) imageChars--; // trim trailing NUL(s)
        }
    }

    // Read config and watch membership from the same published policy.
    PBDRV_CONFIG cfg;
    if (!SnapshotPolicy(imagePath, imageChars, pid, protocol, family, &cfg))
        return;                                       // not a ruled process -> direct, in kernel

    // Watched -> redirect the connection to the relay; the relay decides proxy/direct/block.
    UINT64 classifyHandle = 0;   // FwpsAcquireClassifyHandle0 takes UINT64*, not HANDLE
    NTSTATUS status = FwpsAcquireClassifyHandle0((void *)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) return;

    FWPS_CONNECT_REQUEST0 *req = NULL;
    status = FwpsAcquireWritableLayerDataPointer0(classifyHandle, filter->filterId, 0, (PVOID *)&req, classifyOut);
    if (!NT_SUCCESS(status) || req == NULL) { FwpsReleaseClassifyHandle0(classifyHandle); return; }

    // Leave loopback destinations direct unless redirectLoopbackApps is set (Localhost via Proxy).
    if (!cfg.redirectLoopbackApps) {
        BOOLEAN lb = (family == AF_INET)
            ? IsLoopbackV4(((PSOCKADDR_IN)&req->remoteAddressAndPort)->sin_addr.S_un.S_addr)
            : IsLoopbackV6((const UINT8 *)&((PSOCKADDR_IN6)&req->remoteAddressAndPort)->sin6_addr);
        if (lb) {
            FwpsApplyModifiedLayerData0(classifyHandle, req, 0);
            FwpsReleaseClassifyHandle0(classifyHandle);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    }

    // Capture the ORIGINAL destination (still in req->remoteAddressAndPort) into a context the
    // relay reads back via SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT.
    PBDRV_REDIRECT_CTX *ctx = (PBDRV_REDIRECT_CTX *)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*ctx), PB_TAG);
    if (ctx == NULL) {
        FwpsApplyModifiedLayerData0(classifyHandle, req, 0);
        FwpsReleaseClassifyHandle0(classifyHandle);
        classifyOut->actionType = FWP_ACTION_BLOCK;
        return;
    }
    if (ctx != NULL) {
        ctx->family = family; ctx->protocol = protocol; ctx->pid = pid;
        if (family == AF_INET) {
            PSOCKADDR_IN o = (PSOCKADDR_IN)&req->remoteAddressAndPort;
            ctx->origV4   = o->sin_addr.S_un.S_addr;             // network order
            ctx->origPort = RtlUshortByteSwap(o->sin_port);      // -> host order
        } else {
            PSOCKADDR_IN6 o = (PSOCKADDR_IN6)&req->remoteAddressAndPort;
            RtlCopyMemory(ctx->origV6, &o->sin6_addr, 16);
            ctx->origPort = RtlUshortByteSwap(o->sin6_port);
        }
    }

    // UDP carries no per-datagram redirect context: record src -> orig-dest for the relay to query.
    // The local address/port is left unmodified (changing it is unsupported at this layer).
    if (protocol == IPPROTO_UDP && ctx != NULL) {
        UINT64 endpoint = FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE)
            ? inMeta->transportEndpointHandle : 0;
        BOOLEAN mapped;
        if (family == AF_INET) {
            PSOCKADDR_IN l = (PSOCKADDR_IN)&req->localAddressAndPort;
            mapped = UdpMapPut(endpoint, AF_INET, l->sin_addr.S_un.S_addr, NULL, RtlUshortByteSwap(l->sin_port),
                      ctx->origV4, NULL, ctx->origPort, pid);
        } else {
            PSOCKADDR_IN6 l = (PSOCKADDR_IN6)&req->localAddressAndPort;
            mapped = UdpMapPut(endpoint, AF_INET6, 0, (const UINT8 *)&l->sin6_addr, RtlUshortByteSwap(l->sin6_port),
                      0, ctx->origV6, ctx->origPort, pid);
        }
        if (!mapped) {
            // No safe mapping: finish writable data unchanged, then reject this attempt.
            ExFreePoolWithTag(ctx, PB_TAG);
            FwpsApplyModifiedLayerData0(classifyHandle, req, 0);
            FwpsReleaseClassifyHandle0(classifyHandle);
            classifyOut->actionType = FWP_ACTION_BLOCK;
            return;
        }
    }

    // Rewrite the destination to the local relay (MS connect-redirect sample): target loopback
    // only when the app has no bound local address, else its own local address, to avoid crossing
    // TCP/IP zones. localRedirectTargetPID is REQUIRED for a valid loopback redirect (docs).
    static const UINT8 kLoopV6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const UINT8 kAnyV6[16]  = {0};
    UINT16 relayPortNet = RtlUshortByteSwap((protocol == IPPROTO_UDP)
                            ? (family == AF_INET ? cfg.udpV4Port : cfg.udpV6Port)
                            : (family == AF_INET ? cfg.tcpV4Port : cfg.tcpV6Port));
    if (family == AF_INET) {
        PSOCKADDR_IN r = (PSOCKADDR_IN)&req->remoteAddressAndPort;
        PSOCKADDR_IN l = (PSOCKADDR_IN)&req->localAddressAndPort;
        r->sin_family = AF_INET;
        r->sin_addr.S_un.S_addr = (l->sin_addr.S_un.S_addr == 0) ? cfg.tcpV4Addr /*127.0.0.1*/
                                                                 : l->sin_addr.S_un.S_addr;
        r->sin_port = relayPortNet;
    } else {
        PSOCKADDR_IN6 r = (PSOCKADDR_IN6)&req->remoteAddressAndPort;
        PSOCKADDR_IN6 l = (PSOCKADDR_IN6)&req->localAddressAndPort;
        r->sin6_family = AF_INET6;
        if (RtlEqualMemory(&l->sin6_addr, kAnyV6, 16)) RtlCopyMemory(&r->sin6_addr, kLoopV6, 16);  // ::1
        else                                           RtlCopyMemory(&r->sin6_addr, &l->sin6_addr, 16);
        r->sin6_port = relayPortNet;
    }
    req->localRedirectHandle      = gRedirect;
    req->localRedirectTargetPID   = cfg.selfPid;   // REQUIRED: process handling the redirected flow
    req->localRedirectContext     = ctx;
    req->localRedirectContextSize = ctx ? sizeof(*ctx) : 0;

    FwpsApplyModifiedLayerData0(classifyHandle, req, 0);   // returns void
    FwpsReleaseClassifyHandle0(classifyHandle);
    // Do NOT free ctx: once applied, WFP owns localRedirectContext and frees it when the redirect
    // record is torn down. Freeing it too is a double-free -> BugCheck 0x13A (heap corruption).

    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

// classifyFn v1: carries `classifyContext`, which connect-redirect needs for FwpsAcquireClassifyHandle0.
static void NTAPI ClassifyV4(
    const FWPS_INCOMING_VALUES0 *inFixed, const FWPS_INCOMING_METADATA_VALUES0 *inMeta,
    void *layerData, const void *classifyContext, const FWPS_FILTER1 *filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNREFERENCED_PARAMETER(flowContext);
    ClassifyCore(AF_INET, inFixed, inMeta, layerData, classifyContext, filter, classifyOut,
                 FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL,
                 FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID);
}

static void NTAPI ClassifyV6(
    const FWPS_INCOMING_VALUES0 *inFixed, const FWPS_INCOMING_METADATA_VALUES0 *inMeta,
    void *layerData, const void *classifyContext, const FWPS_FILTER1 *filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNREFERENCED_PARAMETER(flowContext);
    ClassifyCore(AF_INET6, inFixed, inMeta, layerData, classifyContext, filter, classifyOut,
                 FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL,
                 FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID);
}

static NTSTATUS NTAPI NotifyFn(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *key, FWPS_FILTER1 *filter)
{
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

// Monitor (ALE_AUTH_CONNECT): log every outbound connect; pure inspection, never changes the
// verdict. Only flows we redirected are skipped (the relay logs those with the true dest).
static void MonitorCore(
    ADDRESS_FAMILY family,
    const FWPS_INCOMING_VALUES0 *inFixed,
    const FWPS_INCOMING_METADATA_VALUES0 *inMeta,
    FWPS_CLASSIFY_OUT0 *classifyOut,
    UINT32 idxProto, UINT32 idxRemoteAddr, UINT32 idxRemotePort, UINT32 idxAppId)
{
    classifyOut->actionType = FWP_ACTION_CONTINUE;   // inspection: pass through untouched
    if (InterlockedCompareExchange(&gEnabled, 1, 1) == 0) return;

    if (inFixed->incomingValue[idxProto].value.type != FWP_UINT8) return;
    UINT8 protocol = inFixed->incomingValue[idxProto].value.uint8;
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) return;

    UINT32 pid = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_PROCESS_ID))
        pid = (UINT32)inMeta->processId;
    KIRQL cfgIrql = ExAcquireSpinLockShared(&gCfgLock);
    UINT32 selfPid = gConfig.selfPid;
    ExReleaseSpinLockShared(&gCfgLock, cfgIrql);
    if (pid != 0 && pid == selfPid) return;   // skip the relay's own sockets

    // Skip only the flows WE redirected (detected by the redirect handle, not by loopback
    // address) - the relay logs those with the true dest, and genuine app->127.x still logs.
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        FWPS_CONNECTION_REDIRECT_STATE st =
            FwpsQueryConnectionRedirectState0(inMeta->redirectRecords, gRedirect, NULL);
        if (st == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
            st == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF)
            return;
    }

    UINT16 port = inFixed->incomingValue[idxRemotePort].value.uint16;   // host order

    // Capture the image basename now (the PID may be gone by the time user mode drains this).
    const WCHAR *img = NULL; ULONG imgChars = 0;
    if (inFixed->incomingValue[idxAppId].value.type == FWP_BYTE_BLOB_TYPE) {
        FWP_BYTE_BLOB *blob = inFixed->incomingValue[idxAppId].value.byteBlob;
        if (blob && blob->data && blob->size >= sizeof(WCHAR)) {
            const WCHAR *full = (const WCHAR *)blob->data;
            ULONG fullChars = (ULONG)(blob->size / sizeof(WCHAR));
            while (fullChars > 0 && full[fullChars - 1] == 0) fullChars--;
            ImageBasename(full, fullChars, &img, &imgChars);
        }
    }

    if (family == AF_INET) {
        UINT32 hostAddr = inFixed->incomingValue[idxRemoteAddr].value.uint32;   // host order
        EventPush(AF_INET, protocol, RtlUlongByteSwap(hostAddr), NULL, port, pid, img, imgChars);  // net order
    } else {
        FWP_BYTE_ARRAY16 *b16 = inFixed->incomingValue[idxRemoteAddr].value.byteArray16;
        if (inFixed->incomingValue[idxRemoteAddr].value.type != FWP_BYTE_ARRAY16_TYPE || b16 == NULL) return;
        EventPush(AF_INET6, protocol, 0, (const UINT8 *)b16->byteArray16, port, pid, img, imgChars);
    }
}

static void NTAPI MonitorV4(
    const FWPS_INCOMING_VALUES0 *inFixed, const FWPS_INCOMING_METADATA_VALUES0 *inMeta,
    void *layerData, const void *classifyContext, const FWPS_FILTER1 *filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNREFERENCED_PARAMETER(layerData); UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);    UNREFERENCED_PARAMETER(flowContext);
    MonitorCore(AF_INET, inFixed, inMeta, classifyOut,
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
                FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID);
}

static void NTAPI MonitorV6(
    const FWPS_INCOMING_VALUES0 *inFixed, const FWPS_INCOMING_METADATA_VALUES0 *inMeta,
    void *layerData, const void *classifyContext, const FWPS_FILTER1 *filter,
    UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNREFERENCED_PARAMETER(layerData); UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);    UNREFERENCED_PARAMETER(flowContext);
    MonitorCore(AF_INET6, inFixed, inMeta, classifyOut,
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL,
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
                FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID);
}

// ---- WFP registration ----
static void NTAPI EndpointClosed(const FWPS_INCOMING_VALUES0 *values,
    const FWPS_INCOMING_METADATA_VALUES0 *meta, void *layerData, const void *classifyContext,
    const FWPS_FILTER1 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *out)
{
    UNREFERENCED_PARAMETER(values); UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext); UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    if (FWPS_IS_METADATA_FIELD_PRESENT(meta, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE))
        UdpMapRemoveEndpoint(meta->transportEndpointHandle);
    if (out->rights & FWPS_RIGHT_ACTION_WRITE) out->actionType = FWP_ACTION_CONTINUE;
}

static NTSTATUS AddCallout(PDEVICE_OBJECT dev, const GUID *calloutKey, const GUID *layerKey,
                           FWPS_CALLOUT_CLASSIFY_FN1 fn, UINT32 *outId, UINT64 *outFilterId)
{
    FWPS_CALLOUT1 sCallout = {0};
    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = fn;
    sCallout.notifyFn   = NotifyFn;
    NTSTATUS status = FwpsCalloutRegister1(dev, &sCallout, outId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT0 mCallout = {0};
    mCallout.calloutKey        = *calloutKey;
    mCallout.displayData.name  = L"ProxyBridge Connect-Redirect";
    mCallout.providerKey       = (GUID *)&PB_PROVIDER_GUID;
    mCallout.applicableLayer   = *layerKey;
    status = FwpmCalloutAdd0(gEngine, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    FWPM_FILTER0 filter = {0};
    filter.displayData.name = L"ProxyBridge Redirect Filter";
    filter.layerKey         = *layerKey;
    filter.subLayerKey      = PB_SUBLAYER_GUID;
    filter.providerKey      = (GUID *)&PB_PROVIDER_GUID;
    filter.weight.type      = FWP_EMPTY;              // auto weight
    filter.numFilterConditions = 0;                  // all outbound connects; we filter in classify
    filter.action.type      = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = *calloutKey;
    return FwpmFilterAdd0(gEngine, &filter, NULL, outFilterId);
}

// Non-terminating INSPECTION callout: observes connects for logging, never alters the verdict.
static NTSTATUS AddMonitorCallout(PDEVICE_OBJECT dev, const GUID *calloutKey, const GUID *layerKey,
                                  FWPS_CALLOUT_CLASSIFY_FN1 fn, UINT32 *outId, UINT64 *outFilterId)
{
    BOOLEAN endpointClosure = fn == EndpointClosed;
    FWPS_CALLOUT1 sCallout = {0};
    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = fn;
    sCallout.notifyFn   = NotifyFn;
    NTSTATUS status = FwpsCalloutRegister1(dev, &sCallout, outId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT0 mCallout = {0};
    mCallout.calloutKey        = *calloutKey;
    mCallout.displayData.name  = endpointClosure ? L"ProxyBridge UDP Endpoint Closure" : L"ProxyBridge Connection Monitor";
    mCallout.providerKey       = (GUID *)&PB_PROVIDER_GUID;
    mCallout.applicableLayer   = *layerKey;
    status = FwpmCalloutAdd0(gEngine, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    FWPM_FILTER0 filter = {0};
    filter.displayData.name = endpointClosure ? L"ProxyBridge UDP Closure Filter" : L"ProxyBridge Monitor Filter";
    filter.layerKey         = *layerKey;
    filter.subLayerKey      = PB_SUBLAYER_GUID;
    filter.providerKey      = (GUID *)&PB_PROVIDER_GUID;
    filter.weight.type      = FWP_EMPTY;
    FWPM_FILTER_CONDITION0 protocol = {0};
    if (endpointClosure) {
        protocol.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        protocol.matchType = FWP_MATCH_EQUAL;
        protocol.conditionValue.type = FWP_UINT8;
        protocol.conditionValue.uint8 = IPPROTO_UDP;
        filter.numFilterConditions = 1;
        filter.filterCondition = &protocol;
    }
    filter.action.type      = FWP_ACTION_CALLOUT_INSPECTION;   // non-terminating: log only
    filter.action.calloutKey = *calloutKey;
    return FwpmFilterAdd0(gEngine, &filter, NULL, outFilterId);
}

NTSTATUS PbWfpStart(PDEVICE_OBJECT dev)
{
    if (gWfpDeviceReference != NULL) return STATUS_INVALID_DEVICE_STATE;
    ObReferenceObject(dev);
    gWfpDeviceReference = dev;
    NTSTATUS status;
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;       // auto-cleanup engine objects on handle close

    // Prepare redirect state before publishing any filters.
    status = FwpsRedirectHandleCreate0(&PB_PROVIDER_GUID, 0, &gRedirect);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngine);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmTransactionBegin0(gEngine, 0);
    if (!NT_SUCCESS(status)) return status;

    FWPM_PROVIDER0 provider = {0};
    provider.providerKey = PB_PROVIDER_GUID;
    provider.displayData.name = L"ProxyBridge";
    status = FwpmProviderAdd0(gEngine, &provider, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        FwpmTransactionAbort0(gEngine);
        return status;
    }

    FWPM_SUBLAYER0 sub = {0};
    sub.subLayerKey = PB_SUBLAYER_GUID;
    sub.displayData.name = L"ProxyBridge Redirect";
    sub.providerKey = (GUID *)&PB_PROVIDER_GUID;
    sub.weight = 0x8000;
    status = FwpmSubLayerAdd0(gEngine, &sub, NULL);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }

    status = AddCallout(dev, &PB_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, ClassifyV4, &gCalloutV4Id, &gFilterV4Id);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }
    status = AddCallout(dev, &PB_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, ClassifyV6, &gCalloutV6Id, &gFilterV6Id);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }

    // Monitor callouts: log every outbound connect (direct/proxy/block alike).
    status = AddMonitorCallout(dev, &PB_MON_CALLOUT_V4_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, MonitorV4, &gMonCalloutV4Id, &gMonFilterV4Id);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }
    status = AddMonitorCallout(dev, &PB_MON_CALLOUT_V6_GUID, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, MonitorV6, &gMonCalloutV6Id, &gMonFilterV6Id);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }

    status = AddMonitorCallout(dev, &PB_CLOSE_V4_GUID, &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
                              EndpointClosed, &gCloseV4Id, &gCloseFilterV4Id);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }
    status = AddMonitorCallout(dev, &PB_CLOSE_V6_GUID, &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
                              EndpointClosed, &gCloseV6Id, &gCloseFilterV6Id);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }

    status = FwpmTransactionCommit0(gEngine);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }

    return STATUS_SUCCESS;
}

static NTSTATUS UnregisterCallout(UINT32 *id)
{
    if (*id == 0) return STATUS_SUCCESS;
    NTSTATUS status = FwpsCalloutUnregisterById0(*id);
    if (NT_SUCCESS(status) || status == STATUS_FWP_CALLOUT_NOT_FOUND) {
        *id = 0;
        return STATUS_SUCCESS;
    }
    // No flow contexts are associated by this driver, and the KMDF lifecycle
    // serializes all registration. BUSY/IN_USE would violate those invariants.
    // Preserve ownership on any failure; never pretend the callout is gone.
    return status;
}

NTSTATUS PbWfpStop(void)
{
    // Teardown order matters. (1) Close the engine: the dynamic session removes our filters, so
    // no NEW classify can enter. (2) Unregister the kernel callouts: this waits for any in-flight
    // classify to drain. (3) Only now destroy the shared redirect handle - doing it earlier could
    // let a still-running classify dereference a freed gRedirect.
    if (gEngine) {
        NTSTATUS status = FwpmEngineClose0(gEngine);
        if (!NT_SUCCESS(status)) return status;
        gEngine = NULL;
    }
    NTSTATUS result = STATUS_SUCCESS;
    UINT32 *ids[] = { &gCalloutV4Id, &gCalloutV6Id, &gMonCalloutV4Id, &gMonCalloutV6Id, &gCloseV4Id, &gCloseV6Id };
    for (ULONG i = 0; i < RTL_NUMBER_OF(ids); ++i) {
        NTSTATUS status = UnregisterCallout(ids[i]);
        if (!NT_SUCCESS(status) && NT_SUCCESS(result)) result = status;
    }
    if (!NT_SUCCESS(result)) return result;
    if (gRedirect)       { FwpsRedirectHandleDestroy0(gRedirect);       gRedirect = NULL; }
    if (gWfpDeviceReference != NULL) {
        PDEVICE_OBJECT dev = gWfpDeviceReference;
        gWfpDeviceReference = NULL;
        ObDereferenceObject(dev);
    }
    return STATUS_SUCCESS;
}

void PbResetSession(void)
{
    // Only after successful WFP teardown and after file requests have drained.
    NT_ASSERT(gEngine == NULL && gRedirect == NULL);
    KIRQL old = ExAcquireSpinLockExclusive(&gCfgLock);
    PBDRV_WATCHLIST *watch = gWatch;
    gWatch = NULL;
    RtlZeroMemory(&gConfig, sizeof(gConfig));
    gConfigured = FALSE;
    gWatchRevision = 0;
    gLastActivationStatus = STATUS_SUCCESS;
    ExReleaseSpinLockExclusive(&gCfgLock, old);
    if (watch != NULL) ExFreePoolWithTag(watch, PB_TAG);
    UdpMapClear();
    EventClear();
}

// Buffer lengths are checked here even though KMDF validates buffer access.
NTSTATUS PbDeviceControl(ULONG code, PVOID input, ULONG inLen,
                         PVOID output, ULONG outputLength, ULONG_PTR *information)
{
    PVOID buf = input;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;
    KIRQL old;
    switch (code) {
    case PBDRV_IOCTL_SET_CONFIG:
        if (inLen < sizeof(PBDRV_CONFIG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            const PBDRV_CONFIG *config = (const PBDRV_CONFIG *)buf;
            if (config->selfPid == 0 || config->tcpV4Port == 0 ||
                config->redirectUdp > 1 || config->redirectIpv6 > 1 ||
                config->redirectLoopbackApps > 1 || !IsLoopbackV4(config->tcpV4Addr) ||
                (config->redirectUdp && (config->udpV4Port == 0 || !IsLoopbackV4(config->udpV4Addr))) ||
                (config->redirectIpv6 && (config->tcpV6Port == 0 || !IsLoopbackV6(config->tcpV6Addr))) ||
                (config->redirectIpv6 && config->redirectUdp &&
                 (config->udpV6Port == 0 || !IsLoopbackV6(config->udpV6Addr)))) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        old = ExAcquireSpinLockExclusive(&gCfgLock);
        RtlCopyMemory(&gConfig, buf, sizeof(PBDRV_CONFIG));
        gConfigured = TRUE;
        ExReleaseSpinLockExclusive(&gCfgLock, old);
        break;

    case PBDRV_IOCTL_SET_RULE_POLICY:
    case PBDRV_IOCTL_SET_WATCHLIST: {
        const PBDRV_RULE_POLICY *policy = NULL;
        SIZE_T prefix = 0;
        if (code == PBDRV_IOCTL_SET_RULE_POLICY) {
            prefix = FIELD_OFFSET(PBDRV_RULE_POLICY, watch);
            if (inLen < prefix + sizeof(UINT32)) { status = STATUS_BUFFER_TOO_SMALL; break; }
            policy = (const PBDRV_RULE_POLICY *)buf;
            if (policy->redirectLoopbackApps > 1) { status = STATUS_INVALID_PARAMETER; break; }
        }
        if (inLen < prefix + sizeof(UINT32)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        const PBDRV_WATCHLIST *incoming = (const PBDRV_WATCHLIST *)((const UCHAR *)buf + prefix);
        if (incoming->count > PBDRV_MAX_WATCH) { status = STATUS_INVALID_PARAMETER; break; }
        SIZE_T need = FIELD_OFFSET(PBDRV_WATCHLIST, entries) + (SIZE_T)incoming->count * sizeof(PBDRV_WATCH_ENTRY);
        if (inLen - prefix < need) { status = STATUS_BUFFER_TOO_SMALL; break; }
        for (UINT32 i = 0; i < incoming->count; ++i) {
            ULONG length = 0;
            while (length < PBDRV_NAME_LEN && incoming->entries[i].image[length] != L'\0') ++length;
            if (length == 0 || length == PBDRV_NAME_LEN) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        if (!NT_SUCCESS(status)) break;
        PBDRV_WATCHLIST *copy = (PBDRV_WATCHLIST *)ExAllocatePool2(POOL_FLAG_NON_PAGED, need, PB_TAG);
        if (!copy) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
        RtlCopyMemory(copy, incoming, need);
        old = ExAcquireSpinLockExclusive(&gCfgLock);
        if (policy != NULL && !gConfigured) {
            ExReleaseSpinLockExclusive(&gCfgLock, old);
            ExFreePoolWithTag(copy, PB_TAG);
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        if (policy != NULL) gConfig.redirectLoopbackApps = policy->redirectLoopbackApps;
        PBDRV_WATCHLIST *oldWatch = gWatch; gWatch = copy;
        if (++gWatchRevision == 0) ++gWatchRevision;
        ExReleaseSpinLockExclusive(&gCfgLock, old);
        if (oldWatch) ExFreePoolWithTag(oldWatch, PB_TAG);
        break;
    }

    case PBDRV_IOCTL_QUERY_UDP: {
        ULONG outLen = outputLength;
        if (inLen < sizeof(PBDRV_UDP_QUERY) || outLen < sizeof(PBDRV_UDP_QUERY)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PBDRV_UDP_QUERY *q = (PBDRV_UDP_QUERY *)output;
        RtlCopyMemory(q, input, sizeof(*q));
        q->found = UdpMapGet(q) ? 1 : 0;
        info = sizeof(PBDRV_UDP_QUERY);
        break;
    }

    case PBDRV_IOCTL_POP_EVENTS: {
        ULONG outLen = outputLength;
        ULONG maxCount = outLen / sizeof(PBDRV_EVENT);
        if (maxCount == 0) { status = STATUS_BUFFER_TOO_SMALL; break; }
        ULONG got = EventPopMany((PBDRV_EVENT *)output, maxCount);
        info = (ULONG_PTR)got * sizeof(PBDRV_EVENT);
        break;
    }

    case PBDRV_IOCTL_GET_STATUS: {
        if (outputLength < sizeof(PBDRV_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PBDRV_STATUS *result = (PBDRV_STATUS *)output;
        RtlZeroMemory(result, sizeof(*result));
        result->size = sizeof(*result);
        result->protocolVersion = PBDRV_PROTOCOL_VERSION;
        result->driverVersion = PBDRV_DRIVER_VERSION;
        result->generation = 0; // supplied by the KMDF device context
        old = ExAcquireSpinLockShared(&gCfgLock);
        result->flags = PBDRV_STATUS_READY;
        if (gConfigured) result->flags |= PBDRV_STATUS_CONFIGURED;
        if (gWatch != NULL) result->flags |= PBDRV_STATUS_WATCHLIST;
        if (gEnabled) result->flags |= PBDRV_STATUS_ACTIVE;
        result->watchlistRevision = gWatchRevision;
        result->lastActivationStatus = (UINT32)gLastActivationStatus;
        if (UdpMapHadFailure()) result->flags |= PBDRV_STATUS_UDP_ADMISSION_FAILED;
        ExReleaseSpinLockShared(&gCfgLock, old);
        info = sizeof(*result);
        break;
    }
    case PBDRV_IOCTL_ENABLE:
        old = ExAcquireSpinLockExclusive(&gCfgLock);
        if (!gConfigured || gWatch == NULL)
            status = STATUS_INVALID_DEVICE_STATE;
        else
            InterlockedExchange(&gEnabled, 1);
        gLastActivationStatus = status;
        ExReleaseSpinLockExclusive(&gCfgLock, old);
        break;
    case PBDRV_IOCTL_DISABLE:
        old = ExAcquireSpinLockExclusive(&gCfgLock);
        InterlockedExchange(&gEnabled, 0);
        ExReleaseSpinLockExclusive(&gCfgLock, old);
        break;
    default: status = STATUS_INVALID_DEVICE_REQUEST; break;
    }

    *information = info;
    return status;
}
