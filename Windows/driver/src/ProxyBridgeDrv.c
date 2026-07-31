/*
 * ProxyBridgeDrv.c - ProxyBridge WFP connect-redirect callout driver.
 *
 * Redirects outbound connections of watched processes to the user-mode relay at the
 * ALE_CONNECT_REDIRECT layer (one layer covers TCP+UDP; two callouts cover IPv4+IPv6), and
 * observes every connect at ALE_AUTH_CONNECT for the connection log. The relay recovers the
 * original destination from the redirect context - no packet mangling, PID delivered by WFP.
 * DriverEntry/IOCTL dispatch live here; the UDP map + event ring live in pbdrv_state.c.
 */

#include <initguid.h>   // must precede includes so DEFINE_GUID allocates the GUID bytes

// fwpsk.h needs an NDIS version and pulls in ndis.h/ws2def.h/ws2ipdef.h - don't include those first.
#define NDIS_SUPPORT_NDIS6 1
#include <ntddk.h>
#include <wdmsec.h>              // IoCreateDeviceSecure - restrict the control device to admins
#pragma warning(push)
#pragma warning(disable: 4201)   // nameless struct/union in WFP headers
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)

#include "ProxyBridgeDrv_ioctl.h"
#include "pbdrv_state.h"

// Control-device DACL: only SYSTEM and the built-in Administrators group may open \\.\ProxyBridgeDrv.
// Without this the device is world-openable and any local user could reconfigure the redirect
// target (hijack other apps' connections) or drain the connection-event log (info disclosure).
DECLARE_CONST_UNICODE_STRING(gDeviceSddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
// {7C1B6A10-2E44-4E8B-9E21-0F9A5D3C1A07} - device class GUID for IoCreateDeviceSecure.
DEFINE_GUID(PB_DEVCLASS_GUID, 0x7c1b6a10,0x2e44,0x4e8b,0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x07);

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

// ---- Globals ----
static HANDLE      gEngine       = NULL;             // WFP engine session
static HANDLE      gRedirect     = NULL;             // shared redirect handle (loop detection)
static UINT32      gCalloutV4Id  = 0;
static UINT32      gCalloutV6Id  = 0;
static UINT64      gFilterV4Id    = 0;
static UINT64      gFilterV6Id    = 0;
static UINT32      gMonCalloutV4Id = 0;
static UINT32      gMonCalloutV6Id = 0;
static UINT64      gMonFilterV4Id  = 0;
static UINT64      gMonFilterV6Id  = 0;
static PDEVICE_OBJECT gDevice    = NULL;

static EX_SPIN_LOCK  gCfgLock;                        // guards gConfig / gWatch
static PBDRV_CONFIG  gConfig;                         // redirect targets + exclusions
static PBDRV_WATCHLIST *gWatch   = NULL;             // heap copy of the process watch list
static volatile LONG gEnabled    = 0;                // 0 until user mode enables

// Case-insensitive check: does `path` end with `suffix` (both null-terminated WCHAR)?
static BOOLEAN EndsWithI(const WCHAR *path, ULONG pathChars, const WCHAR *suffix)
{
    ULONG sl = 0; while (suffix[sl] && sl < PBDRV_NAME_LEN) sl++;
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
static BOOLEAN IsWatched(const WCHAR *imagePath, ULONG imageChars)
{
    BOOLEAN watched = FALSE;
    KIRQL old = ExAcquireSpinLockShared(&gCfgLock);
    if (gWatch != NULL) {
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

    // Snapshot config under the lock (SET_CONFIG can rewrite it at runtime), then use `cfg`.
    PBDRV_CONFIG cfg;
    KIRQL cfgIrql = ExAcquireSpinLockShared(&gCfgLock);
    cfg = gConfig;
    ExReleaseSpinLockShared(&gCfgLock, cfgIrql);

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
    if (protocol == IPPROTO_UDP && !cfg.redirectUdp)   return;   // TCP-only unless enabled
    if (family   == AF_INET6    && !cfg.redirectIpv6)  return;   // IPv4-only unless enabled

    UINT32 pid = 0;
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_PROCESS_ID))
        pid = (UINT32)inMeta->processId;
    if (pid != 0 && pid == cfg.selfPid) return;   // never redirect the relay itself

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

    if (!IsWatched(imagePath, imageChars))
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
        if (lb) { FwpsReleaseClassifyHandle0(classifyHandle); return; }
    }

    // Capture the ORIGINAL destination (still in req->remoteAddressAndPort) into a context the
    // relay reads back via SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT.
    PBDRV_REDIRECT_CTX *ctx = (PBDRV_REDIRECT_CTX *)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ctx), PB_TAG);
    if (ctx != NULL) {
        RtlZeroMemory(ctx, sizeof(*ctx));
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
        if (family == AF_INET) {
            PSOCKADDR_IN l = (PSOCKADDR_IN)&req->localAddressAndPort;
            UdpMapPut(AF_INET, l->sin_addr.S_un.S_addr, NULL, RtlUshortByteSwap(l->sin_port),
                      ctx->origV4, NULL, ctx->origPort, pid);
        } else {
            PSOCKADDR_IN6 l = (PSOCKADDR_IN6)&req->localAddressAndPort;
            UdpMapPut(AF_INET6, 0, (const UINT8 *)&l->sin6_addr, RtlUshortByteSwap(l->sin6_port),
                      0, ctx->origV6, ctx->origPort, pid);
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
    if (pid != 0 && pid == gConfig.selfPid) return;   // skip the relay's own sockets

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
    FWPS_CALLOUT1 sCallout = {0};
    sCallout.calloutKey = *calloutKey;
    sCallout.classifyFn = fn;
    sCallout.notifyFn   = NotifyFn;
    NTSTATUS status = FwpsCalloutRegister1(dev, &sCallout, outId);
    if (!NT_SUCCESS(status)) return status;

    FWPM_CALLOUT0 mCallout = {0};
    mCallout.calloutKey        = *calloutKey;
    mCallout.displayData.name  = L"ProxyBridge Connection Monitor";
    mCallout.providerKey       = (GUID *)&PB_PROVIDER_GUID;
    mCallout.applicableLayer   = *layerKey;
    status = FwpmCalloutAdd0(gEngine, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    FWPM_FILTER0 filter = {0};
    filter.displayData.name = L"ProxyBridge Monitor Filter";
    filter.layerKey         = *layerKey;
    filter.subLayerKey      = PB_SUBLAYER_GUID;
    filter.providerKey      = (GUID *)&PB_PROVIDER_GUID;
    filter.weight.type      = FWP_EMPTY;
    filter.numFilterConditions = 0;
    filter.action.type      = FWP_ACTION_CALLOUT_INSPECTION;   // non-terminating: log only
    filter.action.calloutKey = *calloutKey;
    return FwpmFilterAdd0(gEngine, &filter, NULL, outFilterId);
}

static NTSTATUS RegisterWfp(PDEVICE_OBJECT dev)
{
    NTSTATUS status;
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;       // auto-cleanup engine objects on handle close

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngine);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmTransactionBegin0(gEngine, 0);
    if (!NT_SUCCESS(status)) return status;

    FWPM_PROVIDER0 provider = {0};
    provider.providerKey = PB_PROVIDER_GUID;
    provider.displayData.name = L"ProxyBridge";
    FwpmProviderAdd0(gEngine, &provider, NULL);      // ok if it already exists

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

    status = FwpmTransactionCommit0(gEngine);
    if (!NT_SUCCESS(status)) { FwpmTransactionAbort0(gEngine); return status; }

    // Shared redirect handle drives the loop-detection above.
    return FwpsRedirectHandleCreate0(&PB_PROVIDER_GUID, 0, &gRedirect);
}

static void UnregisterWfp(void)
{
    // Teardown order matters. (1) Close the engine: the dynamic session removes our filters, so
    // no NEW classify can enter. (2) Unregister the kernel callouts: this waits for any in-flight
    // classify to drain. (3) Only now destroy the shared redirect handle - doing it earlier could
    // let a still-running classify dereference a freed gRedirect.
    if (gEngine) {
        FwpmEngineClose0(gEngine);       // removes filters/callouts/sublayer/provider
        gEngine = NULL;
    }
    if (gCalloutV4Id)    { FwpsCalloutUnregisterById0(gCalloutV4Id);    gCalloutV4Id = 0; }
    if (gCalloutV6Id)    { FwpsCalloutUnregisterById0(gCalloutV6Id);    gCalloutV6Id = 0; }
    if (gMonCalloutV4Id) { FwpsCalloutUnregisterById0(gMonCalloutV4Id); gMonCalloutV4Id = 0; }
    if (gMonCalloutV6Id) { FwpsCalloutUnregisterById0(gMonCalloutV6Id); gMonCalloutV6Id = 0; }
    if (gRedirect)       { FwpsRedirectHandleDestroy0(gRedirect);       gRedirect = NULL; }
}

// ---- IOCTL device interface ----
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buf = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;
    KIRQL old;

    switch (code) {
    case PBDRV_IOCTL_SET_CONFIG:
        if (inLen < sizeof(PBDRV_CONFIG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        old = ExAcquireSpinLockExclusive(&gCfgLock);
        RtlCopyMemory(&gConfig, buf, sizeof(PBDRV_CONFIG));
        ExReleaseSpinLockExclusive(&gCfgLock, old);
        break;

    case PBDRV_IOCTL_SET_WATCHLIST: {
        if (inLen < sizeof(UINT32)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PBDRV_WATCHLIST *incoming = (PBDRV_WATCHLIST *)buf;
        if (incoming->count > PBDRV_MAX_WATCH) { status = STATUS_INVALID_PARAMETER; break; }
        SIZE_T need = FIELD_OFFSET(PBDRV_WATCHLIST, entries) + (SIZE_T)incoming->count * sizeof(PBDRV_WATCH_ENTRY);
        if (inLen < need) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PBDRV_WATCHLIST *copy = (PBDRV_WATCHLIST *)ExAllocatePoolWithTag(NonPagedPoolNx, need, PB_TAG);
        if (!copy) { status = STATUS_INSUFFICIENT_RESOURCES; break; }
        RtlCopyMemory(copy, incoming, need);
        old = ExAcquireSpinLockExclusive(&gCfgLock);
        PBDRV_WATCHLIST *oldWatch = gWatch; gWatch = copy;
        ExReleaseSpinLockExclusive(&gCfgLock, old);
        if (oldWatch) ExFreePoolWithTag(oldWatch, PB_TAG);
        break;
    }

    case PBDRV_IOCTL_QUERY_UDP: {
        ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
        if (inLen < sizeof(PBDRV_UDP_QUERY) || outLen < sizeof(PBDRV_UDP_QUERY)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PBDRV_UDP_QUERY *q = (PBDRV_UDP_QUERY *)buf;
        q->found = UdpMapGet(q) ? 1 : 0;
        info = sizeof(PBDRV_UDP_QUERY);
        break;
    }

    case PBDRV_IOCTL_POP_EVENTS: {
        ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG maxCount = outLen / sizeof(PBDRV_EVENT);
        if (maxCount == 0) { status = STATUS_BUFFER_TOO_SMALL; break; }
        ULONG got = EventPopMany((PBDRV_EVENT *)buf, maxCount);
        info = (ULONG_PTR)got * sizeof(PBDRV_EVENT);
        break;
    }

    case PBDRV_IOCTL_ENABLE:  InterlockedExchange(&gEnabled, 1); break;
    case PBDRV_IOCTL_DISABLE: InterlockedExchange(&gEnabled, 0); break;
    default: status = STATUS_INVALID_DEVICE_REQUEST; break;
    }

    irp->IoStatus.Status = status; irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

// ---- Driver entry / unload ----
static void DriverUnload(PDRIVER_OBJECT driver)
{
    UNREFERENCED_PARAMETER(driver);
    InterlockedExchange(&gEnabled, 0);
    UnregisterWfp();
    if (gDevice) {
        UNICODE_STRING link; RtlInitUnicodeString(&link, PBDRV_SYMLINK_NAME);
        IoDeleteSymbolicLink(&link);
        IoDeleteDevice(gDevice);
        gDevice = NULL;
    }
    KIRQL old = ExAcquireSpinLockExclusive(&gCfgLock);
    PBDRV_WATCHLIST *w = gWatch; gWatch = NULL;
    ExReleaseSpinLockExclusive(&gCfgLock, old);
    if (w) ExFreePoolWithTag(w, PB_TAG);
    UdpMapClear();
}

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);
    NTSTATUS status;

    driver->DriverUnload = DriverUnload;
    driver->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    driver->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    UNICODE_STRING devName; RtlInitUnicodeString(&devName, PBDRV_DEVICE_NAME);
    // Secure device: SYSTEM + Administrators only (see gDeviceSddl). FILE_DEVICE_SECURE_OPEN
    // makes the namespace-relative opens honor the same descriptor.
    status = IoCreateDeviceSecure(driver, 0, &devName, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceSddl,
                                  (LPCGUID)&PB_DEVCLASS_GUID, &gDevice);
    if (!NT_SUCCESS(status)) return status;

    UNICODE_STRING link; RtlInitUnicodeString(&link, PBDRV_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&link, &devName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(gDevice); gDevice = NULL; return status; }

    status = RegisterWfp(gDevice);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&link);
        IoDeleteDevice(gDevice); gDevice = NULL;
        return status;
    }
    return STATUS_SUCCESS;
}
