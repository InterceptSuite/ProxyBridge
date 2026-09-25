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
#include <setupapi.h>
#include <stdlib.h>
#include "ProxyBridgeDrv_user.h"

// ---- driver handle / config ------------------------------------------------

HANDLE pbdrv_open(void)
{
    HDEVINFO devices = SetupDiGetClassDevsW(&PBDRV_INTERFACE_GUID, NULL, NULL,
                                           DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devices == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD error = ERROR_SUCCESS;
    SP_DEVICE_INTERFACE_DATA interfaceData = {0};
    interfaceData.cbSize = sizeof(interfaceData);
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail = NULL;
    if (!SetupDiEnumDeviceInterfaces(devices, NULL, &PBDRV_INTERFACE_GUID, 0, &interfaceData)) {
        error = GetLastError();
        if (error == ERROR_NO_MORE_ITEMS) error = ERROR_NOT_FOUND;
        goto done;
    }
    SP_DEVICE_INTERFACE_DATA duplicate = {0};
    duplicate.cbSize = sizeof(duplicate);
    if (SetupDiEnumDeviceInterfaces(devices, NULL, &PBDRV_INTERFACE_GUID, 1, &duplicate)) {
        error = ERROR_DUP_NAME;
        goto done; // never silently select one of several devices
    }
    if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        error = GetLastError();
        goto done;
    }
    DWORD required = 0;
    SetupDiGetDeviceInterfaceDetailW(devices, &interfaceData, NULL, 0, &required, NULL);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof(*detail)) {
        error = ERROR_INVALID_DATA;
        goto done;
    }
    detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)malloc(required);
    if (detail == NULL) {
        error = ERROR_NOT_ENOUGH_MEMORY;
        goto done;
    }
    detail->cbSize = sizeof(*detail);
    if (!SetupDiGetDeviceInterfaceDetailW(devices, &interfaceData, detail, required, NULL, NULL)) {
        error = GetLastError();
        goto done;
    }
    // No inheritance and no shared controller handles. KMDF also enforces one owner.
    handle = CreateFileW(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
                         0, NULL, OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) error = GetLastError();
done:
    free(detail);
    SetupDiDestroyDeviceInfoList(devices);
    SetLastError(error);
    return handle;
}

BOOL pbdrv_get_status(HANDLE h, PBDRV_STATUS *status)
{
    DWORD bytes = 0;
    ZeroMemory(status, sizeof(*status));
    if (!DeviceIoControl(h, PBDRV_IOCTL_GET_STATUS, NULL, 0,
                         status, sizeof(*status), &bytes, NULL))
        return FALSE;
    if (bytes != sizeof(*status) || status->size != sizeof(*status) ||
        status->protocolVersion != PBDRV_PROTOCOL_VERSION ||
        status->driverVersion != PBDRV_DRIVER_VERSION || status->reserved != 0) {
        SetLastError(ERROR_REVISION_MISMATCH);
        return FALSE;
    }
    return TRUE;
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
    if (q == NULL || (q->family != AF_INET && q->family != AF_INET6)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    PBDRV_UDP_QUERY input = *q;
    DWORD ret = 0;
    if (!DeviceIoControl(h, PBDRV_IOCTL_QUERY_UDP, q, sizeof(*q), q, sizeof(*q), &ret, NULL))
        return FALSE;
    BOOL sameSource = q->family == input.family && q->srcPort == input.srcPort &&
        (input.family == AF_INET ? q->srcV4 == input.srcV4 : memcmp(q->srcV6, input.srcV6, 16) == 0);
    if (ret != sizeof(*q) || !sameSource || q->found > 1 ||
        (q->found && q->mappingGeneration == 0)) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    return TRUE;
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

BOOL pbdrv_set_rule_policy(HANDLE h, const PBDRV_WATCHLIST *wl, BOOL loopback)
{
    if (wl == NULL || wl->count > PBDRV_MAX_WATCH) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    SIZE_T watchSize = FIELD_OFFSET(PBDRV_WATCHLIST, entries) + (SIZE_T)wl->count * sizeof(PBDRV_WATCH_ENTRY);
    DWORD length = (DWORD)(FIELD_OFFSET(PBDRV_RULE_POLICY, watch) + watchSize);
    PBDRV_RULE_POLICY *policy = malloc(length);
    if (policy == NULL) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    policy->redirectLoopbackApps = !!loopback;
    memcpy(&policy->watch, wl, watchSize);
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, PBDRV_IOCTL_SET_RULE_POLICY, policy, length, NULL, 0, &returned, NULL);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    free(policy);
    SetLastError(error);
    return ok;
}
