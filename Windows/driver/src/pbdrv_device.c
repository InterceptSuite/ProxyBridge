// KMDF PnP and controller lifetime. WFP uses this same FDO, not a companion
// legacy control device. All control/lifecycle operations run at PASSIVE_LEVEL.
#include <ntddk.h>
#include <wdf.h>
#include "ProxyBridgeDrv_ioctl.h"
#include "pbdrv_device.h"

static const GUID PBDRV_INTERFACE_GUID =
    {0x7c1b6a10,0x2e44,0x4e8b,{0x9e,0x21,0x0f,0x9a,0x5d,0x3c,0x1a,0x08}};

typedef struct PB_DEVICE_CONTEXT {
    WDFWAITLOCK lifecycle;
    WDFFILEOBJECT owner;
    ULONG generation;
    BOOLEAN ready;
    BOOLEAN wfpStarted;
    NTSTATUS teardownStatus;
} PB_DEVICE_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PB_DEVICE_CONTEXT, PbDeviceContext);

typedef struct PB_FILE_CONTEXT {
    EX_RUNDOWN_REF requests;
    volatile LONG valid;
    ULONG generation;
    ULONG processId;
} PB_FILE_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PB_FILE_CONTEXT, PbFileContext);

// The existing WFP/map state is singleton. Hold this guard until final cleanup,
// including failed AddDevice. A second devnode must never share that state.
static volatile LONG gInstanceClaimed;

EVT_WDF_DRIVER_DEVICE_ADD PbEvtDeviceAdd;
EVT_WDF_DEVICE_D0_ENTRY PbEvtD0Entry;
EVT_WDF_DEVICE_D0_EXIT PbEvtD0Exit;
EVT_WDF_DEVICE_RELEASE_HARDWARE PbEvtReleaseHardware;
EVT_WDF_DEVICE_SURPRISE_REMOVAL PbEvtSurpriseRemoval;
EVT_WDF_DEVICE_FILE_CREATE PbEvtFileCreate;
EVT_WDF_FILE_CLEANUP PbEvtFileCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL PbEvtIoDeviceControl;
EVT_WDF_OBJECT_CONTEXT_CLEANUP PbEvtDeviceCleanup;
DRIVER_INITIALIZE DriverEntry;

static NTSTATUS PbDisable(PB_DEVICE_CONTEXT *context)
{
    ULONG_PTR ignored;
    PbDeviceControl(PBDRV_IOCTL_DISABLE, NULL, 0, NULL, 0, &ignored);
    NTSTATUS status = PbWfpStop();
    context->teardownStatus = status;
    if (NT_SUCCESS(status)) context->wfpStarted = FALSE;
    return status;
}

// lifecycle held. Invalidating before draining prevents late file requests from
// observing a new session. Fast requests never wait for the lifecycle lock.
static NTSTATUS PbQuiesce(PB_DEVICE_CONTEXT *context)
{
    ULONG_PTR ignored;
    PbDeviceControl(PBDRV_IOCTL_DISABLE, NULL, 0, NULL, 0, &ignored);
    if (context->owner != NULL) {
        PB_FILE_CONTEXT *file = PbFileContext(context->owner);
        InterlockedExchange(&file->valid, FALSE);
        ExWaitForRundownProtectionRelease(&file->requests);
    }
    NTSTATUS status = PbDisable(context);
    if (NT_SUCCESS(status)) {
        PbResetSession();
        context->owner = NULL;
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS PbEvtD0Entry(WDFDEVICE device, WDF_POWER_DEVICE_STATE previousState)
{
    UNREFERENCED_PARAMETER(previousState);
    PB_DEVICE_CONTEXT *context = PbDeviceContext(device);
    WdfWaitLockAcquire(context->lifecycle, NULL);
    NTSTATUS status = context->teardownStatus;
    if (NT_SUCCESS(status)) {
        // A sleep/resume keeps the existing controller and WFP session.
        if (context->owner == NULL && ++context->generation == 0)
            ++context->generation;
        context->ready = TRUE;
    }
    // No BFE work here. A started devnode is independent of filtering activation.
    WdfWaitLockRelease(context->lifecycle);
    return status;
}

_Use_decl_annotations_
NTSTATUS PbEvtD0Exit(WDFDEVICE device, WDF_POWER_DEVICE_STATE targetState)
{
    PB_DEVICE_CONTEXT *context = PbDeviceContext(device);
    WdfWaitLockAcquire(context->lifecycle, NULL);
    context->ready = FALSE;
    // The software callouts have no hardware to power down. Keep their state
    // across sleep/hibernate; removal, rebalance and final shutdown still drain it.
    NTSTATUS status = targetState == WdfPowerDeviceD3Final
        ? PbQuiesce(context) : STATUS_SUCCESS;
    WdfWaitLockRelease(context->lifecycle);
    return status;
}

_Use_decl_annotations_
NTSTATUS PbEvtReleaseHardware(WDFDEVICE device, WDFCMRESLIST resources)
{
    UNREFERENCED_PARAMETER(resources);
    return PbEvtD0Exit(device, WdfPowerDeviceD3Final);
}

_Use_decl_annotations_
void PbEvtSurpriseRemoval(WDFDEVICE device)
{
    // ReleaseHardware retries cleanup if a lower-level teardown failed.
    (void)PbEvtD0Exit(device, WdfPowerDeviceD3Final);
}

_Use_decl_annotations_
void PbEvtFileCreate(WDFDEVICE device, WDFREQUEST request, WDFFILEOBJECT fileObject)
{
    PB_DEVICE_CONTEXT *context = PbDeviceContext(device);
    PB_FILE_CONTEXT *file = PbFileContext(fileObject);
    ExInitializeRundownProtection(&file->requests);
    WdfWaitLockAcquire(context->lifecycle, NULL);
    NTSTATUS status = STATUS_SUCCESS;
    if (!context->ready || !NT_SUCCESS(context->teardownStatus))
        status = STATUS_DEVICE_NOT_READY;
    else if (context->owner != NULL)
        status = STATUS_SHARING_VIOLATION;
    else {
        file->generation = context->generation;
        file->processId = WdfRequestGetRequestorProcessId(request);
        InterlockedExchange(&file->valid, TRUE);
        context->owner = fileObject;
    }
    WdfWaitLockRelease(context->lifecycle);
    WdfRequestComplete(request, status);
}

_Use_decl_annotations_
void PbEvtFileCleanup(WDFFILEOBJECT fileObject)
{
    PB_DEVICE_CONTEXT *context = PbDeviceContext(WdfFileObjectGetDevice(fileObject));
    WdfWaitLockAcquire(context->lifecycle, NULL);
    if (context->owner == fileObject) {
        (void)PbQuiesce(context);
        // Even if teardown failed, the file object is about to go away. The
        // error blocks subsequent opens; resource IDs remain owned by WFP state.
        context->owner = NULL;
    }
    WdfWaitLockRelease(context->lifecycle);
}

_Use_decl_annotations_
void PbEvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outputLength,
                         size_t inputLength, ULONG code)
{
    WDFDEVICE device = WdfIoQueueGetDevice(queue);
    PB_DEVICE_CONTEXT *context = PbDeviceContext(device);
    WDFFILEOBJECT fileObject = WdfRequestGetFileObject(request);
    PVOID input = NULL, output = NULL;
    ULONG_PTR information = 0;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    if (fileObject == NULL || inputLength > MAXULONG || outputLength > MAXULONG)
        goto complete;
    if (inputLength != 0) {
        status = WdfRequestRetrieveInputBuffer(request, inputLength, &input, NULL);
        if (!NT_SUCCESS(status)) goto complete;
    }
    if (outputLength != 0) {
        status = WdfRequestRetrieveOutputBuffer(request, outputLength, &output, NULL);
        if (!NT_SUCCESS(status)) goto complete;
    }

    PB_FILE_CONTEXT *file = PbFileContext(fileObject);
    if (code == PBDRV_IOCTL_QUERY_UDP || code == PBDRV_IOCTL_POP_EVENTS) {
        // Existing map/ring locks protect the actual data. No WFP API or
        // lifecycle mutex on the UDP lookup path.
        if (!ExAcquireRundownProtection(&file->requests)) {
            status = STATUS_FILE_CLOSED;
            goto complete;
        }
        if (InterlockedCompareExchange(&file->valid, 0, 0))
            status = PbDeviceControl(code, input, (ULONG)inputLength,
                                     output, (ULONG)outputLength, &information);
        else
            status = STATUS_FILE_CLOSED;
        ExReleaseRundownProtection(&file->requests);
        goto complete;
    }

    WdfWaitLockAcquire(context->lifecycle, NULL);
    if (!context->ready || context->owner != fileObject || !file->valid ||
        file->generation != context->generation) {
        status = STATUS_DEVICE_NOT_READY;
    } else if (code == PBDRV_IOCTL_SET_CONFIG && inputLength >= sizeof(PBDRV_CONFIG) &&
               ((PBDRV_CONFIG *)input)->selfPid != file->processId) {
        status = STATUS_INVALID_PARAMETER;
    } else if (code == PBDRV_IOCTL_ENABLE) {
        if (!PbSessionConfigured())
            status = STATUS_INVALID_DEVICE_STATE;
        else {
            status = context->teardownStatus;
            if (NT_SUCCESS(status) && !context->wfpStarted) {
                status = PbWfpStart(WdfDeviceWdmGetDeviceObject(device));
                if (NT_SUCCESS(status)) context->wfpStarted = TRUE;
                else {
                    NTSTATUS cleanup = PbDisable(context);
                    if (!NT_SUCCESS(cleanup)) status = cleanup;
                }
            }
            if (NT_SUCCESS(status))
                status = PbDeviceControl(code, input, (ULONG)inputLength,
                                         output, (ULONG)outputLength, &information);
        }
    } else if (code == PBDRV_IOCTL_DISABLE) {
        status = PbDisable(context);
    } else {
        status = PbDeviceControl(code, input, (ULONG)inputLength,
                                 output, (ULONG)outputLength, &information);

    }
    WdfWaitLockRelease(context->lifecycle);
complete:
    WdfRequestCompleteWithInformation(request, status, information);
}

_Use_decl_annotations_
void PbEvtDeviceCleanup(WDFOBJECT object)
{
    PB_DEVICE_CONTEXT *context = PbDeviceContext(object);
    // Also covers AddDevice failure before any resources or callbacks existed.
    if (context->lifecycle != NULL) {
        WdfWaitLockAcquire(context->lifecycle, NULL);
        NTSTATUS status = PbQuiesce(context);
        WdfWaitLockRelease(context->lifecycle);
        WdfObjectDelete(context->lifecycle);
        context->lifecycle = NULL;
        if (!NT_SUCCESS(status)) {
            // PbWfpStop retains a native FDO reference, not this WDF context.
            // Remaining callouts use module state only, with filtering disabled.
            // Keep the singleton closed until reboot; do not retry indefinitely
            // or permit a replacement device to overwrite retained WFP state.
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
                "ProxyBridgeDrv: final WFP teardown failed (0x%08lX); reboot required\n",
                (ULONG)status);
            return;
        }
    }
    InterlockedExchange(&gInstanceClaimed, FALSE);
}

_Use_decl_annotations_
NTSTATUS PbEvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT deviceInit)
{
    if (InterlockedCompareExchange(&gInstanceClaimed, TRUE, FALSE))
        return STATUS_OBJECT_NAME_COLLISION;

    WDF_PNPPOWER_EVENT_CALLBACKS power;
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);
    power.EvtDeviceD0Entry = PbEvtD0Entry;
    power.EvtDeviceD0Exit = PbEvtD0Exit;
    power.EvtDeviceReleaseHardware = PbEvtReleaseHardware;
    power.EvtDeviceSurpriseRemoval = PbEvtSurpriseRemoval;
    WdfDeviceInitSetPnpPowerEventCallbacks(deviceInit, &power);
    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, TRUE);
    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    WDF_FILEOBJECT_CONFIG files;
    WDF_FILEOBJECT_CONFIG_INIT(&files, PbEvtFileCreate, WDF_NO_EVENT_CALLBACK, PbEvtFileCleanup);
    WDF_OBJECT_ATTRIBUTES fileAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&fileAttributes, PB_FILE_CONTEXT);
    fileAttributes.ExecutionLevel = WdfExecutionLevelPassive;
    fileAttributes.SynchronizationScope = WdfSynchronizationScopeNone;
    WdfDeviceInitSetFileObjectConfig(deviceInit, &files, &fileAttributes);

    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, PB_DEVICE_CONTEXT);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    attributes.SynchronizationScope = WdfSynchronizationScopeNone;
    attributes.EvtCleanupCallback = PbEvtDeviceCleanup;
    WDFDEVICE device;
    NTSTATUS status = WdfDeviceCreate(&deviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&gInstanceClaimed, FALSE);
        return status;
    }
    PB_DEVICE_CONTEXT *context = PbDeviceContext(device);
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    // Device cleanup still uses this lock. Own it under the driver and delete
    // it explicitly there, before driver cleanup, instead of using a child
    // whose cleanup would precede the device's cleanup callback.
    attributes.ParentObject = driver;
    status = WdfWaitLockCreate(&attributes, &context->lifecycle);
    if (!NT_SUCCESS(status)) return status;

    WDF_IO_QUEUE_CONFIG queue;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue, WdfIoQueueDispatchParallel);
    // Explicit state checking returns NOT_READY in Dx instead of retaining
    // synchronous application requests until a later power transition.
    queue.PowerManaged = WdfFalse;
    queue.EvtIoDeviceControl = PbEvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queue, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) return status;
    status = WdfDeviceCreateDeviceInterface(device, &PBDRV_INTERFACE_GUID, NULL);
    if (!NT_SUCCESS(status)) return status;
    // Keep the existing user-mode open path and IOCTL layouts compatible.
    DECLARE_CONST_UNICODE_STRING(link, PBDRV_SYMLINK_NAME);
    return WdfDeviceCreateSymbolicLink(device, &link);
}

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, PbEvtDeviceAdd);
    return WdfDriverCreate(driver, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}
