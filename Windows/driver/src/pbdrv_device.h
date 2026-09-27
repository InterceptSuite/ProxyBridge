#ifndef PBDRV_DEVICE_H
#define PBDRV_DEVICE_H

#include <ntddk.h>

// Called at PASSIVE_LEVEL by the serialized KMDF lifecycle/control path.
NTSTATUS PbWfpStart(PDEVICE_OBJECT device);
NTSTATUS PbWfpStop(void);
void PbResetSession(void);
BOOLEAN PbSessionConfigured(void);
NTSTATUS PbDeviceControl(ULONG code, PVOID input, ULONG inputLength,
                         PVOID output, ULONG outputLength, ULONG_PTR *information);

#endif
