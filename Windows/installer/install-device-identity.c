#include "install-device-identity.h"
#include <stdio.h>
#include <wchar.h>

DWORD pb_plan_device_instance(const GUID *transaction, WCHAR instance[200])
{
    static const GUID empty = {0};
    if (!transaction || !instance || IsEqualGUID(transaction, &empty)) return ERROR_INVALID_PARAMETER;
    int count = swprintf_s(instance, 200,
        L"ROOT\\InterceptSuite_ProxyBridge\\%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        transaction->Data1, transaction->Data2, transaction->Data3,
        transaction->Data4[0], transaction->Data4[1], transaction->Data4[2], transaction->Data4[3],
        transaction->Data4[4], transaction->Data4[5], transaction->Data4[6], transaction->Data4[7]);
    return count < 0 ? ERROR_INVALID_DATA : ERROR_SUCCESS;
}

DWORD pb_check_device_instance(const PB_INSTALL_JOURNAL *record, BOOL exists, const WCHAR *instance)
{
    DWORD error = pb_journal_validate(record);
    if (error != ERROR_SUCCESS) return error;
    if (!exists) return record->deviceExisted ? ERROR_NOT_FOUND : ERROR_SUCCESS;
    if (!instance || !instance[0] || wcsnlen_s(instance, 200) == 200) return ERROR_INVALID_DATA;
    return _wcsicmp(record->deviceInstance, instance) == 0 ? ERROR_SUCCESS : ERROR_REVISION_MISMATCH;
}

DWORD pb_check_device_before_install(const PB_INSTALL_JOURNAL *record, BOOL exists,
                                     const WCHAR *instance, const WCHAR *currentInf)
{
    DWORD error = pb_check_device_instance(record, exists, instance);
    if (error != ERROR_SUCCESS) return error;
    if (record->phase != PB_INSTALL_PREPARED) return ERROR_INVALID_STATE;
    if (record->deviceExisted) {
        if (!record->previousDirectory[0] || !record->previousInf[0] || !currentInf ||
            _wcsicmp(record->previousInf, currentInf) != 0) return ERROR_REVISION_MISMATCH;
    } else {
        // PREPARED predates registration. Even a matching unexpected device is
        // a conflict here; interrupted registration has DRIVER_CHANGING phase.
        if (exists) return ERROR_ALREADY_EXISTS;
        WCHAR planned[200];
        error = pb_plan_device_instance(&record->transaction, planned);
        if (error != ERROR_SUCCESS) return error;
        if (_wcsicmp(planned, record->deviceInstance)) return ERROR_REVISION_MISMATCH;
    }
    return ERROR_SUCCESS;
}
