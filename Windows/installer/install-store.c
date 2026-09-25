#include "install-store.h"
#include <sddl.h>
#include <stdlib.h>
#include <string.h>

static const WCHAR storePath[] = L"SOFTWARE\\InterceptSuite\\ProxyBridge\\InstallTransaction";
static const WCHAR storeSecurity[] = L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";

DWORD pb_install_store_check_security(PSECURITY_DESCRIPTOR descriptor)
{
    if (!descriptor || !IsValidSecurityDescriptor(descriptor)) return ERROR_INVALID_SECURITY_DESCR;
    PSID owner = NULL;
    BOOL defaulted = FALSE, present = FALSE;
    PACL actual = NULL, expected = NULL;
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    if (!GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !owner ||
        (!IsWellKnownSid(owner, WinBuiltinAdministratorsSid) && !IsWellKnownSid(owner, WinLocalSystemSid)) ||
        !GetSecurityDescriptorControl(descriptor, &control, &revision) || !(control & SE_DACL_PROTECTED) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &actual, &defaulted) || !present || !actual)
        return ERROR_ACCESS_DENIED;
    PSECURITY_DESCRIPTOR reference = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(storeSecurity, SDDL_REVISION_1, &reference, NULL))
        return GetLastError();
    DWORD error = ERROR_ACCESS_DENIED;
    if (GetSecurityDescriptorDacl(reference, &present, &expected, &defaulted) && expected &&
        actual->AclSize == expected->AclSize && memcmp(actual, expected, expected->AclSize) == 0)
        error = ERROR_SUCCESS;
    LocalFree(reference);
    return error;
}

static DWORD open_store(BOOL create, BOOL write, HKEY *key)
{
    if (!key) return ERROR_INVALID_PARAMETER;
    *key = NULL;
    HKEY opened = NULL;
    REGSAM access = KEY_QUERY_VALUE | READ_CONTROL | KEY_WOW64_64KEY;
    if (write) access |= KEY_SET_VALUE;
    LSTATUS error;
    if (create) {
        PSECURITY_DESCRIPTOR descriptor = NULL;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(storeSecurity, SDDL_REVISION_1, &descriptor, NULL))
            return GetLastError();
        SECURITY_ATTRIBUTES attributes = {sizeof(attributes), descriptor, FALSE};
        error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, storePath, 0, NULL, REG_OPTION_NON_VOLATILE,
                                access | KEY_SET_VALUE, &attributes, &opened, NULL);
        LocalFree(descriptor);
    } else {
        error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, storePath, 0, access, &opened);
    }
    if (error != ERROR_SUCCESS) return (DWORD)error;
    DWORD bytes = 0;
    const SECURITY_INFORMATION information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    error = RegGetKeySecurity(opened, information, NULL, &bytes);
    if (error == ERROR_INSUFFICIENT_BUFFER && bytes > 0 && bytes <= 65536) {
        PSECURITY_DESCRIPTOR descriptor = malloc(bytes);
        if (!descriptor) error = ERROR_NOT_ENOUGH_MEMORY;
        else {
            error = RegGetKeySecurity(opened, information, descriptor, &bytes);
            if (error == ERROR_SUCCESS) error = (LSTATUS)pb_install_store_check_security(descriptor);
            free(descriptor);
        }
    } else if (error == ERROR_SUCCESS || error == ERROR_INSUFFICIENT_BUFFER) {
        error = ERROR_INVALID_SECURITY_DESCR;
    }
    if (error != ERROR_SUCCESS) { RegCloseKey(opened); return (DWORD)error; }
    *key = opened;
    return ERROR_SUCCESS;
}

DWORD pb_install_store_open(BOOL create, HKEY *key)
{
    return open_store(create, create, key);
}

DWORD pb_install_store_open_existing_write(HKEY *key)
{
    return open_store(FALSE, TRUE, key);
}
