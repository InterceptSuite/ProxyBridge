#include "startup-installed.h"
#include "startup-identity.h"
#include "install-stage.h"
#include "install-layout.h"
#include <shlobj.h>
#include <aclapi.h>
#include <wchar.h>
#include <stddef.h>

DWORD pb_startup_file_security(PSECURITY_DESCRIPTOR descriptor)
{
    PSID owner; PACL acl; BOOL defaulted, present;
    if (!descriptor || !IsValidSecurityDescriptor(descriptor) ||
        !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !owner ||
        (!IsWellKnownSid(owner, WinBuiltinAdministratorsSid) && !IsWellKnownSid(owner, WinLocalSystemSid)) ||
        !GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) || !present || !acl || !IsValidAcl(acl))
        return ERROR_ACCESS_DENIED;
    BOOL administrators = FALSE, system = FALSE;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        ACCESS_ALLOWED_ACE *ace;
        if (!GetAce(acl, i, (void **)&ace) || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (ace->Header.AceFlags & INHERIT_ONLY_ACE)) return ERROR_ACCESS_DENIED;
        PSID sid = &ace->SidStart;
        if (ace->Header.AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8 ||
            ace->Header.AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + GetSidLengthRequired(((SID *)sid)->SubAuthorityCount) ||
            !IsValidSid(sid)) return ERROR_ACCESS_DENIED;
        if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) administrators = TRUE;
        else if (IsWellKnownSid(sid, WinLocalSystemSid)) system = TRUE;
        else if (!IsWellKnownSid(sid, WinBuiltinUsersSid) ||
                 (ace->Mask & ~(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE))) return ERROR_ACCESS_DENIED;
    }
    return administrators && system ? 0 : ERROR_ACCESS_DENIED;
}

DWORD pb_startup_installed(PB_STARTUP_OPERATION operation, BOOL *enabled)
{
    if (!enabled) return ERROR_INVALID_PARAMETER;
    *enabled = FALSE;
    WCHAR root[MAX_PATH], launcher[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, root))) return ERROR_PATH_NOT_FOUND;
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE directory = NULL, file = INVALID_HANDLE_VALUE;
    DWORD error = 0;
    if (operation == PB_STARTUP_ENABLE || operation == PB_STARTUP_RETARGET) {
        DWORD bytes = sizeof(launcher);
        error = RegGetValueW(HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\InterceptSuite.ProxyBridge",
            L"InstallLocation", RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, NULL, launcher, &bytes);
        if (error) return error;
        if (bytes < sizeof(WCHAR) || bytes > sizeof(launcher) || bytes % sizeof(WCHAR) ||
            (wcslen(launcher) + 1) * sizeof(WCHAR) != bytes) return ERROR_INVALID_DATA;
        if (wcscat_s(launcher, MAX_PATH, L"\\ProxyBridgeLauncher.exe") || !pb_startup_launcher_path(root, launcher))
            return ERROR_INVALID_NAME;
        WCHAR programs[MAX_PATH]; PB_PRODUCT_LAYOUT layout;
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, SHGFP_TYPE_CURRENT, programs))) return ERROR_PATH_NOT_FOUND;
        error = pb_product_layout(programs, &layout); if (error) return error;
        if (!_wcsicmp(layout.launcher, launcher)) error = pb_product_root_open(FALSE, &guard, &directory);
        else {
            size_t offset = wcslen(root) + wcslen(L"\\InterceptSuite.ProxyBridge\\bootstrap\\");
            WCHAR hash[65]; wmemcpy(hash, launcher + offset, 64); hash[64] = 0;
            error = pb_bootstrap_root_read(hash, &guard, &directory);
        }
        if (error) return error;
        file = CreateFileW(launcher, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file == INVALID_HANDLE_VALUE) error = GetLastError();
        FILE_ATTRIBUTE_TAG_INFO attributes = {0};
        if (!error && !GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes))) error = GetLastError();
        if (!error && (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) error = ERROR_INVALID_NAME;
        PSECURITY_DESCRIPTOR descriptor = NULL;
        if (!error) error = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                           NULL, NULL, NULL, NULL, &descriptor);
        if (!error) error = pb_startup_file_security(descriptor);
        if (descriptor) LocalFree(descriptor);
    }
    if (!error) error = pb_startup_task_apply(operation, root, launcher, enabled);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    pb_payload_close(&guard);
    return error;
}
