#include "../install-stage.h"
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>

static const WCHAR *actualSecurity;
static DWORD fileAttributes = FILE_ATTRIBUTE_DIRECTORY;
static DWORD securityError;
static BOOL mock_attributes(HANDLE h, FILE_INFO_BY_HANDLE_CLASS kind, LPVOID data, DWORD bytes)
{
    (void)h;
    if (kind != FileAttributeTagInfo || bytes != sizeof(FILE_ATTRIBUTE_TAG_INFO)) return FALSE;
    FILE_ATTRIBUTE_TAG_INFO *info = data;
    info->FileAttributes = fileAttributes; info->ReparseTag = 0;
    return TRUE;
}
static DWORD mock_security(HANDLE h, SE_OBJECT_TYPE type, SECURITY_INFORMATION flags,
    PSID *owner, PSID *group, PACL *dacl, PACL *sacl, PSECURITY_DESCRIPTOR *descriptor)
{
    (void)h; (void)type; (void)flags; (void)group; (void)sacl;
    if (securityError) return securityError;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(actualSecurity, SDDL_REVISION_1, descriptor, NULL))
        return GetLastError();
    BOOL defaulted, present;
    GetSecurityDescriptorOwner(*descriptor, owner, &defaulted);
    GetSecurityDescriptorDacl(*descriptor, &present, dacl, &defaulted);
    return 0;
}
// Substitute only metadata retrieval. Production check_root parses and checks
// real Windows security descriptors. No filesystem mutation is performed.
#define GetFileInformationByHandleEx mock_attributes
#define GetSecurityInfo mock_security
#include "../install-stage.c"
#define CHECK(x) do { if (!(x)) { printf("Failure line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    const struct { const WCHAR *sddl; DWORD expected; } cases[] = {
        {L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", 0},
        {L"O:SYG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", 0},
        {L"O:BUG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:P(A;OICI;FA;;;WD)", ERROR_ACCESS_DENIED}
    };
    PSECURITY_DESCRIPTOR expected = NULL;
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(directorySecurity, SDDL_REVISION_1, &expected, NULL));
    for (unsigned i = 0; i < ARRAYSIZE(cases); ++i) {
        actualSecurity = cases[i].sddl;
        CHECK(check_root((HANDLE)1, expected) == cases[i].expected);
    }
    actualSecurity = cases[0].sddl;
    fileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
    CHECK(check_root((HANDLE)1, expected) == ERROR_INVALID_NAME);
    fileAttributes = FILE_ATTRIBUTE_NORMAL;
    CHECK(check_root((HANDLE)1, expected) == ERROR_INVALID_NAME);
    fileAttributes = FILE_ATTRIBUTE_DIRECTORY; securityError = ERROR_ACCESS_DENIED;
    CHECK(check_root((HANDLE)1, expected) == ERROR_ACCESS_DENIED);
    LocalFree(expected);
    puts("Production staging security checks passed; metadata retrieval mocked, no system changes.");
    return 0;
}
