#include "../startup-installed.h"
#include <sddl.h>
#include <stdio.h>
DWORD pb_startup_task_apply(PB_STARTUP_OPERATION op,const WCHAR *root,const WCHAR *path,BOOL *enabled) {
    (void)op;(void)root;(void)path;(void)enabled; return ERROR_CALL_NOT_IMPLEMENTED;
}
int main(void)
{
    const struct { const WCHAR *text; DWORD expected; } cases[] = {
        {L"O:BAG:BAD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FRFX;;;BU)", 0},
        {L"O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)", 0},
        {L"O:BUG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;WD)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:(A;;FA;;;BA)(A;;FRFX;;;BU)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:(A;;FA;;;SY)(A;;FRFX;;;BU)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:(A;IO;FA;;;SY)(A;;FA;;;BA)", ERROR_ACCESS_DENIED},
        {L"O:BAG:BAD:(D;;FW;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)", ERROR_ACCESS_DENIED}
    };
    for (unsigned i = 0; i < ARRAYSIZE(cases); ++i) {
        PSECURITY_DESCRIPTOR descriptor = NULL;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(cases[i].text, SDDL_REVISION_1, &descriptor, NULL)) return 2;
        DWORD error = pb_startup_file_security(descriptor); LocalFree(descriptor);
        if (error != cases[i].expected) { printf("FAIL file ACL case %u: %lu\n", i, error); return 1; }
    }
    if (pb_startup_file_security(NULL) != ERROR_ACCESS_DENIED) return 1;
    puts("PASS startup file security: inherited/protected ACLs, owner and unexpected rights rejection");
    return 0;
}
