#include "../install-store.h"
#include <sddl.h>
#include <stdio.h>

int main(void)
{
    const struct { const WCHAR *sddl; BOOL allowed; } cases[] = {
        {L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", TRUE},
        {L"O:SYG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", TRUE},
        {L"O:BUG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", FALSE},
        {L"O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)", FALSE},
        {L"O:BAG:BAD:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)", FALSE},
        {L"O:BAG:BAD:P(A;;KA;;;WD)", FALSE}
    };
    for (unsigned i = 0; i < ARRAYSIZE(cases); ++i) {
        PSECURITY_DESCRIPTOR descriptor = NULL;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(cases[i].sddl, SDDL_REVISION_1, &descriptor, NULL)) return 1;
        BOOL allowed = pb_install_store_check_security(descriptor) == ERROR_SUCCESS;
        LocalFree(descriptor);
        if (allowed != cases[i].allowed) { printf("Security case %u failed\n", i); return 1; }
    }
    puts("Journal security descriptor checks passed; no key created or modified.");
    return 0;
}
