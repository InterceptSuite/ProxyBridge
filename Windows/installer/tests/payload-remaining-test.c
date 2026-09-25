#include "../install-payload.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
int wmain(int argc, WCHAR **argv)
{
    if (argc != 4 || wcslen(argv[2]) != 64) return 1;
    BYTE hash[32];
    for (unsigned i = 0; i < 32; ++i) {
        WCHAR pair[3] = {argv[2][2*i], argv[2][2*i+1], 0}, *end;
        unsigned long value = wcstoul(pair, &end, 16);
        if (*end || value > 255) return 1;
        hash[i] = (BYTE)value;
    }
    PB_VERIFIED_PAYLOAD payload;
    DWORD result = pb_payload_open_remaining(argv[1], hash, 4, 65537, &payload);
    DWORD expected = wcstoul(argv[3], NULL, 10);
    pb_payload_close(&payload);
    if (result != expected) { printf("Expected %lu, got %lu\n", expected, result); return 1; }
    if (!result) {
        result = pb_payload_open(argv[1], hash, 4, 65537, &payload);
        pb_payload_close(&payload);
        if (result != ERROR_FILE_NOT_FOUND) { printf("Strict verification did not reject incomplete payload: %lu\n", result); return 1; }
    }
    puts("Remaining-file verification and strict-install separation passed.");
    return 0;
}
