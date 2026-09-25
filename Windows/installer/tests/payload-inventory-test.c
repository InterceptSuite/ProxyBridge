#include "../install-payload.h"
#include <stdio.h>
#include <stdlib.h>
int wmain(int argc, WCHAR **argv)
{
    if (argc != 3) return 1;
    DWORD expected = wcstoul(argv[2], NULL, 10);
    DWORD error = pb_payload_check_inventory(argv[1]);
    printf("Inventory result: %lu (expected %lu)\n", error, expected);
    return error == expected ? 0 : 1;
}
