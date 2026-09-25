#include <windows.h>
#include <wchar.h>
#ifndef TEST_VERSION
#error TEST_VERSION required
#endif
int wmain(int argc, WCHAR **argv)
{
    if (argc != 2 || (wcscmp(argv[1], L"--minimized") && wcscmp(argv[1], L"--identity"))) return 99;
    return TEST_VERSION;
}
