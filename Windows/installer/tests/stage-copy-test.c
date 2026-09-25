#include "../install-stage.h"
#include <stdio.h>

int wmain(int argc, WCHAR **argv)
{
    if (argc != 2) return 1;
    PB_VERIFIED_PAYLOAD guard = {0}; HANDLE root = NULL;
    if (pb_bootstrap_root_open(NULL, &guard, &root) != ERROR_INVALID_PARAMETER ||
        pb_bootstrap_root_open(L"..\\outside", &guard, &root) != ERROR_INVALID_PARAMETER ||
        pb_bootstrap_root_open(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/", &guard, &root) != ERROR_INVALID_PARAMETER)
        return 1;
    if (guard.directoryCount || root) return 1;
    WCHAR sourcePath[MAX_PATH], targetPath[MAX_PATH];
    swprintf_s(sourcePath, MAX_PATH, L"%s\\copy-source.bin", argv[1]);
    swprintf_s(targetPath, MAX_PATH, L"%s\\copy-target.bin", argv[1]);
    HANDLE source = CreateFileW(sourcePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    HANDLE target = CreateFileW(targetPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (source == INVALID_HANDLE_VALUE || target == INVALID_HANDLE_VALUE) return 1;
    BYTE input[65536], output[65536];
    for (unsigned i = 0; i < sizeof(input); ++i) input[i] = (BYTE)(i % 251);
    DWORD bytes;
    for (unsigned part = 0; part < 3; ++part)
        if (!WriteFile(source, input, part == 2 ? 123 : sizeof(input), &bytes, NULL)) return 1;
    // Source position starts at EOF as it does after hashing.
    if (pb_stage_copy_file(source, target)) return 1;
    LARGE_INTEGER zero = {0};
    if (!SetFilePointerEx(target, zero, NULL, FILE_BEGIN)) return 1;
    for (unsigned part = 0; part < 3; ++part) {
        DWORD expected = part == 2 ? 123 : sizeof(input);
        if (!ReadFile(target, output, expected, &bytes, NULL) || bytes != expected || memcmp(input, output, bytes)) return 1;
    }
    if (pb_stage_copy_file(source, target) != ERROR_ALREADY_EXISTS) return 1;
    CloseHandle(source); CloseHandle(target);
    puts("Staging multibuffer copy, EOF rewind and overwrite refusal passed; files retained.");
    return 0;
}
