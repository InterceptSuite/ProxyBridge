#include <windows.h>
#include <wchar.h>

int wmain(int argc, WCHAR **argv)
{
    if (argc == 2 && !wcscmp(argv[1], L"--no-input")) {
        DWORD bytes;
        return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "child-ok", 8, &bytes, NULL) && bytes == 8 ? 37 : 94;
    }
    if (argc != 3 || wcscmp(argv[1], L"--profile") || wcscmp(argv[2], L"C:\\space dir\\quoted\"value\\")) return 91;
    char input[3]; DWORD bytes = 0;
    if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), input, 3, &bytes, NULL) || bytes != 3 ||
        input[0] != 'a' || input[1] != 'b' || input[2] != 'c') return 92;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "child-ok", 8, &bytes, NULL) || bytes != 8) return 93;
    return 37;
}
