#include <windows.h>
#include <stdio.h>
int main(void)
{
    setvbuf(stdout,NULL,_IONBF,0);
    HMODULE module=LoadLibraryW(L".\\core-lifecycle-test.dll");
    if (!module) { printf("Load failed %lu\n",GetLastError()); return 1; }
    int (*run)(void)=(int(*)(void))GetProcAddress(module,"run_lifecycle_tests");
    int result=run ? run() : 1;
    if (!FreeLibrary(module)) return 1;
    return result;
}
