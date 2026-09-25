#include "../install-stage.h"
#include <shlobj.h>
#include <stdio.h>
static const WCHAR *fixtureRoot;
static unsigned creates;
static HRESULT test_folder(HWND w,int id,HANDLE t,DWORD flags,LPWSTR path) {
    (void)w;(void)id;(void)t;(void)flags; return wcscpy_s(path,MAX_PATH,fixtureRoot) ? E_FAIL : S_OK;
}
static BOOL WINAPI forbid_create(LPCWSTR path,LPSECURITY_ATTRIBUTES security) {
    (void)path;(void)security; ++creates; SetLastError(ERROR_ACCESS_DENIED); return FALSE;
}
#define SHGetFolderPathW test_folder
#define CreateDirectoryW forbid_create
#include "../install-stage.c"
int wmain(int argc,WCHAR **argv) {
    if(argc!=2) return 2;
    fixtureRoot=argv[1]; PB_VERIFIED_PAYLOAD guard={0}; HANDLE root=NULL;
    DWORD error=pb_bootstrap_root_read(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",&guard,&root);
    pb_payload_close(&guard);
    if(creates || (error!=ERROR_PATH_NOT_FOUND && error!=ERROR_FILE_NOT_FOUND) || root) return 1;
    puts("PASS read-only bootstrap open: missing product tree rejected, no create attempts"); return 0;
}
