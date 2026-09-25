#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "../install-flat-service.h"
#include "../install-payload.h"
static WCHAR fixtureWindows[MAX_PATH], servicePath[MAX_PATH];
static DWORD serviceOpenError, serviceType = SERVICE_KERNEL_DRIVER, startType = SERVICE_DEMAND_START;
static SC_HANDLE WINAPI fixture_manager(LPCWSTR m,LPCWSTR d,DWORD a){(void)m;(void)d;(void)a;return (SC_HANDLE)1;}
static SC_HANDLE WINAPI fixture_service(SC_HANDLE m,LPCWSTR n,DWORD a){(void)m;(void)n;(void)a;if(serviceOpenError){SetLastError(serviceOpenError);return NULL;}return (SC_HANDLE)2;}
static BOOL WINAPI close_service(SC_HANDLE s){(void)s;return TRUE;}
static BOOL WINAPI configuration(SC_HANDLE s,LPQUERY_SERVICE_CONFIGW out,DWORD size,LPDWORD needed){
    (void)s;(void)needed;if(size<sizeof(*out))return FALSE;ZeroMemory(out,sizeof(*out));
    out->dwServiceType=serviceType;out->dwStartType=startType;out->lpBinaryPathName=servicePath;return TRUE;
}
static UINT WINAPI windows_dir(LPWSTR out,UINT size){wcscpy_s(out,size,fixtureWindows);return (UINT)wcslen(out);}
DWORD pb_payload_lock_directory(const WCHAR *directory,PB_VERIFIED_PAYLOAD *guard){(void)directory;ZeroMemory(guard,sizeof(*guard));return ERROR_SUCCESS;}
void pb_payload_close(PB_VERIFIED_PAYLOAD *guard){(void)guard;}
#define OpenSCManagerW fixture_manager
#define OpenServiceW fixture_service
#define CloseServiceHandle close_service
#define QueryServiceConfigW configuration
#define GetWindowsDirectoryW windows_dir
#include "../install-flat-service.c"
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s (%lu)\n",__LINE__,#x,GetLastError());return 1;}}while(0)
static BOOL write_file(const WCHAR *path,const char *data){
    HANDLE f=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);if(f==INVALID_HANDLE_VALUE)return FALSE;
    DWORD n=0;BOOL ok=WriteFile(f,data,(DWORD)strlen(data),&n,NULL);CloseHandle(f);return ok && n==strlen(data);
}
int wmain(int argc,WCHAR **argv){
    CHECK(argc==2);wcscpy_s(fixtureWindows,MAX_PATH,argv[1]);WCHAR path[MAX_PATH],input[MAX_PATH];
    swprintf_s(path,MAX_PATH,L"%s\\System32",fixtureWindows);CHECK(CreateDirectoryW(path,NULL));
    swprintf_s(path,MAX_PATH,L"%s\\System32\\drivers",fixtureWindows);CHECK(CreateDirectoryW(path,NULL));
    swprintf_s(servicePath,MAX_PATH,L"%s\\System32\\drivers\\ProxyBridgeDrv.sys",fixtureWindows);CHECK(write_file(servicePath,"verified bytes"));
    swprintf_s(input,MAX_PATH,L"%s\\input.sys",fixtureWindows);CHECK(write_file(input,"verified bytes"));
    HANDLE source=CreateFileW(input,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);CHECK(source!=INVALID_HANDLE_VALUE);
    CHECK(!pb_flat_service_check(source));
    wcscpy_s(servicePath,MAX_PATH,L"\\SystemRoot\\System32\\drivers\\ProxyBridgeDrv.sys");CHECK(!pb_flat_service_check(source));
    serviceType=SERVICE_WIN32_OWN_PROCESS;CHECK(pb_flat_service_check(source)==ERROR_REVISION_MISMATCH);serviceType=SERVICE_KERNEL_DRIVER;
    startType=SERVICE_AUTO_START;CHECK(pb_flat_service_check(source)==ERROR_REVISION_MISMATCH);startType=SERVICE_DEMAND_START;
    wcscpy_s(servicePath,MAX_PATH,input);CHECK(pb_flat_service_check(source)==ERROR_REVISION_MISMATCH);
    swprintf_s(servicePath,MAX_PATH,L"%s\\System32\\drivers\\ProxyBridgeDrv.sys",fixtureWindows);
    CHECK(DeleteFileW(servicePath));CHECK(write_file(servicePath,"different file"));CHECK(pb_flat_service_check(source)==ERROR_REVISION_MISMATCH);
    CHECK(DeleteFileW(servicePath));CHECK(pb_flat_service_check(source)==ERROR_SUCCESS_REBOOT_REQUIRED);
    CHECK(pb_flat_service_removal_pending()==ERROR_SUCCESS_REBOOT_REQUIRED);
    serviceOpenError=ERROR_SERVICE_MARKED_FOR_DELETE;CHECK(pb_flat_service_check(source)==ERROR_SUCCESS_REBOOT_REQUIRED);
    CHECK(pb_flat_service_removal_pending()==ERROR_SUCCESS_REBOOT_REQUIRED);
    serviceOpenError=ERROR_SERVICE_DOES_NOT_EXIST;CHECK(!pb_flat_service_check(source));
    CHECK(pb_flat_service_removal_pending()==ERROR_SUCCESS);
    serviceOpenError=ERROR_ACCESS_DENIED;CHECK(pb_flat_service_removal_pending()==ERROR_ACCESS_DENIED);
    CloseHandle(source);puts("PASS orphan fixture_service gate: matching bytes/SystemRoot, mismatch/type/start/path refusal, absent and pending/missing image, removal reboot gate. Real fixture files; SCM and Windows-root adapters.");return 0;
}
