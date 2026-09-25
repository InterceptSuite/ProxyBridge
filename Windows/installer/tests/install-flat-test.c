#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include "../install-journal.h"
#include "../install-payload.h"
#include "../install-layout.h"
#include "../install-registration.h"
#include "../install-trace.h"
#define PBDRV_PROTOCOL_VERSION 4
#define PBDRV_DRIVER_VERSION 65537
static PB_INSTALL_JOURNAL fixture_stored;
static BOOL hasRecord, hasDevice, rebootInstall, rebootRemove;
static unsigned writes, copies, installs, removes, registrations, cleanups, fileRemovals;
static DWORD sourceError, copyError, driverError, registryError, cleanupError, serviceError, bindingError, flushError, removalPendingError;
static const WCHAR fixture_instance[] = L"ROOT\\InterceptSuite_ProxyBridge\\TEST";
static const WCHAR fixture_hashText[] = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
#define CHECK(x) do {if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
static LSTATUS WINAPI query(HKEY k,LPCWSTR n,LPDWORD r,LPDWORD type,LPBYTE data,LPDWORD size) {
    (void)k;(void)n;(void)r;if(!hasRecord)return ERROR_FILE_NOT_FOUND;
    if(*size<sizeof(fixture_stored))return ERROR_MORE_DATA;*type=REG_BINARY;*size=sizeof(fixture_stored);memcpy(data,&fixture_stored,sizeof(fixture_stored));return 0;
}
static LSTATUS WINAPI put(HKEY k,LPCWSTR n,DWORD r,DWORD type,const BYTE *data,DWORD size) {
    (void)k;(void)n;(void)r;(void)type;if(size!=sizeof(fixture_stored))return ERROR_INVALID_DATA;
    memcpy(&fixture_stored,data,size);hasRecord=TRUE;++writes;return 0;
}
static LSTATUS WINAPI flush(HKEY k){(void)k;return flushError;}
#define RegQueryValueExW query
#define RegSetValueExW put
#define RegFlushKey flush
#include "../install-journal.c"
static HRESULT WINAPI folder(HWND w,int id,HANDLE t,DWORD f,LPWSTR path){(void)w;(void)id;(void)t;(void)f;wcscpy_s(path,MAX_PATH,L"C:\\Program Files");return S_OK;}
static HDEVINFO WINAPI fixture_devices(const GUID *g,PCWSTR e,HWND w,DWORD f){(void)g;(void)e;(void)w;(void)f;return (HDEVINFO)2;}
static BOOL WINAPI destroy(HDEVINFO d){(void)d;return TRUE;}
static BOOL WINAPI device_id(HDEVINFO d,PSP_DEVINFO_DATA v,PWSTR text,DWORD size,PDWORD required){(void)d;(void)v;(void)required;wcscpy_s(text,size,fixture_instance);return TRUE;}
static BOOL WINAPI close_handle(HANDLE h){(void)h;return TRUE;}
static LSTATUS WINAPI close_key(HKEY k){(void)k;return 0;}
static HRESULT WINAPI guid(GUID *id){ZeroMemory(id,sizeof(*id));id->Data1=writes+1;return S_OK;}
static HANDLE WINAPI source_file(LPCWSTR n,DWORD a,DWORD s,LPSECURITY_ATTRIBUTES sa,DWORD c,DWORD f,HANDLE t){(void)n;(void)a;(void)s;(void)sa;(void)c;(void)f;(void)t;return (HANDLE)3;}
static BOOL WINAPI file_info(HANDLE h,FILE_INFO_BY_HANDLE_CLASS c,LPVOID out,DWORD size){(void)h;(void)c;ZeroMemory(out,size);return TRUE;}
static BOOL WINAPI uninstall_device(HWND w,HDEVINFO d,PSP_DEVINFO_DATA v,DWORD f,PBOOL reboot){(void)w;(void)d;(void)v;(void)f;++removes;*reboot=rebootRemove;if(!rebootRemove)hasDevice=FALSE;return TRUE;}
static BOOL WINAPI uninstall_inf(PCWSTR inf,DWORD f,PVOID r){(void)inf;(void)f;(void)r;return TRUE;}
DWORD pb_install_store_open(BOOL create,HKEY *key){(void)create;*key=(HKEY)1;return 0;}
DWORD pb_install_store_open_existing_write(HKEY *key){*key=(HKEY)1;return 0;}
DWORD pb_payload_open(const WCHAR *dir,const BYTE hash[32],DWORD p,DWORD v,PB_VERIFIED_PAYLOAD *out){
    (void)dir;(void)hash;ZeroMemory(out,sizeof(*out));out->manifest.protocol=p;out->manifest.driverVersion=v;
    for(unsigned i=0;i<=PB_PAYLOAD_FILES;++i)out->files[i]=(HANDLE)3;return sourceError;
}
void pb_payload_close(PB_VERIFIED_PAYLOAD *p){(void)p;}
DWORD pb_payload_lock_directory(const WCHAR *d,PB_VERIFIED_PAYLOAD *p){(void)d;(void)p;return 0;}
DWORD pb_product_overwrite(PB_VERIFIED_PAYLOAD *p,HANDLE l,HANDLE u,const BYTE h[32]){
    (void)p;(void)l;(void)u;(void)h;if(!hasRecord || fixture_stored.phase!=PB_INSTALL_FLAT_COPYING || !pb_journal_blocks_launch(fixture_stored.phase))return ERROR_INVALID_STATE;
    ++copies;return copyError;
}
DWORD pb_product_legacy_cleanup(void){++cleanups;return cleanupError;}
DWORD pb_product_remove_files(void){++fileRemovals;return 0;}
DWORD pb_registration_flat(BOOL remove){(void)remove;++registrations;return registryError;}
DWORD pb_flat_service_check(HANDLE f){(void)f;return serviceError;}
DWORD pb_flat_service_removal_pending(void){return removalPendingError;}
DWORD pb_plan_device_instance(const GUID *id,WCHAR out[200]){(void)id;wcscpy_s(out,200,fixture_instance);return 0;}
static DWORD verify_inf(const WCHAR *inf){(void)inf;return 0;}
static DWORD find_device(HDEVINFO d,SP_DEVINFO_DATA *v,BOOL *exists){(void)d;(void)v;*exists=hasDevice;return 0;}
static DWORD check_service(HDEVINFO d,SP_DEVINFO_DATA *v){(void)d;(void)v;return bindingError;}
static DWORD device_inf(HDEVINFO d,SP_DEVINFO_DATA *v,WCHAR out[MAX_PATH]){(void)d;(void)v;wcscpy_s(out,MAX_PATH,L"oem14.inf");return 0;}
static DWORD install_package(HDEVINFO d,SP_DEVINFO_DATA *v,BOOL exists,const WCHAR *inf,const WCHAR *planned,BOOL rollback,BOOL orphan,BOOL unbound){
    (void)d;(void)v;(void)inf;(void)planned;
    if(rollback || (!exists && !orphan) || fixture_stored.phase!=PB_INSTALL_FLAT_DRIVER)return ERROR_INVALID_STATE;
    if(bindingError && !unbound)return bindingError;
    ++installs;if(driverError)return driverError;hasDevice=TRUE;bindingError=0;return rebootInstall?ERROR_SUCCESS_REBOOT_REQUIRED:0;
}
#define SHGetFolderPathW folder
#define SetupDiGetClassDevsW fixture_devices
#define SetupDiDestroyDeviceInfoList destroy
#define SetupDiGetDeviceInstanceIdW device_id
#define CloseHandle close_handle
#define RegCloseKey close_key
#define CoCreateGuid guid
#define CreateFileW source_file
#define GetFileInformationByHandleEx file_info
#define DiUninstallDevice uninstall_device
#define SetupUninstallOEMInfW uninstall_inf
#include "../install-flat.inc"
static void reset(void){ZeroMemory(&fixture_stored,sizeof(fixture_stored));hasRecord=hasDevice=rebootInstall=rebootRemove=FALSE;writes=copies=installs=removes=registrations=cleanups=fileRemovals=0;sourceError=copyError=driverError=registryError=cleanupError=serviceError=bindingError=flushError=removalPendingError=0;}
static DWORD install(void){return flat_install(L"C:\\input",fixture_hashText,L"C:\\support");}
int main(void){
    reset();CHECK(!install());CHECK(fixture_stored.phase==PB_INSTALL_COMMITTED && !fixture_stored.previousDirectory[0]);
    CHECK(!wcscmp(fixture_stored.targetDirectory,L"C:\\Program Files\\InterceptSuite\\ProxyBridge"));
    CHECK(!install());CHECK(copies==2 && hasDevice); // overwrite/reinstall
    PB_INSTALL_JOURNAL before=fixture_stored;unsigned count=writes;
    sourceError=ERROR_CRC;CHECK(install()==ERROR_CRC && writes==count && !memcmp(&before,&fixture_stored,sizeof(before)));sourceError=0;
    CHECK(flat_uninstall(L"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")==ERROR_REVISION_MISMATCH && !removes);
    CHECK(!flat_uninstall(fixture_hashText));CHECK(fixture_stored.phase==PB_INSTALL_FLAT_REMOVED && fileRemovals==1 && !hasDevice);
    CHECK(!flat_uninstall(fixture_hashText));CHECK(!install()); // removal retry and reinstall
    reset();CHECK(!install());removalPendingError=ERROR_SUCCESS_REBOOT_REQUIRED;
    CHECK(flat_uninstall(fixture_hashText)==ERROR_SUCCESS_REBOOT_REQUIRED && fixture_stored.phase==PB_INSTALL_FLAT_REMOVED && !hasDevice && fileRemovals==1);
    reset();copyError=ERROR_DISK_FULL;CHECK(install()==ERROR_DISK_FULL && fixture_stored.phase==PB_INSTALL_FLAT_COPYING && !installs);
    copyError=0;CHECK(!install());
    reset();flushError=ERROR_WRITE_FAULT;CHECK(install()==ERROR_WRITE_FAULT && !copies && !installs);
    flushError=0;CHECK(!install());
    reset();driverError=ERROR_NOT_READY;CHECK(install()==ERROR_NOT_READY);hasDevice=TRUE;bindingError=ERROR_INVALID_DATA;
    CHECK(!flat_uninstall(fixture_hashText) && fixture_stored.phase==PB_INSTALL_FLAT_REMOVED); // unbound device removal
    reset();driverError=ERROR_NOT_READY;CHECK(install()==ERROR_NOT_READY && fixture_stored.phase==PB_INSTALL_FLAT_DRIVER && !registrations);
    driverError=0;hasDevice=TRUE;bindingError=ERROR_INVALID_DATA;CHECK(!install()); // registered but not yet bound
    reset();rebootInstall=TRUE;CHECK(install()==3010 && fixture_stored.phase==PB_INSTALL_FLAT_PENDING && registrations==1);
    rebootInstall=FALSE;CHECK(!install());
    rebootRemove=TRUE;CHECK(flat_uninstall(fixture_hashText)==3010 && fixture_stored.phase==PB_INSTALL_FLAT_REMOVING && !fileRemovals);
    rebootRemove=FALSE;CHECK(!flat_uninstall(fixture_hashText));
    reset();registryError=ERROR_ACCESS_DENIED;CHECK(install()==ERROR_ACCESS_DENIED && fixture_stored.phase==PB_INSTALL_FLAT_REGISTERING);
    registryError=0;CHECK(!install());
    cleanupError=ERROR_SHARING_VIOLATION;CHECK(install()==ERROR_SHARING_VIOLATION && fixture_stored.phase==PB_INSTALL_FLAT_REGISTERING);
    cleanupError=0;CHECK(!install());
    reset();serviceError=ERROR_REVISION_MISMATCH;CHECK(install()==ERROR_REVISION_MISMATCH && !writes && !copies);
    serviceError=3010;CHECK(install()==3010 && !writes);serviceError=0;
    CHECK(!install());fixture_stored.phase=PB_INSTALL_ROLLING_BACK;wcscpy_s(fixture_stored.targetDirectory,MAX_PATH,L"C:\\ProgramData\\InterceptSuite.ProxyBridge\\versions\\{OLD}");
    CHECK(!install());CHECK(fixture_stored.phase==PB_INSTALL_COMMITTED && !fixture_stored.previousDirectory[0]);
    before=fixture_stored;PB_INSTALL_JOURNAL next=fixture_stored;next.phase=PB_INSTALL_FLAT_COPYING;before.lastError=123;
    CHECK(pb_journal_replace_flat((HKEY)1,&before,&next)==ERROR_REVISION_MISMATCH);
    puts("PASS single-folder coordinator: write-ahead launch block, overwrite/reinstall, all phase retries, reboot install/remove, stale uninstall, foreign service refusal, legacy pending migration, journal CAS. Native APIs adapted; no live install.");return 0;
}
