#include "../install-stage.h"
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>
static WCHAR programs[MAX_PATH], data[MAX_PATH];
static BOOL deny;
static HRESULT fixture_folder(HWND w,int id,HANDLE token,DWORD flags,LPWSTR out) {
    (void)w;(void)token;(void)flags;
    const WCHAR *path=id==CSIDL_PROGRAM_FILES?programs:id==CSIDL_COMMON_APPDATA?data:NULL;
    return path && !wcscpy_s(out,MAX_PATH,path)?S_OK:E_FAIL;
}
static DWORD security(HANDLE h,SE_OBJECT_TYPE t,SECURITY_INFORMATION f,PSID *o,PSID *g,PACL *d,PACL *s,PSECURITY_DESCRIPTOR *out) {
    (void)h;(void)t;(void)f;(void)o;(void)g;(void)d;(void)s;
    if(deny)return ERROR_ACCESS_DENIED;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)",
        SDDL_REVISION_1,out,NULL))return GetLastError();
    BOOL present,defaulted;
    if(o)GetSecurityDescriptorOwner(*out,o,&defaulted);
    if(d)GetSecurityDescriptorDacl(*out,&present,d,&defaulted);
    return 0;
}
static BOOL WINAPI fixture_create(LPCWSTR path,LPSECURITY_ATTRIBUTES attributes) {
    (void)attributes;return CreateDirectoryW(path,NULL);
}
#define CreateDirectoryW fixture_create
#define SHGetFolderPathW fixture_folder
#define GetSecurityInfo security
#include "../install-stage.c"
#define CHECK(x) do {if(!(x)){printf("FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int wmain(int argc,WCHAR **argv) {
    CHECK(argc==2);
    CHECK(swprintf_s(programs,MAX_PATH,L"%s\\Program Files",argv[1])>0);
    CHECK(swprintf_s(data,MAX_PATH,L"%s\\ProgramData",argv[1])>0);
    CHECK(CreateDirectoryW(programs,NULL));CHECK(CreateDirectoryW(data,NULL));
    PB_VERIFIED_PAYLOAD oldGuard={0},newGuard={0},readGuard={0}; HANDLE oldRoot=NULL,newRoot=NULL,readRoot=NULL;
    DWORD result=protected_folder_open(CSIDL_COMMON_APPDATA,L"\\InterceptSuite.ProxyBridge",&oldGuard,&oldRoot,L"\\versions",NULL,TRUE);
    if(result)printf("legacy root error=%lu\n",result);
    CHECK(!result);
    CHECK(!pb_stage_root_read(&readGuard,&readRoot)); // Read-only fallback before migration.
    pb_payload_close(&readGuard);
    CHECK(!pb_stage_root_open(&newGuard,&newRoot));
    GUID id={1,0,0,{0}}; WCHAR oldPath[MAX_PATH],newPath[MAX_PATH],wrong[MAX_PATH];
    CHECK(!pb_stage_target_path(oldRoot,&id,oldPath));
    CHECK(!pb_stage_target_path(newRoot,&id,newPath));
    CHECK(wcsstr(newPath,L"\\Program Files\\InterceptSuite\\ProxyBridge\\versions\\")!=NULL);
    CHECK(!pb_stage_validate_target(newRoot,&id,newPath));
    CHECK(!pb_stage_validate_target(newRoot,&id,oldPath));
    CHECK(!pb_stage_cleanup_partial(newRoot,&id,oldPath)); // Absent pending output.
    CHECK(CreateDirectoryW(oldPath,NULL));
    CHECK(!pb_stage_cleanup_partial(newRoot,&id,oldPath)); // Empty old pending output.
    id.Data1=2;CHECK(pb_stage_validate_target(newRoot,&id,oldPath)==ERROR_INVALID_NAME);
    CHECK(swprintf_s(wrong,MAX_PATH,L"%s\\{00000001-0000-0000-0000-000000000000}",programs)>0);
    CHECK(pb_stage_cleanup_partial(newRoot,&id,wrong)==ERROR_INVALID_NAME);
    deny=TRUE;id.Data1=1;
    CHECK(pb_stage_validate_target(newRoot,&id,oldPath)==ERROR_ACCESS_DENIED);
    deny=FALSE;
    CHECK(!pb_stage_root_read(&readGuard,&readRoot));
    CHECK(direct_version_child(readRoot,newPath));
    pb_payload_close(&readGuard);pb_payload_close(&newGuard);pb_payload_close(&oldGuard);
    puts("PASS new Program Files root, legacy read/cleanup, exact GUID/root and ACL refusal; real fixture filesystem, known folders/security adapted.");return 0;
}
