#include "../install-stage.h"
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
static BOOL denySecurity;
static int deleteCountdown = -1;
static DWORD fixture_security(HANDLE object, SE_OBJECT_TYPE kind, SECURITY_INFORMATION request,
    PSID *owner, PSID *group, PACL *dacl, PACL *sacl, PSECURITY_DESCRIPTOR *out)
{
    (void)object;(void)kind;(void)request;(void)group;(void)sacl;
    if(denySecurity)return ERROR_ACCESS_DENIED;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)",SDDL_REVISION_1,out,NULL))return GetLastError();
    BOOL defaulted,present;
    if(owner)GetSecurityDescriptorOwner(*out,owner,&defaulted);
    if(dacl)GetSecurityDescriptorDacl(*out,&present,dacl,&defaulted);
    return 0;
}
static BOOL WINAPI fixture_disposition(HANDLE file,FILE_INFO_BY_HANDLE_CLASS kind,void *info,DWORD size)
{
    if(deleteCountdown==0){SetLastError(ERROR_SHARING_VIOLATION);return FALSE;}
    if(deleteCountdown>0)--deleteCountdown;
    return SetFileInformationByHandle(file,kind,info,size);
}
#define GetSecurityInfo fixture_security
#define SetFileInformationByHandle fixture_disposition
#include "../install-stage.c"
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s (Win=%lu)\n",__LINE__,#x,GetLastError());return 1;}}while(0)
static BOOL write_file(const WCHAR *dir,const WCHAR *name)
{
    WCHAR path[MAX_PATH];swprintf_s(path,MAX_PATH,L"%s\\%s",dir,name);
    HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);
    if(file==INVALID_HANDLE_VALUE)return FALSE;
    DWORD written=0;BOOL ok=WriteFile(file,"partial",7,&written,NULL);CloseHandle(file);return ok && written==7;
}
static BOOL exists(const WCHAR *dir,const WCHAR *name)
{WCHAR path[MAX_PATH];swprintf_s(path,MAX_PATH,L"%s\\%s",dir,name);return GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES;}
int wmain(int argc,WCHAR **argv)
{
    CHECK(argc==2);PB_VERIFIED_PAYLOAD guard={0};CHECK(!pb_payload_lock_directory(argv[1],&guard));
    HANDLE root=guard.directories[guard.directoryCount-1];GUID id={0};WCHAR target[MAX_PATH],driver[MAX_PATH],path[MAX_PATH];
    id.Data1=1;CHECK(!pb_stage_target_path(root,&id,target));
    CHECK(!pb_stage_cleanup_partial(root,&id,target)); // Intent flushed, no directory yet.
    for(unsigned files=0;files<=PB_PAYLOAD_FILES+1;++files){
        id.Data1=files+2;CHECK(!pb_stage_target_path(root,&id,target));CHECK(CreateDirectoryW(target,NULL));
        swprintf_s(driver,MAX_PATH,L"%s\\driver",target);
        if(files)CHECK(CreateDirectoryW(driver,NULL));
        for(unsigned i=0;i<files;++i)CHECK(write_file(target,pb_payload_file_name(i)));
        CHECK(!pb_stage_cleanup_partial(root,&id,target));
        CHECK(!pb_stage_cleanup_partial(root,&id,target));
        for(unsigned i=0;i<files;++i)CHECK(!exists(target,pb_payload_file_name(i)));
    }
    id.Data1=30;CHECK(!pb_stage_target_path(root,&id,target));CHECK(CreateDirectoryW(target,NULL));
    CHECK(write_file(target,L"ProxyBridge.exe"));CHECK(write_file(target,L"foreign.txt"));
    CHECK(pb_stage_cleanup_partial(root,&id,target)==ERROR_INVALID_DATA && exists(target,L"ProxyBridge.exe"));
    CHECK(pb_stage_cleanup_partial(root,&id,argv[1])==ERROR_INVALID_NAME);
    id.Data1=31;CHECK(!pb_stage_target_path(root,&id,target));CHECK(CreateDirectoryW(target,NULL));
    CHECK(write_file(target,L"ProxyBridge.exe"));CHECK(write_file(target,L"ProxyBridgeCore.dll"));
    swprintf_s(path,MAX_PATH,L"%s\\ProxyBridgeCore.dll",target);
    HANDLE busy=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);CHECK(busy!=INVALID_HANDLE_VALUE);
    CHECK(pb_stage_cleanup_partial(root,&id,target)==ERROR_SHARING_VIOLATION && exists(target,L"ProxyBridge.exe"));
    CloseHandle(busy);
    denySecurity=TRUE;CHECK(pb_stage_cleanup_partial(root,&id,target)==ERROR_ACCESS_DENIED && exists(target,L"ProxyBridge.exe"));denySecurity=FALSE;
    deleteCountdown=1;CHECK(pb_stage_cleanup_partial(root,&id,target)==ERROR_SHARING_VIOLATION);
    deleteCountdown=-1;CHECK(!pb_stage_cleanup_partial(root,&id,target));CHECK(!exists(target,L"ProxyBridge.exe") && !exists(target,L"ProxyBridgeCore.dll"));
    pb_payload_close(&guard);
    puts("PASS partial stage: absent/empty/each file boundary/truncated manifest, idempotence, foreign entry, root escape, pinned file, security refusal, partial deletion retry. Real files; security descriptor adapter.");return 0;
}
