#include <windows.h>
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <map>
#include <vector>
#include <stdio.h>
extern "C" {
#include "../install-stage.h"
#include "../startup-installed.h"
#include "../startup-identity.h"
#include "../install-bootstrap-retention.h"
#include "../install-store.h"
#include "../install-layout.h"
}
static std::wstring fixtureBase;
struct Value { DWORD type; std::vector<BYTE> bytes; };
static std::map<std::wstring,Value> fixtureValues;
static BOOL keyExists;
static std::wstring failValue;
static BOOL failDelete;
static unsigned taskCalls;
static DWORD taskError,flushError,eraseValueError;
static BOOL unsafeDesktop;
static DWORD open_fixture(const std::wstring &path,PB_VERIFIED_PAYLOAD *guard,HANDLE *out){
    ZeroMemory(guard,sizeof(*guard));*out=nullptr;
    HANDLE h=CreateFileW(path.c_str(),FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    if(h==INVALID_HANDLE_VALUE)return GetLastError();
    guard->directories[guard->directoryCount++]=h;*out=h;return 0;
}
static DWORD fixture_bootstrap(const WCHAR *hash,PB_VERIFIED_PAYLOAD *guard,HANDLE *out){
    return open_fixture(fixtureBase+L"\\InterceptSuite.ProxyBridge\\bootstrap\\"+hash,guard,out);
}
static DWORD fixture_programs(BOOL create,PB_VERIFIED_PAYLOAD *guard,HANDLE *out){(void)create;return open_fixture(fixtureBase+L"\\Programs",guard,out);}
static DWORD fixture_product(BOOL create,PB_VERIFIED_PAYLOAD *guard,HANDLE *out){(void)create;return open_fixture(fixtureBase+L"\\Program Files\\InterceptSuite\\ProxyBridge",guard,out);}
static BOOL fixture_launcher(const WCHAR *root,const WCHAR *path){
    return !_wcsicmp(path,(fixtureBase+L"\\Program Files\\InterceptSuite\\ProxyBridge\\ProxyBridgeLauncher.exe").c_str()) || pb_startup_launcher_path(root,path);
}
static HRESULT fixture_folder(HWND w,int id,HANDLE token,DWORD flags,LPWSTR path){
    (void)w;(void)token;(void)flags;
    if(id!=CSIDL_COMMON_APPDATA && id!=CSIDL_COMMON_DESKTOPDIRECTORY && id!=CSIDL_PROGRAM_FILES)return E_INVALIDARG;
    std::wstring value=fixtureBase+(id==CSIDL_COMMON_DESKTOPDIRECTORY?L"\\Desktop":id==CSIDL_PROGRAM_FILES?L"\\Program Files":L"");
    return wcscpy_s(path,MAX_PATH,value.c_str())?E_FAIL:S_OK;
}
static DWORD fixture_security(HANDLE h,SE_OBJECT_TYPE type,SECURITY_INFORMATION flags,PSID *owner,PSID *group,
    PACL *dacl,PACL *sacl,PSECURITY_DESCRIPTOR *out){
    (void)h;(void)type;(void)flags;(void)owner;(void)group;(void)dacl;(void)sacl;
    BOOL desktop=FALSE;WCHAR objectPath[MAX_PATH];
    if(GetFinalPathNameByHandleW(h,objectPath,MAX_PATH,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS))
        desktop=wcsstr(objectPath,L"\\Desktop")!=nullptr;
    const WCHAR *sddl=unsafeDesktop && desktop?
        L"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)":
        L"O:BAG:BAD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FRFX;;;BU)";
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,
        SDDL_REVISION_1,out,nullptr))return GetLastError();
    BOOL present,defaulted;
    if(owner)GetSecurityDescriptorOwner(*out,owner,&defaulted);
    if(dacl)GetSecurityDescriptorDacl(*out,&present,dacl,&defaulted);
    return 0;
}
static LSTATUS WINAPI fake_open(HKEY parent,LPCWSTR name,DWORD options,REGSAM access,PHKEY key){
    (void)parent;(void)name;(void)options;(void)access;*key=keyExists?(HKEY)1:nullptr;return keyExists?0:ERROR_FILE_NOT_FOUND;
}
static LSTATUS WINAPI fake_create(HKEY parent,LPCWSTR name,DWORD reserved,LPWSTR klass,DWORD options,REGSAM access,
    const LPSECURITY_ATTRIBUTES security,PHKEY key,LPDWORD disposition){
    (void)parent;(void)name;(void)reserved;(void)klass;(void)options;(void)access;(void)security;(void)disposition;
    keyExists=TRUE;*key=(HKEY)1;return 0;
}
static LSTATUS WINAPI fake_get(HKEY key,LPCWSTR subkey,LPCWSTR name,DWORD flags,LPDWORD type,PVOID data,LPDWORD bytes){
    (void)key;(void)subkey;(void)flags;auto found=fixtureValues.find(name);if(found==fixtureValues.end())return ERROR_FILE_NOT_FOUND;
    DWORD needed=(DWORD)found->second.bytes.size(),given=*bytes;*bytes=needed;
    if(type)*type=found->second.type;if(given<needed)return ERROR_MORE_DATA;
    memcpy(data,found->second.bytes.data(),needed);return 0;
}
static LSTATUS WINAPI fake_set(HKEY key,LPCWSTR name,DWORD reserved,DWORD type,const BYTE *data,DWORD bytes){
    (void)key;(void)reserved;if(failValue==name)return ERROR_WRITE_FAULT;
    fixtureValues[name]={type,std::vector<BYTE>(data,data+bytes)};return 0;
}
static LSTATUS WINAPI fake_close(HKEY key){(void)key;return 0;}
static LSTATUS WINAPI fake_flush(HKEY key){(void)key;return flushError;}
static LSTATUS WINAPI fake_erase_value(HKEY key,LPCWSTR name){
    (void)key;if(eraseValueError)return eraseValueError;
    return fixtureValues.erase(name)?0:ERROR_FILE_NOT_FOUND;
}
static LSTATUS WINAPI fake_delete(HKEY key,LPCWSTR subkey,REGSAM view,DWORD reserved){
    (void)key;(void)subkey;(void)view;(void)reserved;if(failDelete)return ERROR_ACCESS_DENIED;
    keyExists=FALSE;fixtureValues.clear();return 0;
}
static DWORD fake_task(PB_STARTUP_OPERATION operation,BOOL *enabled){(void)operation;++taskCalls;*enabled=FALSE;return taskError;}
static unsigned retirementCalls,collectionCalls;
static DWORD retireError;
static DWORD fake_store(HKEY *key){*key=(HKEY)2;return 0;}
static DWORD fake_journal(HKEY key,PB_INSTALL_JOURNAL *record){(void)key;ZeroMemory(record,sizeof(*record));return 0;}
static DWORD fake_retire(HKEY key,const WCHAR *hash){(void)key;(void)hash;++retirementCalls;return retireError;}
static DWORD fake_collect(HKEY key,const PB_INSTALL_JOURNAL *record,const WCHAR *hash,PB_BOOTSTRAP_REFERENCED callback,void *context){
    (void)key;(void)record;(void)hash;(void)callback;(void)context;++collectionCalls;return 0;
}
#define pb_install_store_open_existing_write fake_store
#define pb_journal_read fake_journal
#define pb_bootstrap_retire fake_retire
#define pb_bootstrap_collect fake_collect
#define pb_bootstrap_root_read fixture_bootstrap
#define pb_programs_root_open fixture_programs
#define pb_product_root_open fixture_product
#define pb_startup_launcher_path fixture_launcher
#define SHGetFolderPathW fixture_folder
#define GetSecurityInfo fixture_security
#define RegOpenKeyExW fake_open
#define RegCreateKeyExW fake_create
#define RegGetValueW fake_get
#define RegSetValueExW fake_set
#define RegCloseKey fake_close
#define RegFlushKey fake_flush
#define RegDeleteKeyExW fake_delete
#define RegDeleteValueW fake_erase_value
#define pb_startup_installed fake_task
#include "../install-registration.cpp"

#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
static BOOL mkdir_new(const std::wstring &path){return CreateDirectoryW(path.c_str(),nullptr);}
static BOOL file_new(const std::wstring &path){
    HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE)return FALSE;DWORD bytes=0;
    BOOL ok=WriteFile(h,"INERT FIXTURE",13,&bytes,nullptr);CloseHandle(h);return ok && bytes==13;
}
static std::wstring location(){
    auto found=fixtureValues.find(L"InstallLocation");if(found==fixtureValues.end())return L"";
    std::wstring result(found->second.bytes.size()/sizeof(WCHAR),L'\0');
    memcpy(&result[0],found->second.bytes.data(),found->second.bytes.size());result.resize(result.size()-1);return result;
}
static HRESULT rewrite_fixture_link(const std::wstring &path,const std::wstring &target,const WCHAR *arguments=L""){
    RegistrationPtr<IShellLinkW> link;RegistrationPtr<IPersistFile> persist;
    HRESULT hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&link.p);
    if(SUCCEEDED(hr))hr=link->QueryInterface(IID_IPersistFile,(void**)&persist.p);
    if(SUCCEEDED(hr))hr=link->SetPath(target.c_str());
    if(SUCCEEDED(hr))hr=link->SetArguments(arguments);
    if(SUCCEEDED(hr))hr=persist->Save(path.c_str(),TRUE);return hr;
}
static BOOL link_matches(const std::wstring &path,const std::wstring &target){
    RegistrationPtr<IShellLinkW> link;RegistrationPtr<IPersistFile> persist;
    HRESULT hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&link.p);
    if(SUCCEEDED(hr))hr=link->QueryInterface(IID_IPersistFile,(void**)&persist.p);
    if(SUCCEEDED(hr))hr=persist->Load(path.c_str(),STGM_READ);
    WCHAR actual[MAX_PATH],icon[MAX_PATH];int index=-1;
    if(SUCCEEDED(hr))hr=link->GetPath(actual,MAX_PATH,nullptr,SLGP_RAWPATH);
    if(SUCCEEDED(hr))hr=link->GetIconLocation(icon,MAX_PATH,&index);
    return SUCCEEDED(hr) && !_wcsicmp(actual,target.c_str()) && !_wcsicmp(icon,target.c_str()) && index==0;
}
int wmain(int argc,WCHAR **argv){
    CHECK(argc==2);fixtureBase=argv[1];
    const WCHAR *a=L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const WCHAR *b=L"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const WCHAR *c=L"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    CHECK(mkdir_new(fixtureBase+L"\\InterceptSuite.ProxyBridge"));
    CHECK(mkdir_new(fixtureBase+L"\\InterceptSuite.ProxyBridge\\bootstrap"));
    CHECK(mkdir_new(fixtureBase+L"\\Programs"));
    CHECK(mkdir_new(fixtureBase+L"\\Desktop"));
    std::wstring base=fixtureBase+L"\\InterceptSuite.ProxyBridge\\bootstrap\\",dirA=base+a,dirB=base+b;
    for(const auto &dir:{dirA,dirB,base+c}){
        CHECK(mkdir_new(dir));
        for(const auto name:{L"ProxyBridgeLauncher.exe",L"ProxyBridgeDriverSetup.exe",L"uninstall.exe"})CHECK(file_new(dir+L"\\"+name));
    }
    CHECK(pb_registration_apply(a,0)==0 && !keyExists && taskCalls==0);
    CHECK(GetFileAttributesW((fixtureBase+L"\\Programs\\Recovery-"+a+L".lnk").c_str())==INVALID_FILE_ATTRIBUTES);
    unsafeDesktop=TRUE;
    CHECK(pb_registration_apply(a,1)==ERROR_ACCESS_DENIED && !keyExists);
    unsafeDesktop=FALSE;
    CHECK(pb_registration_apply(a,1)==0 && location()==dirA);
    CHECK(pb_registration_apply(a,1)==0); // Idempotent repair.
    CHECK(SUCCEEDED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED)));
    CHECK(link_matches(fixtureBase+L"\\Desktop\\ProxyBridge.lnk",dirA+L"\\ProxyBridgeLauncher.exe"));
    CHECK(SUCCEEDED(rewrite_fixture_link(fixtureBase+L"\\Programs\\ProxyBridge.lnk",L"C:\\foreign.exe")));
    CHECK(pb_registration_apply(b,1)==ERROR_ACCESS_DENIED && location()==dirA);
    CHECK(SUCCEEDED(rewrite_fixture_link(fixtureBase+L"\\Programs\\ProxyBridge.lnk",dirA+L"\\ProxyBridgeLauncher.exe")));
    failValue=L"DisplayIcon";
    CHECK(pb_registration_apply(b,1)==ERROR_WRITE_FAULT && location()==dirA);
    failValue.clear();
    flushError=ERROR_WRITE_FAULT;
    CHECK(pb_registration_apply(b,1)==flushError && location()==dirA);
    flushError=0;taskError=ERROR_ACCESS_DENIED;
    CHECK(pb_registration_apply(b,1)==taskError && location()==dirB && fixtureValues.count(L"RetiringBootstrap"));
    unsigned beforeBlocked=taskCalls;
    CHECK(pb_registration_apply(c,1)==ERROR_BUSY && location()==dirB && taskCalls==beforeBlocked);
    std::wstring recoveryA=fixtureBase+L"\\Programs\\Recovery-"+a+L".lnk";
    std::wstring resumeA=std::wstring(L"resume-package ")+a;
    // A package predating the journal-only recovery design may have left this
    // owned technical link. Updating it must still reject a foreign rewrite
    // and remove the owned original once retirement completes.
    CHECK(shortcut((fixtureBase+L"\\Programs").c_str(),(L"Recovery-"+std::wstring(a)+L".lnk").c_str(),
        (dirA+L"\\ProxyBridgeDriverSetup.exe").c_str(),resumeA.c_str(),nullptr,FALSE)==0);
    CHECK(GetFileAttributesW(recoveryA.c_str())!=INVALID_FILE_ATTRIBUTES);
    taskError=0;
    CHECK(SUCCEEDED(rewrite_fixture_link(recoveryA,L"C:\\foreign.exe")));
    CHECK(pb_registration_apply(b,1)==ERROR_ACCESS_DENIED && fixtureValues.count(L"RetiringBootstrap"));
    CHECK(SUCCEEDED(rewrite_fixture_link(recoveryA,dirA+L"\\ProxyBridgeDriverSetup.exe",resumeA.c_str())));
    retireError=ERROR_WRITE_FAULT;
    CHECK(pb_registration_apply(b,1)==retireError && fixtureValues.count(L"RetiringBootstrap"));
    retireError=0;
    eraseValueError=ERROR_ACCESS_DENIED;
    CHECK(pb_registration_apply(b,1)==eraseValueError && fixtureValues.count(L"RetiringBootstrap"));
    CHECK(GetFileAttributesW(recoveryA.c_str())==INVALID_FILE_ATTRIBUTES);
    eraseValueError=0;CHECK(pb_registration_apply(b,1)==0 && location()==dirB && !fixtureValues.count(L"RetiringBootstrap"));
    CHECK(link_matches(fixtureBase+L"\\Desktop\\ProxyBridge.lnk",dirB+L"\\ProxyBridgeLauncher.exe"));
    std::wstring menuPath=fixtureBase+L"\\Programs";
    std::wstring desktopPath=fixtureBase+L"\\Desktop";
    BootstrapReferences refs={menuPath.c_str(),desktopPath.c_str()};BOOL referenced=FALSE;
    CHECK(!bootstrap_referenced(&refs,dirB.c_str(),&referenced) && referenced);
    CHECK(!bootstrap_referenced(&refs,dirA.c_str(),&referenced) && !referenced);
    CHECK(SUCCEEDED(rewrite_fixture_link(desktopPath+L"\\ProxyBridge.lnk",dirA+L"\\ProxyBridgeLauncher.exe")));
    CHECK(!bootstrap_referenced(&refs,dirA.c_str(),&referenced) && referenced);
    CHECK(pb_registration_apply(b,1)==ERROR_ACCESS_DENIED);
    CHECK(SUCCEEDED(rewrite_fixture_link(desktopPath+L"\\ProxyBridge.lnk",dirB+L"\\ProxyBridgeLauncher.exe")));
    CHECK(SUCCEEDED(rewrite_fixture_link(menuPath+L"\\Custom.lnk",dirA+L"\\ProxyBridgeLauncher.exe")));
    CHECK(!bootstrap_referenced(&refs,dirA.c_str(),&referenced) && referenced);
    unsigned before=taskCalls;CHECK(pb_registration_apply(a,2)==ERROR_REVISION_MISMATCH && taskCalls==before);
    taskError=ERROR_ACCESS_DENIED;CHECK(pb_registration_apply(b,2)==ERROR_ACCESS_DENIED && keyExists);
    taskError=0;failDelete=TRUE;CHECK(pb_registration_apply(b,2)==ERROR_ACCESS_DENIED && keyExists);
    failDelete=FALSE;CHECK(pb_registration_apply(b,2)==0 && !keyExists);
    CHECK(GetFileAttributesW((desktopPath+L"\\ProxyBridge.lnk").c_str())==INVALID_FILE_ATTRIBUTES);
    CHECK(pb_registration_apply(b,2)==0); // Missing links/key are retryable success.
    CHECK(mkdir_new(fixtureBase+L"\\Program Files"));
    CHECK(mkdir_new(fixtureBase+L"\\Program Files\\InterceptSuite"));
    std::wstring flat=fixtureBase+L"\\Program Files\\InterceptSuite\\ProxyBridge";
    CHECK(mkdir_new(flat));
    for(const auto name:{L"ProxyBridgeLauncher.exe",L"ProxyBridgeDriverSetup.exe",L"uninstall.exe"})CHECK(file_new(flat+L"\\"+name));
    // Legacy links with no registration (manual cleanup) migrate by exact
    // owned path/action, not by their title alone.
    CHECK(shortcut(menuPath.c_str(),L"ProxyBridge.lnk",(dirA+L"\\ProxyBridgeLauncher.exe").c_str(),L"",nullptr,FALSE)==0);
    CHECK(shortcut(menuPath.c_str(),L"Resume installation.lnk",(dirA+L"\\ProxyBridgeDriverSetup.exe").c_str(),resumeA.c_str(),nullptr,FALSE)==0);
    CHECK(shortcut(menuPath.c_str(),(L"Recovery-"+std::wstring(a)+L".lnk").c_str(),(dirA+L"\\ProxyBridgeDriverSetup.exe").c_str(),resumeA.c_str(),nullptr,FALSE)==0);
    CHECK(!pb_registration_flat(FALSE) && location()==flat);
    CHECK(link_matches(menuPath+L"\\ProxyBridge.lnk",flat+L"\\ProxyBridgeLauncher.exe"));
    CHECK(link_matches(desktopPath+L"\\ProxyBridge.lnk",flat+L"\\ProxyBridgeLauncher.exe"));
    CHECK(GetFileAttributesW(recoveryA.c_str())==INVALID_FILE_ATTRIBUTES);
    CHECK(GetFileAttributesW((menuPath+L"\\Resume installation.lnk").c_str())==INVALID_FILE_ATTRIBUTES);
    CHECK(!pb_registration_flat(FALSE));
    CHECK(SUCCEEDED(rewrite_fixture_link(desktopPath+L"\\ProxyBridge.lnk",L"C:\\foreign.exe")));
    CHECK(pb_registration_flat(TRUE)==ERROR_ACCESS_DENIED && keyExists);
    CHECK(SUCCEEDED(rewrite_fixture_link(desktopPath+L"\\ProxyBridge.lnk",flat+L"\\ProxyBridgeLauncher.exe")));
    CHECK(!pb_registration_flat(TRUE) && !keyExists);CHECK(!pb_registration_flat(TRUE));
    CoUninitialize();
    puts("PASS native registration: A->B, retained retirement across flush/task/delete errors, C blocked until B completes, foreign recovery action preserved, old recovery removed and retries; real fixture shortcuts, registry/security roots/task mocked");return 0;
}
