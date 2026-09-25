#include "install-registration.h"
extern "C" {
#include "install-stage.h"
#include "startup-installed.h"
#include "startup-identity.h"
#include "install-bootstrap-retention.h"
#include "install-store.h"
#include "install-layout.h"
}
#include <shlobj.h>
#include <aclapi.h>
#include <stdio.h>
#include <wchar.h>
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"uuid.lib")
static const WCHAR registrationKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\InterceptSuite.ProxyBridge";
template<class T> struct RegistrationPtr { T *p=nullptr; ~RegistrationPtr(){if(p)p->Release();} T *operator->() const{return p;} };
struct RegistrationGuard { PB_VERIFIED_PAYLOAD payload={}; ~RegistrationGuard(){pb_payload_close(&payload);} };
struct RegistrationKey { HKEY key=nullptr; ~RegistrationKey(){if(key)RegCloseKey(key);} };
static DWORD registration_error(HRESULT hr){return SUCCEEDED(hr)?0:HRESULT_FACILITY(hr)==FACILITY_WIN32?HRESULT_CODE(hr):(DWORD)hr;}
static DWORD folder_path(HANDLE folder,WCHAR path[MAX_PATH]) {
    WCHAR raw[MAX_PATH]; DWORD length=GetFinalPathNameByHandleW(folder,raw,MAX_PATH,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(!length)return GetLastError();
    if(length>=MAX_PATH || wcsncmp(raw,L"\\\\?\\",4))return ERROR_INVALID_NAME;
    return wcscpy_s(path,MAX_PATH,raw+4)?ERROR_FILENAME_EXCED_RANGE:0;
}
static DWORD join_path(WCHAR result[MAX_PATH],const WCHAR *directory,const WCHAR *name) {
    return swprintf_s(result,MAX_PATH,L"%s\\%s",directory,name)<0?ERROR_FILENAME_EXCED_RANGE:0;
}
// The shared desktop keeps its Windows ACL. Require effective write access to
// remain administrative before replacing links by name in that directory.
static DWORD desktop_security(HANDLE directory) {
    PSID owner=nullptr;PACL acl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    DWORD error=GetSecurityInfo(directory,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &owner,nullptr,&acl,nullptr,&descriptor);
    if(error)return error;
    if(!owner || (!IsWellKnownSid(owner,WinBuiltinAdministratorsSid) && !IsWellKnownSid(owner,WinLocalSystemSid)) || !acl || !IsValidAcl(acl))
        error=ERROR_ACCESS_DENIED;
    const DWORD readOnly=FILE_GENERIC_READ|FILE_GENERIC_EXECUTE|GENERIC_READ|GENERIC_EXECUTE;
    for(DWORD i=0;!error && i<acl->AceCount;++i) {
        ACCESS_ALLOWED_ACE *ace=nullptr;
        if(!GetAce(acl,i,(void**)&ace)){error=ERROR_ACCESS_DENIED;break;}
        if(ace->Header.AceFlags&INHERIT_ONLY_ACE)continue;
        if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE){error=ERROR_ACCESS_DENIED;break;}
        PSID sid=&ace->SidStart;
        if(!IsValidSid(sid) || (!IsWellKnownSid(sid,WinBuiltinAdministratorsSid) &&
           !IsWellKnownSid(sid,WinLocalSystemSid) && (ace->Mask&~readOnly)))error=ERROR_ACCESS_DENIED;
    }
    LocalFree(descriptor);return error;
}
static DWORD hold_bootstrap_file(RegistrationGuard &guard,const WCHAR *directory,const WCHAR *name,unsigned slot) {
    WCHAR path[MAX_PATH]; DWORD error=join_path(path,directory,name); if(error)return error;
    HANDLE file=CreateFileW(path,GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(file==INVALID_HANDLE_VALUE)return GetLastError();
    guard.payload.files[slot]=file;
    FILE_ATTRIBUTE_TAG_INFO info={};
    if(!GetFileInformationByHandleEx(file,FileAttributeTagInfo,&info,sizeof(info)))return GetLastError();
    if(info.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))return ERROR_INVALID_NAME;
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    error=GetSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr,&descriptor);
    if(!error)error=pb_startup_file_security(descriptor);
    if(descriptor)LocalFree(descriptor);
    return error;
}
// Refuse to overwrite/delete a shortcut whose action no longer belongs to this
// exact bootstrap. For updates, a registered previous bootstrap may be supplied.
static DWORD shortcut(const WCHAR *folder,const WCHAR *name,const WCHAR *target,const WCHAR *arguments,
                      const WCHAR *previousTarget,BOOL remove) {
    WCHAR path[MAX_PATH]; DWORD error=join_path(path,folder,name); if(error)return error;
    RegistrationPtr<IShellLinkW> link;
    HRESULT hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&link.p);
    if(FAILED(hr))return registration_error(hr);
    RegistrationPtr<IPersistFile> persist;
    hr=link->QueryInterface(IID_IPersistFile,(void**)&persist.p); if(FAILED(hr))return registration_error(hr);
    DWORD attributes=GetFileAttributesW(path);
    if(attributes!=INVALID_FILE_ATTRIBUTES) {
        if(attributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))return ERROR_INVALID_NAME;
        hr=persist->Load(path,STGM_READ); if(FAILED(hr))return registration_error(hr);
        WCHAR actual[MAX_PATH],actualArgs[256]; WIN32_FIND_DATAW data={};
        hr=link->GetPath(actual,MAX_PATH,&data,SLGP_RAWPATH); if(FAILED(hr))return registration_error(hr);
        hr=link->GetArguments(actualArgs,ARRAYSIZE(actualArgs)); if(FAILED(hr))return registration_error(hr);
        BOOL targetMatches=!_wcsicmp(actual,target), argumentsMatch=!wcscmp(actualArgs,arguments);
        BOOL previousMatches=previousTarget && !_wcsicmp(actual,previousTarget);
        BOOL previousArgumentsMatch=argumentsMatch;
        if(previousMatches && !previousArgumentsMatch && !wcsncmp(arguments,L"resume-package ",15)) {
            const size_t suffix=wcslen(L"\\ProxyBridgeDriverSetup.exe"), length=wcslen(previousTarget);
            if(length>=suffix+64 && !_wcsicmp(previousTarget+length-suffix,L"\\ProxyBridgeDriverSetup.exe")) {
                WCHAR previousArguments[96];
                swprintf_s(previousArguments,ARRAYSIZE(previousArguments),L"resume-package %.64s",previousTarget+length-suffix-64);
                previousArgumentsMatch=!wcscmp(actualArgs,previousArguments);
            }
        }
        if(!(targetMatches && argumentsMatch) && !(previousMatches && previousArgumentsMatch && !remove))return ERROR_ACCESS_DENIED;
        if(!remove && targetMatches && argumentsMatch)return 0;
        // Release the loaded file reference before changing the file.
        persist.p->Release(); persist.p=nullptr; link.p->Release(); link.p=nullptr;
        if(remove)return DeleteFileW(path)?0:GetLastError();
        hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&link.p);
        if(SUCCEEDED(hr))hr=link->QueryInterface(IID_IPersistFile,(void**)&persist.p);
        if(FAILED(hr))return registration_error(hr);
    } else {
        error=GetLastError(); if(error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PATH_NOT_FOUND)return error;
        if(remove)return 0;
    }
    hr=link->SetPath(target); if(SUCCEEDED(hr))hr=link->SetArguments(arguments);
    if(SUCCEEDED(hr))hr=link->SetIconLocation(target,0);
    if(FAILED(hr))return registration_error(hr);
    GUID id; WCHAR idText[40],temporary[MAX_PATH],tempName[64];
    hr=CoCreateGuid(&id);if(FAILED(hr))return registration_error(hr);
    if(!StringFromGUID2(id,idText,ARRAYSIZE(idText)))return ERROR_INVALID_DATA;
    swprintf_s(tempName,ARRAYSIZE(tempName),L"%s.registration.tmp",idText);
    error=join_path(temporary,folder,tempName);if(error)return error;
    HANDLE reservation=CreateFileW(temporary,GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(reservation==INVALID_HANDLE_VALUE)return GetLastError();
    CloseHandle(reservation);
    hr=persist->Save(temporary,TRUE);
    persist.p->Release();persist.p=nullptr;
    if(SUCCEEDED(hr) && !MoveFileExW(temporary,path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))error=GetLastError();
    else error=registration_error(hr);
    if(error)DeleteFileW(temporary); // Only the unique file reserved above.
    return error;
}
static DWORD put_string(HKEY key,const WCHAR *name,const WCHAR *value) {
    return RegSetValueExW(key,name,0,REG_SZ,(const BYTE*)value,(DWORD)((wcslen(value)+1)*sizeof(WCHAR)));
}
struct BootstrapReferences { const WCHAR *menu; const WCHAR *desktop; };
static BOOL references_directory(const WCHAR *path,const WCHAR *directory) {
    size_t length=wcslen(directory);
    return !_wcsnicmp(path,directory,length) && (!path[length] || path[length]==L'\\');
}
static DWORD bootstrap_referenced(void *context,const WCHAR *directory,BOOL *referenced) {
    *referenced=FALSE;
    static const WCHAR *names[]={L"InstallLocation",L"RetiringBootstrap"};
    for(const WCHAR *name:names) {
        WCHAR value[MAX_PATH]={};DWORD size=sizeof(value);
        DWORD error=RegGetValueW(HKEY_LOCAL_MACHINE,registrationKey,name,RRF_RT_REG_SZ|RRF_SUBKEY_WOW6464KEY,nullptr,value,&size);
        if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND)continue;
        if(error)return error;
        if(size>sizeof(value) || size!=(wcslen(value)+1)*sizeof(WCHAR))return ERROR_INVALID_DATA;
        if(references_directory(value,directory)){*referenced=TRUE;return 0;}
    }
    const BootstrapReferences *references=(BootstrapReferences*)context;
    const WCHAR *folders[]={references->menu,references->desktop};
    for(unsigned folderIndex=0;folderIndex<ARRAYSIZE(folders);++folderIndex) {
    const WCHAR *menu=folders[folderIndex];
    if(!menu)continue;
    WCHAR pattern[MAX_PATH];DWORD error=join_path(pattern,menu,folderIndex?L"ProxyBridge.lnk":L"*.lnk");if(error)return error;
    WIN32_FIND_DATAW entry;HANDLE search=FindFirstFileW(pattern,&entry);
    if(search==INVALID_HANDLE_VALUE){error=GetLastError();if(error==ERROR_FILE_NOT_FOUND)continue;return error;}
    do {
        if(entry.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)){error=ERROR_INVALID_NAME;break;}
        RegistrationPtr<IShellLinkW> link;RegistrationPtr<IPersistFile> persist;
        HRESULT hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&link.p);
        if(SUCCEEDED(hr))hr=link->QueryInterface(IID_IPersistFile,(void**)&persist.p);
        WCHAR path[MAX_PATH],target[MAX_PATH],arguments[1024];
        error=join_path(path,menu,entry.cFileName);if(error)break;
        if(SUCCEEDED(hr))hr=persist->Load(path,STGM_READ);
        if(SUCCEEDED(hr))hr=link->GetPath(target,MAX_PATH,nullptr,SLGP_RAWPATH);
        if(SUCCEEDED(hr))hr=link->GetArguments(arguments,ARRAYSIZE(arguments));
        if(FAILED(hr)){error=registration_error(hr);break;}
        const WCHAR *hash=wcsrchr(directory,L'\\');
        if(references_directory(target,directory) || (hash && wcsstr(arguments,hash+1))){*referenced=TRUE;break;}
    }while(FindNextFileW(search,&entry));
    if(!error && !*referenced && GetLastError()!=ERROR_NO_MORE_FILES)error=GetLastError();
    FindClose(search);if(error || *referenced)return error;
    }
    return 0;
}
static DWORD retire_bootstrap(const WCHAR *directory) {
    const WCHAR *hash=wcsrchr(directory,L'\\');if(!hash)return ERROR_INVALID_NAME;
    RegistrationKey store;DWORD error=pb_install_store_open_existing_write(&store.key);if(error)return error;
    return pb_bootstrap_retire(store.key,hash+1);
}
static DWORD collect_bootstrap(const WCHAR *hash,const WCHAR *menu,const WCHAR *desktop) {
    RegistrationKey store;DWORD error=pb_install_store_open_existing_write(&store.key);if(error)return error;
    PB_INSTALL_JOURNAL journal={};error=pb_journal_read(store.key,&journal);if(error)return error;
    BootstrapReferences references={menu,desktop};
    return pb_bootstrap_collect(store.key,&journal,hash,bootstrap_referenced,&references);
}
static DWORD registration_work(const WCHAR *hash,unsigned operation) {
    RegistrationGuard bootstrap,programs,desktopGuard; HANDLE bootstrapRoot=nullptr,programsRoot=nullptr;
    DWORD error=pb_bootstrap_root_read(hash,&bootstrap.payload,&bootstrapRoot); if(error)return error;
    WCHAR directory[MAX_PATH],menu[MAX_PATH],launcher[MAX_PATH],helper[MAX_PATH],uninstaller[MAX_PATH],uninstallCommand[MAX_PATH+3],resume[96],recovery[96];
    error=folder_path(bootstrapRoot,directory); if(error)return error;
    error=hold_bootstrap_file(bootstrap,directory,L"ProxyBridgeLauncher.exe",0); if(error)return error;
    error=hold_bootstrap_file(bootstrap,directory,L"ProxyBridgeDriverSetup.exe",1); if(error)return error;
    error=hold_bootstrap_file(bootstrap,directory,L"uninstall.exe",2); if(error)return error;
    if(join_path(launcher,directory,L"ProxyBridgeLauncher.exe") || join_path(helper,directory,L"ProxyBridgeDriverSetup.exe") ||
       join_path(uninstaller,directory,L"uninstall.exe"))return ERROR_FILENAME_EXCED_RANGE;
    swprintf_s(uninstallCommand,ARRAYSIZE(uninstallCommand),L"\"%s\"",uninstaller);
    const WCHAR *canonicalHash=wcsrchr(directory,L'\\');
    if(!canonicalHash || wcslen(++canonicalHash)!=64)return ERROR_INVALID_NAME;
    swprintf_s(resume,ARRAYSIZE(resume),L"resume-package %s",canonicalHash);
    swprintf_s(recovery,ARRAYSIZE(recovery),L"Recovery-%s.lnk",canonicalHash);
    // Recovery is journal-driven and invoked by the installed uninstaller.
    // Do not expose a changing technical recovery link in the Start menu.
    if(operation==0)return 0;
    error=pb_programs_root_open(operation!=2,&programs.payload,&programsRoot);
    BOOL menuMissing=operation==2 && (error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND);
    if(error && !menuMissing)return error;
    if(!menuMissing) {error=folder_path(programsRoot,menu);if(error)return error;}
    WCHAR desktop[MAX_PATH];
    if(FAILED(SHGetFolderPathW(nullptr,CSIDL_COMMON_DESKTOPDIRECTORY,nullptr,SHGFP_TYPE_CURRENT,desktop)))return ERROR_PATH_NOT_FOUND;
    error=pb_payload_lock_directory(desktop,&desktopGuard.payload);
    BOOL desktopMissing=operation==2 && (error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND);
    if(error && !desktopMissing)return error;
    if(!desktopMissing) {
        error=desktop_security(desktopGuard.payload.directories[desktopGuard.payload.directoryCount-1]);
        if(error)return error;
    }
    RegistrationKey key; WCHAR previous[MAX_PATH]={},retiring[MAX_PATH]={}; DWORD bytes=sizeof(previous);
    error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,registrationKey,0,KEY_QUERY_VALUE|KEY_SET_VALUE|KEY_WOW64_64KEY,&key.key);
    if(error!=0 && error!=ERROR_FILE_NOT_FOUND)return error;
    if(!error) {
        error=RegGetValueW(key.key,nullptr,L"InstallLocation",RRF_RT_REG_SZ,nullptr,previous,&bytes);
        if(error!=0 && error!=ERROR_FILE_NOT_FOUND)return error;
        if(!error && (bytes>sizeof(previous) || (wcslen(previous)+1)*sizeof(WCHAR)!=bytes))return ERROR_INVALID_DATA;
        bytes=sizeof(retiring);
        error=RegGetValueW(key.key,nullptr,L"RetiringBootstrap",RRF_RT_REG_SZ,nullptr,retiring,&bytes);
        if(error!=0 && error!=ERROR_FILE_NOT_FOUND)return error;
        if(!error && (bytes>sizeof(retiring) || (wcslen(retiring)+1)*sizeof(WCHAR)!=bytes || !retiring[0]))return ERROR_INVALID_DATA;
    }
    if(operation==2 && previous[0] && _wcsicmp(previous,directory))return ERROR_REVISION_MISMATCH;
    WCHAR previousLauncher[MAX_PATH]={},previousHelper[MAX_PATH]={};
    if(previous[0]) {
        // Metadata is only accepted for a protected, canonical bootstrap tree.
        WCHAR common[MAX_PATH];
        if(FAILED(SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,common)))return ERROR_PATH_NOT_FOUND;
        if(join_path(previousLauncher,previous,L"ProxyBridgeLauncher.exe") || join_path(previousHelper,previous,L"ProxyBridgeDriverSetup.exe"))return ERROR_INVALID_NAME;
        if(!pb_startup_launcher_path(common,previousLauncher))return ERROR_INVALID_NAME;
    }
    WCHAR retiringHelper[MAX_PATH]={},retiringRecovery[96]={},retiringResume[96]={};
    if(retiring[0]) {
        WCHAR common[MAX_PATH],retiringLauncher[MAX_PATH];
        if(FAILED(SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,common)))return ERROR_PATH_NOT_FOUND;
        if(join_path(retiringLauncher,retiring,L"ProxyBridgeLauncher.exe") || !pb_startup_launcher_path(common,retiringLauncher))return ERROR_INVALID_NAME;
        // A new package must first finish the previous package's handoff. The
        // package dispatcher calls this registration repair before beginning it.
        if(operation==1 && previous[0] && _wcsicmp(previous,directory) && _wcsicmp(previous,retiring))return ERROR_BUSY;
    } else if(operation==1 && previous[0] && _wcsicmp(previous,directory)) {
        wcscpy_s(retiring,MAX_PATH,previous);
        error=put_string(key.key,L"RetiringBootstrap",retiring);if(error)return error;
    }
    if(retiring[0]) {
        if(!_wcsicmp(retiring,directory))return ERROR_INVALID_DATA;
        const WCHAR *oldHash=wcsrchr(retiring,L'\\');
        if(!oldHash || wcslen(++oldHash)!=64)return ERROR_INVALID_NAME;
        error=join_path(retiringHelper,retiring,L"ProxyBridgeDriverSetup.exe");if(error)return error;
        swprintf_s(retiringRecovery,ARRAYSIZE(retiringRecovery),L"Recovery-%s.lnk",oldHash);
        swprintf_s(retiringResume,ARRAYSIZE(retiringResume),L"resume-package %s",oldHash);
        // Retry may see a value whose earlier flush failed. Re-establish its
        // durability before changing links, registration or the startup task.
        error=RegFlushKey(key.key);if(error)return error;
    }
    if(operation==2) {
        BOOL enabled=FALSE; error=pb_startup_installed(PB_STARTUP_REMOVE,&enabled); if(error)return error;
        if(!desktopMissing) {error=shortcut(desktop,L"ProxyBridge.lnk",launcher,L"",nullptr,TRUE);if(error)return error;}
        if(!menuMissing) {
            error=shortcut(menu,L"ProxyBridge.lnk",launcher,L"",nullptr,TRUE); if(error)return error;
            error=shortcut(menu,L"Resume installation.lnk",helper,resume,nullptr,TRUE); if(error)return error;
            error=shortcut(menu,recovery,helper,resume,nullptr,TRUE); if(error)return error;
            if(retiring[0]) {error=shortcut(menu,retiringRecovery,retiringHelper,retiringResume,nullptr,TRUE);if(error)return error;}
        }
        if(key.key){RegCloseKey(key.key);key.key=nullptr;}
        if(retiring[0]){error=retire_bootstrap(retiring);if(error)return error;}
        error=retire_bootstrap(directory);if(error)return error;
        error=RegDeleteKeyExW(HKEY_LOCAL_MACHINE,registrationKey,KEY_WOW64_64KEY,0);
        if(error!=0 && error!=ERROR_FILE_NOT_FOUND)return error;
        return collect_bootstrap(hash,menuMissing?nullptr:menu,desktopMissing?nullptr:desktop);
    }
    if(!key.key) {error=RegCreateKeyExW(HKEY_LOCAL_MACHINE,registrationKey,0,nullptr,0,KEY_QUERY_VALUE|KEY_SET_VALUE|KEY_WOW64_64KEY,nullptr,&key.key,nullptr);if(error)return error;}
    // Shortcuts first; InstallLocation is published last. A failed write leaves
    // the old location available for an idempotent repair, not an invented owner.
    error=shortcut(menu,L"ProxyBridge.lnk",launcher,L"",previousLauncher[0]?previousLauncher:nullptr,FALSE);if(error)return error;
    error=shortcut(desktop,L"ProxyBridge.lnk",launcher,L"",previousLauncher[0]?previousLauncher:nullptr,FALSE);if(error)return error;
    error=shortcut(menu,L"Resume installation.lnk",helper,resume,previousHelper[0]?previousHelper:nullptr,FALSE);if(error)return error;
    // Remove the same-version recovery link left by an older package before
    // publishing normal product links. A foreign replacement still blocks it.
    error=shortcut(menu,recovery,helper,resume,nullptr,TRUE);if(error)return error;
    const WCHAR *names[]={L"DisplayName",L"Publisher",L"UninstallString",L"DisplayIcon",L"InstallLocation"};
    const WCHAR *values[]={L"ProxyBridge",L"InterceptSuite",uninstallCommand,launcher,directory};
    for(unsigned i=0;i<ARRAYSIZE(names);++i){error=put_string(key.key,names[i],values[i]);if(error)return error;}
    DWORD one=1;
    error=RegSetValueExW(key.key,L"NoModify",0,REG_DWORD,(const BYTE*)&one,sizeof(one));if(error)return error;
    error=RegSetValueExW(key.key,L"NoRepair",0,REG_DWORD,(const BYTE*)&one,sizeof(one));if(error)return error;
    error=RegFlushKey(key.key);if(error)return error;
    BOOL enabled=FALSE;error=pb_startup_installed(PB_STARTUP_RETARGET,&enabled);if(error)return error;
    // All registered actions now use the new bootstrap. Remove only the exact
    // old recovery shortcut; a foreign/reconfigured action blocks retirement.
    if(retiring[0]) {
        error=shortcut(menu,retiringRecovery,retiringHelper,retiringResume,nullptr,TRUE);if(error)return error;
        error=retire_bootstrap(retiring);if(error)return error;
        error=RegDeleteValueW(key.key,L"RetiringBootstrap");if(error)return error;
        error=RegFlushKey(key.key);if(error)return error;
    }
    return collect_bootstrap(hash,menu,desktop);
}
DWORD pb_registration_apply(const WCHAR *hash,unsigned operation) {
    if(!hash || operation>2)return ERROR_INVALID_PARAMETER;
    HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(initialized) && initialized!=RPC_E_CHANGED_MODE)return registration_error(initialized);
    DWORD error=registration_work(hash,operation);
    if(SUCCEEDED(initialized))CoUninitialize();
    return error;
}
#include "install-flat-registration.inc"
