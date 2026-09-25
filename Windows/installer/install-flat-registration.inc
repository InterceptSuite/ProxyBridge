static DWORD flat_link(const WCHAR *folder, const WCHAR *name, const WCHAR *target, BOOL remove)
{
    WCHAR path[MAX_PATH], previous[MAX_PATH]={};
    DWORD error=join_path(path,folder,name);if(error)return error;
    DWORD attributes=GetFileAttributesW(path);
    if(attributes!=INVALID_FILE_ATTRIBUTES) {
        if(attributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))return ERROR_INVALID_NAME;
        RegistrationPtr<IShellLinkW> link;RegistrationPtr<IPersistFile> file;
        HRESULT hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&link.p);
        if(SUCCEEDED(hr))hr=link->QueryInterface(IID_IPersistFile,(void**)&file.p);
        if(SUCCEEDED(hr))hr=file->Load(path,STGM_READ);
        WCHAR arguments[256], common[MAX_PATH];
        if(SUCCEEDED(hr))hr=link->GetPath(previous,MAX_PATH,nullptr,SLGP_RAWPATH);
        if(SUCCEEDED(hr))hr=link->GetArguments(arguments,ARRAYSIZE(arguments));
        if(FAILED(hr))return registration_error(hr);
        if(FAILED(SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,common)))return ERROR_PATH_NOT_FOUND;
        if(arguments[0] || !pb_startup_launcher_path(common,previous))return ERROR_ACCESS_DENIED;
    } else if(GetLastError()!=ERROR_FILE_NOT_FOUND && GetLastError()!=ERROR_PATH_NOT_FOUND)return GetLastError();
    return shortcut(folder,name,remove && previous[0]?previous:target,L"",previous[0]?previous:nullptr,remove);
}

static DWORD flat_remove_recovery_links(const WCHAR *menu)
{
    WCHAR pattern[MAX_PATH];DWORD error=join_path(pattern,menu,L"*.lnk");if(error)return error;
    WIN32_FIND_DATAW entry;HANDLE scan=FindFirstFileW(pattern,&entry);
    if(scan==INVALID_HANDLE_VALUE){error=GetLastError();return error==ERROR_FILE_NOT_FOUND?0:error;}
    do {
        if(wcscmp(entry.cFileName,L"Resume installation.lnk") && wcsncmp(entry.cFileName,L"Recovery-",9))continue;
        if(entry.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)){error=ERROR_INVALID_NAME;break;}
        WCHAR path[MAX_PATH],actual[MAX_PATH],arguments[256],common[MAX_PATH];
        error=join_path(path,menu,entry.cFileName);if(error)break;
        RegistrationPtr<IShellLinkW> link;RegistrationPtr<IPersistFile> file;
        HRESULT hr=CoCreateInstance(CLSID_ShellLink,nullptr,CLSCTX_INPROC_SERVER,IID_IShellLinkW,(void**)&link.p);
        if(SUCCEEDED(hr))hr=link->QueryInterface(IID_IPersistFile,(void**)&file.p);
        if(SUCCEEDED(hr))hr=file->Load(path,STGM_READ);
        if(SUCCEEDED(hr))hr=link->GetPath(actual,MAX_PATH,nullptr,SLGP_RAWPATH);
        if(SUCCEEDED(hr))hr=link->GetArguments(arguments,ARRAYSIZE(arguments));
        if(FAILED(hr)){error=registration_error(hr);break;}
        WCHAR *name=wcsrchr(actual,L'\\');
        if(!name || _wcsicmp(name,L"\\ProxyBridgeDriverSetup.exe")){error=ERROR_ACCESS_DENIED;break;}
        WCHAR launcher[MAX_PATH];wcscpy_s(launcher,MAX_PATH,actual);*wcsrchr(launcher,L'\\')=0;
        const WCHAR *hash=wcsrchr(launcher,L'\\');
        if(!hash || wcslen(hash+1)!=64){error=ERROR_INVALID_NAME;break;}
        WCHAR expectedArgs[96],expectedName[96];
        swprintf_s(expectedArgs,ARRAYSIZE(expectedArgs),L"resume-package %s",hash+1);
        swprintf_s(expectedName,ARRAYSIZE(expectedName),L"Recovery-%s.lnk",hash+1);
        if(wcscmp(arguments,expectedArgs) || (wcscmp(entry.cFileName,L"Resume installation.lnk") && _wcsicmp(entry.cFileName,expectedName))) {error=ERROR_ACCESS_DENIED;break;}
        wcscat_s(launcher,MAX_PATH,L"\\ProxyBridgeLauncher.exe");
        if(FAILED(SHGetFolderPathW(nullptr,CSIDL_COMMON_APPDATA,nullptr,SHGFP_TYPE_CURRENT,common)) || !pb_startup_launcher_path(common,launcher)){error=ERROR_INVALID_NAME;break;}
        file.p->Release();file.p=nullptr;link.p->Release();link.p=nullptr;
        error=shortcut(menu,entry.cFileName,actual,arguments,nullptr,TRUE);if(error)break;
    } while(FindNextFileW(scan,&entry));
    if(!error && GetLastError()!=ERROR_NO_MORE_FILES)error=GetLastError();
    FindClose(scan);return error;
}

static DWORD flat_registration_work(BOOL remove)
{
    WCHAR programsPath[MAX_PATH];PB_PRODUCT_LAYOUT layout;
    if(FAILED(SHGetFolderPathW(nullptr,CSIDL_PROGRAM_FILES,nullptr,SHGFP_TYPE_CURRENT,programsPath)))return ERROR_PATH_NOT_FOUND;
    DWORD error=pb_product_layout(programsPath,&layout);if(error)return error;
    RegistrationGuard product,programs,desktopGuard;HANDLE root=nullptr;
    if(!remove) {
        error=pb_product_root_open(FALSE,&product.payload,&root);if(error)return error;
        error=hold_bootstrap_file(product,layout.application,L"ProxyBridgeLauncher.exe",0);if(error)return error;
        error=hold_bootstrap_file(product,layout.application,L"uninstall.exe",1);if(error)return error;
    }
    error=pb_programs_root_open(!remove,&programs.payload,&root);
    BOOL menuMissing=remove && (error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND);
    if(error && !menuMissing)return error;
    WCHAR menu[MAX_PATH]={},desktop[MAX_PATH];
    if(!menuMissing){error=folder_path(root,menu);if(error)return error;}
    if(FAILED(SHGetFolderPathW(nullptr,CSIDL_COMMON_DESKTOPDIRECTORY,nullptr,SHGFP_TYPE_CURRENT,desktop)))return ERROR_PATH_NOT_FOUND;
    error=pb_payload_lock_directory(desktop,&desktopGuard.payload);
    BOOL desktopMissing=remove && (error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND);
    if(error && !desktopMissing)return error;
    if(!desktopMissing){error=desktop_security(desktopGuard.payload.directories[desktopGuard.payload.directoryCount-1]);if(error)return error;}
    if(!menuMissing){error=flat_link(menu,L"ProxyBridge.lnk",layout.launcher,remove);if(error)return error;error=flat_remove_recovery_links(menu);if(error)return error;}
    if(!desktopMissing){error=flat_link(desktop,L"ProxyBridge.lnk",layout.launcher,remove);if(error)return error;}
    BOOL enabled=FALSE;
    if(remove) {
        error=pb_startup_installed(PB_STARTUP_REMOVE,&enabled);if(error)return error;
        error=RegDeleteKeyExW(HKEY_LOCAL_MACHINE,registrationKey,KEY_WOW64_64KEY,0);
        return error==ERROR_FILE_NOT_FOUND?0:error;
    }
    RegistrationKey key;
    error=RegCreateKeyExW(HKEY_LOCAL_MACHINE,registrationKey,0,nullptr,0,KEY_QUERY_VALUE|KEY_SET_VALUE|KEY_WOW64_64KEY,nullptr,&key.key,nullptr);if(error)return error;
    WCHAR command[MAX_PATH+4];swprintf_s(command,ARRAYSIZE(command),L"\"%s\"",layout.uninstaller);
    const WCHAR *names[]={L"DisplayName",L"Publisher",L"UninstallString",L"DisplayIcon",L"InstallLocation"};
    const WCHAR *values[]={L"ProxyBridge",L"InterceptSuite",command,layout.launcher,layout.application};
    for(unsigned i=0;i<ARRAYSIZE(names);++i){error=put_string(key.key,names[i],values[i]);if(error)return error;}
    DWORD one=1;
    error=RegSetValueExW(key.key,L"NoModify",0,REG_DWORD,(const BYTE*)&one,sizeof(one));if(error)return error;
    error=RegSetValueExW(key.key,L"NoRepair",0,REG_DWORD,(const BYTE*)&one,sizeof(one));if(error)return error;
    error=RegDeleteValueW(key.key,L"RetiringBootstrap");if(error && error!=ERROR_FILE_NOT_FOUND)return error;
    error=RegFlushKey(key.key);if(error)return error;
    return pb_startup_installed(PB_STARTUP_RETARGET,&enabled);
}

DWORD pb_registration_flat(BOOL remove)
{
    HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(initialized) && initialized!=RPC_E_CHANGED_MODE)return registration_error(initialized);
    DWORD error=flat_registration_work(remove);
    if(SUCCEEDED(initialized))CoUninitialize();
    return error;
}
