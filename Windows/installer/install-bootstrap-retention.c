#include "install-bootstrap-retention.h"
#include "install-stage.h"
#include "startup-installed.h"
#include <aclapi.h>
#include <stdio.h>
#include <string.h>
static const WCHAR receiptPrefix[] = L"RetiredBootstrap-";
static const WCHAR *const bootstrapNames[] = {L"ProxyBridgeDriverSetup.exe",L"ProxyBridgeLauncher.exe",L"uninstall.exe"};
static DWORD canonical_hash(const WCHAR *hash, WCHAR text[65], BYTE bytes[32])
{
    if(!hash || wcsnlen_s(hash,65)!=64)return ERROR_INVALID_PARAMETER;
    ZeroMemory(bytes,32);
    for(unsigned i=0;i<64;++i){
        WCHAR c=hash[i];unsigned n;
        if(c>=L'0' && c<=L'9')n=c-L'0';
        else if(c>=L'a' && c<=L'f')n=c-L'a'+10;
        else if(c>=L'A' && c<=L'F')n=c-L'A'+10;
        else return ERROR_INVALID_PARAMETER;
        text[i]=L"0123456789ABCDEF"[n];bytes[i/2]=(BYTE)((bytes[i/2]<<4)|n);
    }
    text[64]=0;return 0;
}
DWORD pb_bootstrap_retire(HKEY key,const WCHAR *hash)
{
    WCHAR canonical[65],name[96];BYTE bytes[32];DWORD error=canonical_hash(hash,canonical,bytes);if(error)return error;
    swprintf_s(name,ARRAYSIZE(name),L"%s%s",receiptPrefix,canonical);
    DWORD version=1,existing=0,size=sizeof(existing),type=0;
    error=RegQueryValueExW(key,name,NULL,&type,(BYTE*)&existing,&size);
    if(!error && (type!=REG_DWORD || size!=sizeof(existing) || existing!=version))return ERROR_INVALID_DATA;
    if(error && error!=ERROR_FILE_NOT_FOUND)return error;
    if(error)error=RegSetValueExW(key,name,0,REG_DWORD,(const BYTE*)&version,sizeof(version));
    return error?error:RegFlushKey(key);
}
static DWORD remove_bootstrap(const WCHAR *hash,PB_BOOTSTRAP_REFERENCED referenced,void *context,BOOL *removed)
{
    *removed=FALSE;PB_VERIFIED_PAYLOAD guard={0};HANDLE root=NULL;
    DWORD error=pb_bootstrap_root_read(hash,&guard,&root);
    if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND){*removed=TRUE;return 0;}
    if(error)return error;
    WCHAR directory[MAX_PATH],module[MAX_PATH],pattern[MAX_PATH];
    DWORD length=GetFinalPathNameByHandleW(root,directory,MAX_PATH,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(length<7 || length>=MAX_PATH || wcsncmp(directory,L"\\\\?\\",4)){error=ERROR_INVALID_NAME;goto done;}
    length=GetModuleFileNameW(NULL,module,MAX_PATH);
    if(!length || length>=MAX_PATH){error=ERROR_INVALID_NAME;goto done;}
    WCHAR *leaf=wcsrchr(module,L'\\');if(!leaf){error=ERROR_INVALID_NAME;goto done;}*leaf=0;
    if(!_wcsicmp(module,directory+4))goto done;
    BOOL used=TRUE;error=referenced(context,directory+4,&used);if(error || used)goto done;
    if(swprintf_s(pattern,MAX_PATH,L"%s\\*",directory)<0){error=ERROR_FILENAME_EXCED_RANGE;goto done;}
    WIN32_FIND_DATAW entry;HANDLE search=FindFirstFileW(pattern,&entry);
    if(search==INVALID_HANDLE_VALUE){error=GetLastError();goto done;}
    do{
        if(!wcscmp(entry.cFileName,L".") || !wcscmp(entry.cFileName,L".."))continue;
        unsigned i;for(i=0;i<ARRAYSIZE(bootstrapNames);++i)if(!wcscmp(entry.cFileName,bootstrapNames[i]))break;
        // Unknown entries (including old temporaries) keep the whole receipt.
        if(i==ARRAYSIZE(bootstrapNames) || (entry.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))){error=ERROR_INVALID_DATA;break;}
    }while(FindNextFileW(search,&entry));
    if(!error && GetLastError()!=ERROR_NO_MORE_FILES)error=GetLastError();
    FindClose(search);if(error)goto done;
    for(unsigned i=0;!error && i<ARRAYSIZE(bootstrapNames);++i){
        WCHAR path[MAX_PATH];if(swprintf_s(path,MAX_PATH,L"%s\\%s",directory,bootstrapNames[i])<0){error=ERROR_FILENAME_EXCED_RANGE;break;}
        HANDLE file=CreateFileW(path,DELETE|READ_CONTROL|FILE_READ_ATTRIBUTES,0,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        if(file==INVALID_HANDLE_VALUE){error=GetLastError();if(error==ERROR_FILE_NOT_FOUND)error=0;continue;}
        guard.files[i]=file;FILE_ATTRIBUTE_TAG_INFO info;PSECURITY_DESCRIPTOR descriptor=NULL;
        if(!GetFileInformationByHandleEx(file,FileAttributeTagInfo,&info,sizeof(info)))error=GetLastError();
        else if(info.FileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))error=ERROR_INVALID_NAME;
        else error=GetSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL,&descriptor);
        if(!error)error=pb_startup_file_security(descriptor);
        if(descriptor)LocalFree(descriptor);
    }
    for(unsigned i=0;!error && i<ARRAYSIZE(bootstrapNames);++i)if(guard.files[i]){
        FILE_DISPOSITION_INFO disposition={TRUE};
        if(!SetFileInformationByHandle(guard.files[i],FileDispositionInfo,&disposition,sizeof(disposition)))error=GetLastError();
        if(!error){CloseHandle(guard.files[i]);guard.files[i]=NULL;}
    }
    if(!error)*removed=TRUE;
done:
    pb_payload_close(&guard);
    // Files in use can be retried at a later successful package operation.
    return error==ERROR_SHARING_VIOLATION?0:error;
}
DWORD pb_bootstrap_collect(HKEY key,const PB_INSTALL_JOURNAL *current,const WCHAR *activeHash,
    PB_BOOTSTRAP_REFERENCED referenced,void *context)
{
    if(!referenced)return ERROR_INVALID_PARAMETER;
    DWORD error=pb_journal_validate(current);if(error)return error;
    if(current->phase!=PB_INSTALL_COMMITTED && current->phase!=PB_INSTALL_ROLLED_BACK && current->phase!=PB_INSTALL_CLEANED)return 0;
    WCHAR active[65];BYTE activeBytes[32];error=canonical_hash(activeHash,active,activeBytes);if(error)return error;
    PB_INSTALL_JOURNAL pending={0};DWORD size=sizeof(pending),type=0;
    error=RegQueryValueExW(key,L"PendingStage",NULL,&type,(BYTE*)&pending,&size);
    if(error!=ERROR_FILE_NOT_FOUND){
        if(error)return error;
        if(type!=REG_BINARY || size!=sizeof(pending))return ERROR_INVALID_DATA;
        error=pb_journal_validate(&pending);if(error)return error;
        if(pending.phase!=PB_INSTALL_PREPARED)return ERROR_INVALID_STATE;
    }
    for(DWORD index=0;;){
        WCHAR name[96],canonical[65];DWORD length=ARRAYSIZE(name);
        error=RegEnumValueW(key,index,name,&length,NULL,NULL,NULL,NULL);
        if(error==ERROR_NO_MORE_ITEMS)return 0;
        if(error==ERROR_MORE_DATA){++index;continue;}
        if(error)return error;
        if(wcsncmp(name,receiptPrefix,ARRAYSIZE(receiptPrefix)-1)){++index;continue;}
        BYTE hash[32];error=canonical_hash(name+ARRAYSIZE(receiptPrefix)-1,canonical,hash);if(error)return error;
        DWORD version=0;size=sizeof(version);type=0;
        error=RegQueryValueExW(key,name,NULL,&type,(BYTE*)&version,&size);if(error)return error;
        if(type!=REG_DWORD || size!=sizeof(version) || version!=1)return ERROR_INVALID_DATA;
        if(!memcmp(hash,activeBytes,32) || !memcmp(hash,current->targetManifestHash,32) ||
           (current->previousDirectory[0] && !memcmp(hash,current->previousManifestHash,32)) ||
           (pending.size && !memcmp(hash,pending.targetManifestHash,32))){++index;continue;}
        BOOL removed=FALSE;error=remove_bootstrap(canonical,referenced,context,&removed);
        if(error)return error;
        if(!removed){++index;continue;}
        error=RegDeleteValueW(key,name);if(error)return error;
        error=RegFlushKey(key);if(error)return error;
        index=0;
    }
}
