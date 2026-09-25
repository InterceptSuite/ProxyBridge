#include "install-trace.h"
// Entire package flow runs under the helper's update guard + install mutex.
// Uninstall/resume from a different bootstrap must not act on a new package.
static DWORD package_binding(const WCHAR *text, BOOL removal)
{
    if(!text || wcsnlen_s(text,65)!=64)return ERROR_INVALID_PARAMETER;
    BYTE hash[32]={0};
    for(unsigned i=0;i<64;++i) {
        WCHAR c=text[i]; unsigned n;
        if(c>=L'0' && c<=L'9')n=c-L'0';
        else if(c>=L'a' && c<=L'f')n=c-L'a'+10;
        else if(c>=L'A' && c<=L'F')n=c-L'A'+10;
        else return ERROR_INVALID_PARAMETER;
        hash[i/2]=(BYTE)((hash[i/2]<<4)|n);
    }
    PB_INSTALL_JOURNAL record;
    DWORD error=read_transaction(&record);if(error)return error;
    if(!memcmp(hash,record.targetManifestHash,32))return 0;
    if(removal && (record.phase==PB_INSTALL_ROLLED_BACK || record.phase>=PB_INSTALL_REMOVING) &&
       record.previousDirectory[0] && !memcmp(hash,record.previousManifestHash,32))return 0;
    return ERROR_REVISION_MISMATCH;
}
static DWORD package_registration(unsigned operation)
{
    PB_INSTALL_JOURNAL record;
    DWORD error=read_transaction(&record);if(error)return error;
    static const WCHAR digits[]=L"0123456789ABCDEF";
    WCHAR hash[65];
    for(unsigned i=0;i<32;++i) {
        hash[i*2]=digits[record.targetManifestHash[i]>>4];
        hash[i*2+1]=digits[record.targetManifestHash[i]&15];
    }
    hash[64]=0;
    return pb_registration_apply(hash,operation);
}
// Finish publication before a new journal forgets which bootstrap may own
// partially replaced shortcuts. A fresh install has no transaction to repair.
static DWORD package_finish_previous(BOOL *removedOwnedPackage)
{
    if(!removedOwnedPackage)return ERROR_INVALID_PARAMETER;
    *removedOwnedPackage=FALSE;
    PB_INSTALL_JOURNAL record;
    DWORD error=read_transaction(&record);
    if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND)return 0;
    if(error)return error;
    if(record.phase==PB_INSTALL_COMMITTED || record.phase==PB_INSTALL_ROLLED_BACK)
        return package_registration(1);
    if(record.phase==PB_INSTALL_CLEANED) {
        error=cleanup_recorded_owned();if(error)return error;
        error=package_registration(2);
        // A manually deleted obsolete bootstrap cannot be used to remove its
        // already-cleaned registration. The next package will atomically
        // retarget normal registration to its own verified bootstrap.
        if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND)error=0;
        if(error)return error;
        // CLEANED is the terminal state of the same owned removal. A prior
        // attempt may have stopped after it, while SCM still lists the PnP
        // service; carry the proof into the replacement install as well.
        *removedOwnedPackage=TRUE;
        return 0;
    }
    // An interrupted removal owns a journal just as an interrupted update does.
    // Complete it before starting the new package: this avoids stranding a
    // valid replacement bootstrap behind a stale REMOVING state.
    if(record.phase==PB_INSTALL_REMOVING || record.phase==PB_INSTALL_REMOVE_PENDING ||
       record.phase==PB_INSTALL_REMOVED) {
        error=uninstall_recorded();if(error)return error;
        error=cleanup_recorded();if(error)return error;
        error=cleanup_recorded_owned();if(error)return error;
        error=package_registration(2);if(error)return error;
        *removedOwnedPackage=TRUE;
        return 0;
    }
    return ERROR_BUSY; // Resume the unfinished transaction first.
}
static DWORD package_recorded(const WCHAR *command,const WCHAR *directory,const WCHAR *hash)
{
    if(!wcscmp(command,L"prepare-recovery"))return pb_registration_apply(hash,0);
    BOOL remove=!wcscmp(command,L"uninstall-package");
    BOOL update=!wcscmp(command,L"update-package");
    if(!wcscmp(command,L"resume-package")) {
        PB_INSTALL_JOURNAL record;
        DWORD error=read_transaction(&record);if(error)return error;
        remove=record.phase>=PB_INSTALL_REMOVING;
    }
    BOOL removedOwnedPackage=FALSE;
    DWORD result=update ? pb_install_trace(L"finish-previous",package_finish_previous(&removedOwnedPackage)) : package_binding(hash,remove);
    if(!result && update)result=pb_install_trace(L"begin-install",begin_recorded_install(directory,hash,removedOwnedPackage));
    if(result)return result;
    if(remove) {
        PB_INSTALL_JOURNAL record;
        result=read_transaction(&record);if(result)return result;
        if(record.phase==PB_INSTALL_COMMITTED || record.phase==PB_INSTALL_ROLLED_BACK) {
            result=package_registration(1);if(result)return result;
        }
        result=pb_install_trace(L"remove-driver",uninstall_recorded());if(result)return result;
        result=pb_install_trace(L"remove-payload",cleanup_recorded());if(result)return result;
        result=pb_install_trace(L"remove-owned-staging",cleanup_recorded_owned());if(result)return result;
        return pb_install_trace(L"remove-registration",package_registration(2));
    }
    result=pb_install_trace(L"resume-install",resume_recorded_install(TRUE));
    if(result!=0 && result!=ERROR_SUCCESS_REBOOT_REQUIRED) {
        PB_INSTALL_JOURNAL record;
        DWORD stateError=read_transaction(&record);
        if(!stateError && record.phase==PB_INSTALL_ROLLED_BACK) {
            // The current bootstrap can select the restored application. Keep
            // its recovery/uninstaller ownership even though update failed.
            DWORD repairError=package_registration(1);
            if(repairError)return repairError;
        }
        return result;
    }
    DWORD error=package_binding(hash,FALSE);if(error)return error;
    error=package_registration(1);
    if(!error && !result)error=cleanup_recorded_owned();
    return error ? error : result;
}
