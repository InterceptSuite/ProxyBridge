#include "../install-journal.h"
#include "../install-registration.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
static PB_INSTALL_JOURNAL fixtureRecord;
static DWORD readError,beginError,resumeError,removeError,cleanupError,registrationError;
static unsigned begins,resumes,removes,cleanups,registrations,registrationOperation;
static unsigned ownedCleanups;
static DWORD ownedError;
static BOOL rolledBack;
static BOOL beginAfterOwnedRemoval;
static WCHAR registeredHash[65];
static DWORD cleanup_recorded_owned(void){++ownedCleanups;return ownedError;}
static DWORD read_transaction(PB_INSTALL_JOURNAL *out){*out=fixtureRecord;return readError;}
static DWORD begin_recorded_install(const WCHAR *directory,const WCHAR *hash,BOOL removedOwnedPackage){(void)directory;(void)hash;++begins;beginAfterOwnedRemoval=removedOwnedPackage;return beginError;}
static DWORD resume_recorded_install(BOOL only){++resumes;if(!only)return ERROR_INVALID_PARAMETER;fixtureRecord.phase=rolledBack?PB_INSTALL_ROLLED_BACK:resumeError==3010?PB_INSTALL_DRIVER_PENDING:PB_INSTALL_COMMITTED;return resumeError;}
static DWORD uninstall_recorded(void){++removes;if(!removeError)fixtureRecord.phase=PB_INSTALL_REMOVED;return removeError;}
static DWORD cleanup_recorded(void){++cleanups;if(!cleanupError)fixtureRecord.phase=PB_INSTALL_CLEANED;return cleanupError;}
DWORD pb_registration_apply(const WCHAR *hash,unsigned operation){wcscpy_s(registeredHash,65,hash);++registrations;registrationOperation=operation;return registrationError;}
#include "../install-package.inc"
static void reset(void){
    ZeroMemory(&fixtureRecord,sizeof(fixtureRecord));fixtureRecord.phase=PB_INSTALL_COMMITTED;
    memset(fixtureRecord.targetManifestHash,0xaa,32);memset(fixtureRecord.previousManifestHash,0xbb,32);fixtureRecord.previousDirectory[0]=L'C';
    readError=beginError=resumeError=removeError=cleanupError=registrationError=0;
    begins=resumes=removes=cleanups=registrations=registrationOperation=0;
    ownedCleanups=ownedError=0;rolledBack=FALSE;beginAfterOwnedRemoval=FALSE;registeredHash[0]=0;
}
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(void){
    const WCHAR *a=L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const WCHAR *b=L"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    reset();CHECK(package_recorded(L"update-package",L"fixture",a)==0);
    CHECK(begins==1 && resumes==1 && registrations==2 && registrationOperation==1 && ownedCleanups==1);
    reset();resumeError=3010;CHECK(package_recorded(L"update-package",L"fixture",a)==3010 && registrationOperation==1);
    CHECK(!ownedCleanups);
    reset();ownedError=ERROR_SHARING_VIOLATION;
    CHECK(package_recorded(L"resume-package",NULL,a)==ownedError && registrations==1);
    ownedError=0;CHECK(package_recorded(L"resume-package",NULL,a)==0 && ownedCleanups==2);
    reset();ownedError=ERROR_SHARING_VIOLATION;
    CHECK(package_recorded(L"uninstall-package",NULL,a)==ownedError && registrations==1);
    ownedError=0;CHECK(package_recorded(L"resume-package",NULL,a)==0 && registrationOperation==2);
    reset();beginError=ERROR_BUSY;CHECK(package_recorded(L"update-package",L"fixture",a)==ERROR_BUSY && !resumes && registrations==1);
    reset();resumeError=ERROR_ACCESS_DENIED;CHECK(package_recorded(L"update-package",L"fixture",a)==ERROR_ACCESS_DENIED && registrations==1);
    reset();registrationError=ERROR_WRITE_FAULT;CHECK(package_recorded(L"resume-package",NULL,a)==ERROR_WRITE_FAULT);
    registrationError=0;CHECK(package_recorded(L"resume-package",NULL,a)==0 && registrations==2);
    reset();CHECK(package_recorded(L"resume-package",NULL,b)==ERROR_REVISION_MISMATCH && !resumes && !registrations);
    CHECK(package_recorded(L"uninstall-package",NULL,b)==ERROR_REVISION_MISMATCH && !removes && !registrations);
    for(DWORD phase=PB_INSTALL_REMOVING;phase<=PB_INSTALL_CLEANED;++phase){
        reset();fixtureRecord.phase=phase;CHECK(package_recorded(L"resume-package",NULL,a)==0);
        CHECK(removes==1 && cleanups==1 && registrations==1 && registrationOperation==2 && !resumes);
    }
    reset();fixtureRecord.phase=PB_INSTALL_ROLLED_BACK;CHECK(package_recorded(L"uninstall-package",NULL,b)==0 && registrationOperation==2);
    reset();removeError=3010;CHECK(package_recorded(L"uninstall-package",NULL,a)==3010 && !cleanups && registrations==1);
    reset();cleanupError=ERROR_SHARING_VIOLATION;CHECK(package_recorded(L"uninstall-package",NULL,a)==ERROR_SHARING_VIOLATION && registrations==1);
    cleanupError=0;CHECK(package_recorded(L"uninstall-package",NULL,a)==0 && registrationOperation==2);
    reset();readError=ERROR_INVALID_DATA;CHECK(package_recorded(L"resume-package",NULL,a)==ERROR_INVALID_DATA && !resumes && !registrations);
    reset();CHECK(package_binding(L"invalid",FALSE)==ERROR_INVALID_PARAMETER);
    CHECK(package_binding(NULL,FALSE)==ERROR_INVALID_PARAMETER);
    CHECK(package_binding(L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",FALSE)==0);
    reset();CHECK(package_recorded(L"prepare-recovery",NULL,a)==0 && registrationOperation==0 && !begins && !resumes);
    reset();registrationError=ERROR_WRITE_FAULT;
    CHECK(package_recorded(L"update-package",L"fixture",a)==registrationError && !begins && !resumes);
    reset();rolledBack=TRUE;resumeError=ERROR_INSTALL_FAILURE;
    CHECK(package_recorded(L"resume-package",NULL,a)==resumeError && registrations==1 && !ownedCleanups);
    CHECK(!wcscmp(registeredHash,a));
    reset();fixtureRecord.phase=PB_INSTALL_DRIVER_PENDING;
    CHECK(package_recorded(L"update-package",L"fixture",a)==ERROR_BUSY && !begins && !registrations);
    reset();fixtureRecord.phase=PB_INSTALL_CLEANED;
    BOOL removedOwnedPackage=FALSE;
    CHECK(package_finish_previous(&removedOwnedPackage)==0 && removedOwnedPackage && registrationOperation==2 && ownedCleanups==1);
    reset();fixtureRecord.phase=PB_INSTALL_CLEANED;registrationError=ERROR_FILE_NOT_FOUND;
    CHECK(package_finish_previous(&removedOwnedPackage)==0 && removedOwnedPackage && registrationOperation==2);
    reset();fixtureRecord.phase=PB_INSTALL_CLEANED;registrationError=ERROR_ACCESS_DENIED;
    CHECK(package_finish_previous(&removedOwnedPackage)==ERROR_ACCESS_DENIED && !removedOwnedPackage && registrationOperation==2);
    reset();fixtureRecord.phase=PB_INSTALL_REMOVING;
    CHECK(package_finish_previous(&removedOwnedPackage)==0 && removedOwnedPackage && removes==1 && cleanups==1 && ownedCleanups==1 && registrationOperation==2);
    reset();fixtureRecord.phase=PB_INSTALL_REMOVE_PENDING;removeError=3010;
    CHECK(package_finish_previous(&removedOwnedPackage)==3010 && !removedOwnedPackage && removes==1 && !cleanups && !registrations);
    reset();fixtureRecord.phase=PB_INSTALL_REMOVED;cleanupError=ERROR_SHARING_VIOLATION;
    CHECK(package_finish_previous(&removedOwnedPackage)==ERROR_SHARING_VIOLATION && !removedOwnedPackage && removes==1 && cleanups==1 && !registrations);
    reset();readError=ERROR_FILE_NOT_FOUND;CHECK(package_finish_previous(&removedOwnedPackage)==0 && !removedOwnedPackage && !registrations);
    reset();fixtureRecord.phase=PB_INSTALL_REMOVING;
    CHECK(package_recorded(L"update-package",L"fixture",a)==0 && begins==1 && beginAfterOwnedRemoval);
    puts("PASS package orchestration: ownership binding, rollback owner, reboot/error propagation, removal recovery and retry");return 0;
}

