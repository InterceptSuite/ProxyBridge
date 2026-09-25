#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../gui/api/pb_api.h"
#include "../gui/profile/profile.h"
static PBApi g_api;
static PBProfile g_profile;
static HWND g_hMain=(HWND)1;
static WCHAR g_activeProfile[PB_NAME_MAX]=L"A",deletedName[PB_NAME_MAX];
static UINT64 g_profileEditRevision;
static BOOL g_localhost,g_trafficLog,g_closeToTray,g_autoClear;
static BOOL enabled=TRUE,failThread,acceptCommit=TRUE;
static unsigned commits,discards,pins,unpins,errors,deletes;
static LPTHREAD_START_ROUTINE pendingWorker;
static void *pendingArgument;
static void UpdateTitle(void){}
static void ApplyFilterSnapshot(void){}
static void ApplyTrafficLogging(void){}
static void SyncMenuChecks(HWND h){(void)h;}
static void RebuildProfileMenu(HWND h){(void)h;}
static const WCHAR *T(int id){(void)id;return L"error %lu";}
#define S_ERR_PROFILEAPPLY 0
#define APP_TITLE L"fixture"
BOOL PB_ProfileLoad(const WCHAR *name,PBProfile *profile){(void)name;ZeroMemory(profile,sizeof(*profile));return TRUE;}
void PB_SetActiveProfile(const WCHAR *name){(void)name;}
BOOL PB_ProfileDelete(const WCHAR *name){++deletes;wcscpy_s(deletedName,PB_NAME_MAX,name);return TRUE;}
static void discard(void *handle){++discards;free(handle);}
static void *PrepareEngineProfile(PBProfile *profile,PFN_PrepareProfile prepare){(void)profile;(void)prepare;return malloc(1);}
static BOOL ApplyPreparedProfile(PBProfile *profile,void *handle){(void)profile;++commits;free(handle);if(!acceptCommit)SetLastError(ERROR_GEN_FAILURE);return acceptCommit;}
static BOOL WINAPI pin(DWORD flags,LPCWSTR address,HMODULE *module){(void)flags;(void)address;++pins;*module=(HMODULE)2;return TRUE;}
static BOOL WINAPI unpin(HMODULE module){(void)module;++unpins;return TRUE;}
static HANDLE WINAPI start(LPSECURITY_ATTRIBUTES a,SIZE_T size,LPTHREAD_START_ROUTINE worker,void *argument,DWORD flags,LPDWORD id){
    (void)a;(void)size;(void)flags;(void)id;
    if(failThread){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}
    if(pendingWorker){puts("FAIL unbounded workers");ExitProcess(2);}
    pendingWorker=worker;pendingArgument=argument;return (HANDLE)3;
}
static int WINAPI show_error(HWND owner,LPCWSTR text,LPCWSTR title,UINT flags){(void)owner;(void)text;(void)title;(void)flags;++errors;return IDOK;}
#define GetModuleHandleExW pin
#define FreeLibrary unpin
#define CreateThread start
#define CloseHandle(h) TRUE
#define SetTimer(h,id,period,callback) ((UINT_PTR)1)
#define KillTimer(h,id) TRUE
#define IsWindowEnabled(h) enabled
#define MessageBoxW show_error
#pragma warning(disable:4555)
#include "../gui/ui/profile-switch.h"
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
static void run(void){LPTHREAD_START_ROUTINE worker=pendingWorker;void *argument=pendingArgument;pendingWorker=NULL;pendingArgument=NULL;worker(argument);}
int main(void){
    g_api.DiscardProfile=discard;
    CHECK(SwitchToProfile(L"B") && g_profileSwitchJob);
    CHECK(SwitchToProfile(L"C"));run();ProfileSwitchPoll();CHECK(!commits && pendingWorker);
    run();ProfileSwitchPoll();CHECK(commits==1 && !_wcsicmp(g_activeProfile,L"C") && pins==unpins);
    CHECK(SwitchToProfile(L"D"));run();enabled=FALSE;ProfileSwitchPoll();CHECK(commits==1 && g_profileSwitchJob);
    enabled=TRUE;ProfileSwitchPoll();CHECK(commits==2 && !_wcsicmp(g_activeProfile,L"D"));
    CHECK(SwitchToProfile(L"E"));run();++g_profileEditRevision;ProfileSwitchPoll();CHECK(commits==2 && discards==1);
    CHECK(QueueProfileSwitch(L"Default",L"D"));run();acceptCommit=FALSE;ProfileSwitchPoll();
    CHECK(errors==1 && !deletes && !_wcsicmp(g_activeProfile,L"D"));
    acceptCommit=TRUE;CHECK(QueueProfileSwitch(L"Default",L"D"));run();ProfileSwitchPoll();
    CHECK(deletes==1 && !_wcsicmp(deletedName,L"D") && !_wcsicmp(g_activeProfile,L"Default"));
    CHECK(SwitchToProfile(L"F"));CHECK(SwitchToProfile(L"Default"));run();ProfileSwitchPoll();
    CHECK(!pendingWorker && !g_profileSwitchPending && !_wcsicmp(g_activeProfile,L"Default"));
    failThread=TRUE;CHECK(!SwitchToProfile(L"G") && errors==2 && pins==unpins);failThread=FALSE;
    CHECK(SwitchToProfile(L"H"));ProfileSwitchStop();CHECK(pins==unpins+1);run();CHECK(pins==unpins && !g_profileSwitchJob);
    CHECK(SwitchToProfile(L"I"));run();ProfileSwitchStop();CHECK(pins==unpins && discards==2);
    puts("PASS GUI profile queue: latest request, modal editor, newer edits, deferred delete only after commit, active selection cancels, thread failure and shutdown; UI/Core/threads mocked");return 0;
}

