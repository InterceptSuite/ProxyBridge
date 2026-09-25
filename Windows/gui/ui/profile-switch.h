// One worker and one replaceable queued request. Core publication stays on the
// UI thread, after checking request order and edits made while preparation ran.
#define TIMER_PROFILE_SWITCH 0x5057
typedef struct ProfileSwitchJob {
    volatile LONG refs, cancelled, done;
    UINT64 sequence, editRevision;
    WCHAR name[PB_NAME_MAX], deleteAfter[PB_NAME_MAX];
    PBProfile *profile;
    void *prepared;
    DWORD error;
    HMODULE module;
    PFN_PrepareProfile prepare;
    PFN_DiscardProfile discard;
} ProfileSwitchJob;
static ProfileSwitchJob *g_profileSwitchJob;
static UINT64 g_profileSwitchSequence, g_profileSwitchEdit;
static BOOL g_profileSwitchPending;
static WCHAR g_profileSwitchName[PB_NAME_MAX], g_profileSwitchDelete[PB_NAME_MAX];
static void ProfileSwitchRelease(ProfileSwitchJob *job)
{
    if (InterlockedDecrement(&job->refs)) return;
    if (job->prepared) job->discard(job->prepared);
    free(job->profile);
    if (job->module) FreeLibrary(job->module);
    free(job);
}
static DWORD WINAPI ProfileSwitchWorker(LPVOID argument)
{
    ProfileSwitchJob *job=argument;
    if (!InterlockedCompareExchange(&job->cancelled,0,0)) {
        job->profile=malloc(sizeof(*job->profile));
        if (!job->profile) job->error=ERROR_NOT_ENOUGH_MEMORY;
        else if (!PB_ProfileLoad(job->name,job->profile)) {job->error=GetLastError();if(!job->error)job->error=ERROR_INVALID_DATA;}
        else if (!InterlockedCompareExchange(&job->cancelled,0,0)) {
            job->prepared=PrepareEngineProfile(job->profile,job->prepare);
            if (!job->prepared) {job->error=GetLastError();if(!job->error)job->error=ERROR_INVALID_DATA;}
        }
    }
    InterlockedExchange(&job->done,1);
    ProfileSwitchRelease(job);return 0;
}
static void ProfileSwitchError(DWORD error)
{
    wchar_t message[512];
    _snwprintf_s(message,ARRAYSIZE(message),_TRUNCATE,T(S_ERR_PROFILEAPPLY),error);
    MessageBoxW(g_hMain,message,APP_TITLE,MB_OK|MB_ICONERROR);
}
static BOOL ProfileSwitchKick(void)
{
    if (g_profileSwitchJob || !g_profileSwitchPending) return TRUE;
    ProfileSwitchJob *job=calloc(1,sizeof(*job));
    if (!job) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    job->refs=1;job->sequence=g_profileSwitchSequence;job->editRevision=g_profileSwitchEdit;
    lstrcpynW(job->name,g_profileSwitchName,PB_NAME_MAX);
    lstrcpynW(job->deleteAfter,g_profileSwitchDelete,PB_NAME_MAX);
    job->prepare=g_api.PrepareProfile;job->discard=g_api.DiscardProfile;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,(LPCWSTR)(ULONG_PTR)job->prepare,&job->module)) {
        DWORD error=GetLastError();ProfileSwitchRelease(job);SetLastError(error);return FALSE;
    }
    if (!SetTimer(g_hMain,TIMER_PROFILE_SWITCH,50,NULL)) {
        DWORD error=GetLastError();ProfileSwitchRelease(job);SetLastError(error);return FALSE;
    }
    InterlockedIncrement(&job->refs);
    HANDLE thread=CreateThread(NULL,0,ProfileSwitchWorker,job,0,NULL);
    if (!thread) {
        DWORD error=GetLastError();ProfileSwitchRelease(job);ProfileSwitchRelease(job);
        KillTimer(g_hMain,TIMER_PROFILE_SWITCH);SetLastError(error);return FALSE;
    }
    CloseHandle(thread);g_profileSwitchJob=job;return TRUE;
}
static BOOL QueueProfileSwitch(const wchar_t *name,const wchar_t *deleteAfter)
{
    ++g_profileSwitchSequence;g_profileSwitchEdit=g_profileEditRevision;
    g_profileSwitchPending=_wcsicmp(name,g_activeProfile)!=0;
    lstrcpynW(g_profileSwitchName,name,PB_NAME_MAX);
    lstrcpynW(g_profileSwitchDelete,deleteAfter?deleteAfter:L"",PB_NAME_MAX);
    if (g_profileSwitchJob) InterlockedExchange(&g_profileSwitchJob->cancelled,1);
    if (!ProfileSwitchKick()) {
        DWORD error=GetLastError();g_profileSwitchPending=FALSE;UpdateTitle();ProfileSwitchError(error);return FALSE;
    }
    UpdateTitle();return TRUE;
}
static BOOL SwitchToProfile(const wchar_t *name) { return QueueProfileSwitch(name,NULL); }
static void ProfileSwitchPoll(void)
{
    ProfileSwitchJob *job=g_profileSwitchJob;
    // Modal editors hold views into g_profile. Do not replace it underneath them.
    if (!job || !IsWindowEnabled(g_hMain) || !InterlockedCompareExchange(&job->done,0,0)) return;
    g_profileSwitchJob=NULL;
    BOOL current=g_profileSwitchPending && job->sequence==g_profileSwitchSequence;
    DWORD error=0;
    if (current) {
        g_profileSwitchPending=FALSE;
        if (job->editRevision==g_profileEditRevision && !InterlockedCompareExchange(&job->cancelled,0,0)) {
            error=job->error;
            if (!error && job->prepared) {
                void *prepared=job->prepared;job->prepared=NULL; // Commit consumes on every outcome.
                if (!ApplyPreparedProfile(job->profile,prepared)) error=GetLastError();
                else {
                    g_profile=*job->profile;
                    ++g_profileEditRevision;
                    PB_SetActiveProfile(job->name);lstrcpynW(g_activeProfile,job->name,PB_NAME_MAX);
                    if (job->deleteAfter[0]) PB_ProfileDelete(job->deleteAfter);
                    g_localhost=g_profile.localhostViaProxy;g_trafficLog=g_profile.trafficLogging;
                    g_closeToTray=g_profile.closeToTray;g_autoClear=g_profile.autoClearLogs;
                    ApplyFilterSnapshot();ApplyTrafficLogging();SyncMenuChecks(g_hMain);RebuildProfileMenu(g_hMain);
                }
            }
        }
        // An edit after the selection wins. Keep its immediate publication and
        // discard the older profile silently instead of overwriting that edit.
    }
    ProfileSwitchRelease(job);
    if (!g_profileSwitchPending) KillTimer(g_hMain,TIMER_PROFILE_SWITCH);
    else if (!ProfileSwitchKick()) {error=GetLastError();g_profileSwitchPending=FALSE;KillTimer(g_hMain,TIMER_PROFILE_SWITCH);}
    UpdateTitle();if(error)ProfileSwitchError(error);
}
static void ProfileSwitchStop(void)
{
    KillTimer(g_hMain,TIMER_PROFILE_SWITCH);g_profileSwitchPending=FALSE;
    ProfileSwitchJob *job=g_profileSwitchJob;g_profileSwitchJob=NULL;
    if (job) {InterlockedExchange(&job->cancelled,1);ProfileSwitchRelease(job);}
}
