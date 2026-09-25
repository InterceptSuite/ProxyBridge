#ifndef PB_UPDATE_LAUNCH_H
#define PB_UPDATE_LAUNCH_H
typedef enum { UPD_LAUNCHED, UPD_STOP_FAILED, UPD_LAUNCH_FAILED, UPD_RESTART_FAILED } UpdLaunchResult;
// UI-thread handoff: a successful synchronous Stop releases the runtime gate
// before installer execution. Keep the GUI alive on any failed launch.
static UpdLaunchResult UpdStopAndLaunch(HWND owner,const wchar_t* path,DWORD* error)
{
    BOOL wasStarted=g_started;
    *error=ERROR_SUCCESS;
    if(wasStarted) {
        if(!g_api.Stop) {*error=ERROR_PROC_NOT_FOUND;return UPD_STOP_FAILED;}
        if(!g_api.Stop()) {*error=GetLastError();return UPD_STOP_FAILED;}
        g_started=FALSE;g_filteringActive=FALSE;
    }
    SHELLEXECUTEINFOW launch={0};launch.cbSize=sizeof(launch);
    launch.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;
    launch.hwnd=owner;launch.lpVerb=L"open";launch.lpFile=path;launch.nShow=SW_SHOWNORMAL;
    if(ShellExecuteExW(&launch)) {
        if(launch.hProcess)CloseHandle(launch.hProcess);
        return UPD_LAUNCHED;
    }
    *error=GetLastError();
    if(wasStarted) {
        g_started=g_api.Start && g_api.Start();
        g_filteringActive=g_started && g_api.IsFilteringActive && g_api.IsFilteringActive();
        if(!g_started || !g_filteringActive)return UPD_RESTART_FAILED;
    }
    return UPD_LAUNCH_FAILED;
}
#endif
