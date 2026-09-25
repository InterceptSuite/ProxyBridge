// ui/update.h - update checker (startup + manual): reads a
// custom JSON feed. Notification offers Update Now / Later /
// Don't Ask Again. Unity-build include: pulled into main.c after the theme helpers and the
// globals it uses (g_hInst, g_hMain, g_reallyExit).
#ifndef PB_UI_UPDATE_H
#define PB_UI_UPDATE_H

#include <winhttp.h>
#include "../profile/json.h"
#pragma comment(lib, "winhttp.lib")

#define UPD_FEED_URL  L"https://download.interceptsuite.com/proxybridge.json"

#include "update-job.h"
#define TIMER_UPDATE_CHECK 0x5055
#define TIMER_UPDATE_DOWNLOAD 0x5056
static void U8W(const char* s, wchar_t* out, int cch)
{
    MultiByteToWideChar(CP_UTF8, 0, s ? s : "", -1, out, cch);
}

// Parse the first three dot-separated integers, ignoring a leading 'v' and any suffix ("-Beta").
static void UpdParseVer(const wchar_t* s, int out[3])
{
    out[0] = out[1] = out[2] = 0;
    int i = 0;
    while (*s && (*s < L'0' || *s > L'9')) s++;   // skip 'v' / leading junk
    while (*s && i < 3)
    {
        if (*s >= L'0' && *s <= L'9') { int n = 0; while (*s >= L'0' && *s <= L'9') { n = n * 10 + (*s - L'0'); s++; } out[i++] = n; }
        else if (*s == L'.') s++;
        else break;                                // stop at '-Beta' etc.
    }
}
static int UpdVerCmp(const int a[3], const int b[3])
{
    for (int i = 0; i < 3; i++) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

#include "update-http.h"

// Fetch + parse the feed. Fills *out; returns FALSE only on network/parse failure.
static BOOL UpdCheck(UpdInfo* out, UpdWork* job)
{
    ZeroMemory(out, sizeof(*out));
    DWORD len = 0;
    char* body = UpdHttpGet(UPD_FEED_URL, &len, job);
    if (!body) return FALSE;
    JVal* root = json_parse(body, len);
    free(body);
    if (!root) return FALSE;
    BOOL ok = FALSE;
    JVal* win = json_get(root, "windows");
    if (win)
    {
        const char* ver   = json_str(win, "version", NULL);
        const char* dl    = json_str(win, "download", NULL);
        const char* notes = json_str(win, "release_notes", NULL);
        const char* date  = json_str(win, "release_date", NULL);
        if (ver)   U8W(ver,   out->latest,   32);
        if (dl)    U8W(dl,     out->download, 512);
        if (notes) U8W(notes,  out->notes,    512);
        if (date)  U8W(date,   out->date,     32);
        int cur[3], lat[3];
        UpdParseVer(APP_VERSION, cur);
        UpdParseVer(out->latest, lat);
        out->available = (out->download[0] != 0) && (UpdVerCmp(lat, cur) > 0);
        ok = TRUE;
    }
    json_free(root);
    return ok;
}

// Notification dialog. Only the UI owns dialog state; jobs are independently
// reference-counted so cancellation never waits for a synchronous HTTP call.
#include "update-launch.h"
typedef struct { UpdInfo info; UpdWork *job; BOOL launching; } UpdDialog;
static DWORD WINAPI UpdDlThread(LPVOID p)
{
    UpdWork *job=(UpdWork*)p;
    job->success=UpdDownload(job->info.download,job->dest,job);
    InterlockedExchange(&job->done,1);
    UpdWorkRelease(job);return 0;
}
static BOOL UpdReserveDestination(UpdWork *job)
{
    wchar_t directory[MAX_PATH],temporary[MAX_PATH],executable[MAX_PATH];
    DWORD length=GetTempPathW(MAX_PATH,directory);
    if(!length || length>=MAX_PATH || !GetTempFileNameW(directory,L"PBU",0,temporary))return FALSE;
    BOOL ok=_snwprintf_s(executable,MAX_PATH,_TRUNCATE,L"%s.exe",temporary)>=0 && MoveFileW(temporary,executable);
    if(ok)lstrcpynW(job->dest,executable,MAX_PATH);
    else DeleteFileW(temporary);
    return ok;
}
INT_PTR CALLBACK UpdateDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    UpdDialog *state=(UpdDialog*)GetWindowLongPtrW(dlg,GWLP_USERDATA);
    switch(msg)
    {
    case WM_INITDIALOG:
    {
        state=(UpdDialog*)calloc(1,sizeof(*state));
        if(!state){EndDialog(dlg,0);return TRUE;}
        state->info=*(UpdInfo*)lp;
        SetWindowLongPtrW(dlg,GWLP_USERDATA,(LONG_PTR)state);
        UpdInfo *info=&state->info;
        SetWindowTextW(dlg,T(S_UPD_TITLE));
        SetDlgItemTextW(dlg,IDC_UP_TEXT,T(S_UPD_AVAIL));
        wchar_t v[160];_snwprintf_s(v,160,_TRUNCATE,L"%s  \x2192  %s",APP_VERSION,info->latest);
        SetDlgItemTextW(dlg,IDC_UP_VERS,v);
        if(info->date[0]){wchar_t d[64];_snwprintf_s(d,64,_TRUNCATE,L"(%s)",info->date);SetDlgItemTextW(dlg,IDC_UP_DATE,d);}
        if(info->notes[0]){wchar_t n[640];_snwprintf_s(n,640,_TRUNCATE,L"<a href=\"%s\">%s</a>",info->notes,T(S_UPD_NOTES));SetDlgItemTextW(dlg,IDC_UP_NOTES,n);}
        else ShowWindow(GetDlgItem(dlg,IDC_UP_NOTES),SW_HIDE);
        SetDlgItemTextW(dlg,IDC_UP_NOW,T(S_UPD_NOW));
        SetDlgItemTextW(dlg,IDCANCEL,T(S_UPD_LATER));
        SetDlgItemTextW(dlg,IDC_UP_DONTASK,T(S_UPD_DONTASK));
        ShowWindow(GetDlgItem(dlg,IDC_UP_PROGRESS),SW_HIDE);
        InitDarkMode(dlg);return TRUE;
    }
    PB_DARK_CTLCOLORS;
    case WM_NOTIFY:
    {
        LPNMHDR nh=(LPNMHDR)lp;
        if((nh->code==NM_CLICK || nh->code==NM_RETURN) && nh->idFrom==IDC_UP_NOTES)
        {PNMLINK link=(PNMLINK)lp;ShellExecuteW(dlg,L"open",link->item.szUrl,NULL,NULL,SW_SHOWNORMAL);}
        return TRUE;
    }
    case WM_TIMER:
    {
        if(wp!=TIMER_UPDATE_DOWNLOAD || !state || !state->job)return FALSE;
        UpdWork *job=state->job;
        SendDlgItemMessageW(dlg,IDC_UP_PROGRESS,PBM_SETPOS,(WPARAM)InterlockedCompareExchange(&job->progress,0,0),0);
        if(!InterlockedCompareExchange(&job->done,0,0))return TRUE;
        KillTimer(dlg,TIMER_UPDATE_DOWNLOAD);state->job=NULL;
        if(job->success && !UpdCancelled(job))
        {
            DWORD error;BOOL previousActive=g_filteringActive;
            state->launching=TRUE;
            UpdLaunchResult result=UpdStopAndLaunch(dlg,job->dest,&error);
            if(result==UPD_LAUNCHED)job->keepDestination=TRUE;
            UpdWorkRelease(job);
            // ShellExecute may pump messages. Do not touch a dialog destroyed
            // during launch, or a recycled handle with different UI state.
            if((UpdDialog*)GetWindowLongPtrW(dlg,GWLP_USERDATA)!=state)return TRUE;
            state->launching=FALSE;
            if(result!=UPD_LAUNCHED) {
                if(previousActive!=g_filteringActive)
                    LogStoreAdd(&g_actStore,T(g_filteringActive ? S_FILTER_ACTIVE : S_FILTER_INACTIVE));
                wchar_t message[256];
                _snwprintf_s(message,256,_TRUNCATE,L"%s (%lu)",
                    T(result==UPD_STOP_FAILED ? S_UPD_STOPFAIL : result==UPD_RESTART_FAILED ? S_UPD_RESTARTFAIL : S_UPD_LAUNCHFAIL),error);
                SetDlgItemTextW(dlg,IDC_UP_STATUS,message);
                EnableWindow(GetDlgItem(dlg,IDC_UP_NOW),TRUE);return TRUE;
            }
            g_reallyExit=TRUE;EndDialog(dlg,IDOK);DestroyWindow(g_hMain);return TRUE;
        }
        UpdWorkRelease(job);
        SetDlgItemTextW(dlg,IDC_UP_STATUS,T(S_UPD_DLFAIL));
        EnableWindow(GetDlgItem(dlg,IDC_UP_NOW),TRUE);return TRUE;
    }
    case WM_COMMAND:
        if(!state || state->launching)return TRUE;
        switch(LOWORD(wp))
        {
        case IDC_UP_NOW:
        {
            if(state->job)return TRUE;
            UpdWork *job=(UpdWork*)calloc(1,sizeof(*job));if(!job)return TRUE;
            job->refs=1;job->info=state->info;
            if(!UpdReserveDestination(job) || !SetTimer(dlg,TIMER_UPDATE_DOWNLOAD,200,NULL)) {
                UpdWorkRelease(job);SetDlgItemTextW(dlg,IDC_UP_STATUS,T(S_UPD_DLFAIL));return TRUE;
            }
            state->job=job;
            if(!UpdWorkStart(job,UpdDlThread)) {
                KillTimer(dlg,TIMER_UPDATE_DOWNLOAD);UpdWorkCancel(&state->job);
                SetDlgItemTextW(dlg,IDC_UP_STATUS,T(S_UPD_DLFAIL));return TRUE;
            }
            EnableWindow(GetDlgItem(dlg,IDC_UP_NOW),FALSE);
            ShowWindow(GetDlgItem(dlg,IDC_UP_PROGRESS),SW_SHOW);
            SendDlgItemMessageW(dlg,IDC_UP_PROGRESS,PBM_SETRANGE,0,MAKELPARAM(0,100));
            SendDlgItemMessageW(dlg,IDC_UP_PROGRESS,PBM_SETPOS,0,0);
            SetDlgItemTextW(dlg,IDC_UP_STATUS,T(S_UPD_DLING));return TRUE;
        }
        case IDC_UP_DONTASK:PB_SetCheckUpdates(FALSE);EndDialog(dlg,0);return TRUE;
        case IDCANCEL:EndDialog(dlg,0);return TRUE;
        }
        return FALSE;
    case WM_CLOSE:
        if(!state || !state->launching)EndDialog(dlg,0);
        return TRUE;
    case WM_DESTROY:
        KillTimer(dlg,TIMER_UPDATE_DOWNLOAD);
        SetWindowLongPtrW(dlg,GWLP_USERDATA,0);
        if(state){UpdWorkCancel(&state->job);free(state);}
        return TRUE;
    }
    return FALSE;
}

// At most one feed check belongs to the main window. A manual check upgrades
// notification preference without creating another worker or racing its data.
static UpdWork *g_updateCheck;
static DWORD WINAPI UpdCheckThread(LPVOID p)
{
    UpdWork *job=(UpdWork*)p;
    job->success=UpdCheck(&job->info,job);
    InterlockedExchange(&job->done,1);
    UpdWorkRelease(job);return 0;
}
static void UpdStartCheck(HWND owner,BOOL manual)
{
    if(g_updateCheck){if(manual)g_updateCheck->manual=TRUE;return;}
    UpdWork *job=(UpdWork*)calloc(1,sizeof(*job));if(!job)return;
    job->refs=1;job->manual=manual;
    if(!SetTimer(owner,TIMER_UPDATE_CHECK,200,NULL)){UpdWorkRelease(job);return;}
    g_updateCheck=job;
    if(!UpdWorkStart(job,UpdCheckThread)){KillTimer(owner,TIMER_UPDATE_CHECK);UpdWorkCancel(&g_updateCheck);}
}
static void UpdPollCheck(HWND owner)
{
    UpdWork *job=g_updateCheck;
    if(!job || !InterlockedCompareExchange(&job->done,0,0))return;
    g_updateCheck=NULL;KillTimer(owner,TIMER_UPDATE_CHECK);
    UpdInfo info=job->info;BOOL ok=job->success && !UpdCancelled(job),manual=job->manual;
    UpdWorkRelease(job);
    if(ok && info.available)
        DialogBoxParamW(g_hInst,MAKEINTRESOURCEW(IDD_UPDATE),owner,UpdateDlgProc,(LPARAM)&info);
    else if(manual)
        MessageBoxW(owner,ok ? T(S_UPD_LATEST) : T(S_UPD_ERR),T(S_UPD_TITLE),MB_OK|MB_ICONINFORMATION);
}
static void UpdStopCheck(HWND owner)
{
    KillTimer(owner,TIMER_UPDATE_CHECK);UpdWorkCancel(&g_updateCheck);
}
#endif // PB_UI_UPDATE_H
