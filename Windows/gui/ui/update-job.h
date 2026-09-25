// Worker results are polled by the owning UI. Workers never retain HWNDs or
// post pointers; closing a window drops its reference without waiting on I/O.
#ifndef PB_UPDATE_JOB_H
#define PB_UPDATE_JOB_H
#include <windows.h>
#include <stdlib.h>
typedef struct {
    BOOL available;
    wchar_t latest[32], download[512], notes[512], date[32];
} UpdInfo;
typedef struct {
    volatile LONG refs, cancelled, done, progress;
    BOOL success, manual, keepDestination;
    UpdInfo info;
    wchar_t dest[MAX_PATH];
} UpdWork;
static BOOL UpdCancelled(UpdWork *job) { return InterlockedCompareExchange(&job->cancelled,0,0)!=0; }
static void UpdWorkRelease(UpdWork *job)
{
    if(InterlockedDecrement(&job->refs)==0) {
        if(job->dest[0] && !job->keepDestination)DeleteFileW(job->dest);
        free(job);
    }
}
static void UpdWorkCancel(UpdWork **slot)
{
    UpdWork *job=*slot;*slot=NULL;
    if(job){InterlockedExchange(&job->cancelled,1);UpdWorkRelease(job);}
}
static BOOL UpdWorkStart(UpdWork *job,LPTHREAD_START_ROUTINE worker)
{
    InterlockedIncrement(&job->refs);
    HANDLE thread=CreateThread(NULL,0,worker,job,0,NULL);
    if(!thread){UpdWorkRelease(job);return FALSE;}
    CloseHandle(thread);return TRUE;
}
#endif
