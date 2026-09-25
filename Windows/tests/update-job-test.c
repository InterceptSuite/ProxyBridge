#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
static HANDLE proceed,finished,freedEvent;
static volatile LONG freedCount,deletedCount,errors;
static BOOL failThread;
static void counted_free(void *p){free(p);InterlockedIncrement(&freedCount);SetEvent(freedEvent);}
static BOOL WINAPI counted_delete(LPCWSTR path){(void)path;InterlockedIncrement(&deletedCount);return TRUE;}
static HANDLE WINAPI start_thread(LPSECURITY_ATTRIBUTES a,SIZE_T n,LPTHREAD_START_ROUTINE f,LPVOID p,DWORD flags,LPDWORD id){
    if(failThread){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}return CreateThread(a,n,f,p,flags,id);
}
#define free counted_free
#define DeleteFileW counted_delete
#define CreateThread start_thread
#include "../gui/ui/update-job.h"
#undef free
#undef DeleteFileW
#undef CreateThread
#define CHECK(x) do{if(!(x)){printf("FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static DWORD WINAPI worker(LPVOID p){
    UpdWork *job=p;WaitForSingleObject(proceed,INFINITE);
    if(job->manual && !UpdCancelled(job))InterlockedIncrement(&errors);
    job->success=!UpdCancelled(job);job->info.available=TRUE;
    InterlockedExchange(&job->done,1);SetEvent(finished);UpdWorkRelease(job);return 0;
}
int main(void){
    proceed=CreateEventW(NULL,TRUE,FALSE,NULL);finished=CreateEventW(NULL,TRUE,FALSE,NULL);freedEvent=CreateEventW(NULL,TRUE,FALSE,NULL);
    CHECK(proceed && finished && freedEvent);
    for(unsigned i=0;i<300;++i)for(unsigned mode=0;mode<4;++mode){
        ResetEvent(proceed);ResetEvent(finished);ResetEvent(freedEvent);
        LONG before=freedCount,removed=deletedCount;
        UpdWork *job=calloc(1,sizeof(*job));CHECK(job);job->refs=1;job->dest[0]=L'X';
        failThread=mode==3;job->manual=mode==0;
        if(mode==3){CHECK(!UpdWorkStart(job,worker));UpdWorkCancel(&job);}
        else {
            CHECK(UpdWorkStart(job,worker));
            if(mode==0){UpdWorkCancel(&job);CHECK(freedCount==before);SetEvent(proceed);}
            else {
                SetEvent(proceed);CHECK(WaitForSingleObject(finished,5000)==WAIT_OBJECT_0);
                CHECK(InterlockedCompareExchange(&job->done,0,0) && job->success && job->info.available);
                if(mode==2)job->keepDestination=TRUE;
                UpdWorkRelease(job);job=NULL;
            }
        }
        CHECK(WaitForSingleObject(freedEvent,5000)==WAIT_OBJECT_0);
        CHECK(freedCount==before+1 && deletedCount==removed+(mode==2?0:1) && !errors);
    }
    CloseHandle(proceed);CloseHandle(finished);CloseHandle(freedEvent);
    puts("PASS 1200 updater job lifetimes: cancel before completion, completion before release, launched file retention, thread creation failure");return 0;
}
