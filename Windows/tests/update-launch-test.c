#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include "../gui/api/pb_api.h"
static PBApi g_api;
static BOOL g_started,g_filteringActive,guardHeld;
static BOOL stopOk,startOk,launchOk;
static unsigned stopCalls,startCalls,launchCalls;
static HANDLE launchedHandle;
#define CHECK(x) do{if(!(x)){printf("FAIL update line %d\n",__LINE__);ExitProcess(1);}}while(0)
static BOOL fake_stop(void)
{stopCalls++;if(!stopOk){SetLastError(ERROR_BUSY);return FALSE;}guardHeld=FALSE;return TRUE;}
static BOOL fake_start(void)
{startCalls++;CHECK(!guardHeld);guardHeld=startOk;return startOk;}
static BOOL fake_active(void){return guardHeld;}
static BOOL WINAPI fake_launch(SHELLEXECUTEINFOW* launch)
{
    launchCalls++;CHECK(!guardHeld && !g_started && !g_filteringActive);
    CHECK((launch->fMask&SEE_MASK_NOASYNC)!=0);
    if(!launchOk){SetLastError(ERROR_CANCELLED);return FALSE;}
    launch->hProcess=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(launch->hProcess);launchedHandle=launch->hProcess;return TRUE;
}
#define ShellExecuteExW fake_launch
#include "../gui/ui/update-launch.h"
#undef ShellExecuteExW
int main(void)
{
    g_api.Stop=fake_stop;g_api.Start=fake_start;g_api.IsFilteringActive=fake_active;
    for(int started=0;started<2;started++)for(int stop=0;stop<2;stop++)
        for(int launch=0;launch<2;launch++)for(int restart=0;restart<2;restart++){
            g_started=g_filteringActive=guardHeld=started;stopOk=stop;launchOk=launch;startOk=restart;
            stopCalls=startCalls=launchCalls=0;DWORD error=0;
            UpdLaunchResult result=UpdStopAndLaunch(NULL,L"fixture-installer.exe",&error);
            if(started && !stop){CHECK(result==UPD_STOP_FAILED && error==ERROR_BUSY && guardHeld && !launchCalls && !startCalls);}
            else if(launch){
                CHECK(result==UPD_LAUNCHED && !guardHeld && !g_started && !startCalls && launchCalls==1);
                DWORD flags;CHECK(!GetHandleInformation(launchedHandle,&flags) && GetLastError()==ERROR_INVALID_HANDLE);
            }
            else {
                CHECK(error==ERROR_CANCELLED && launchCalls==1);
                CHECK(result==(started && !restart ? UPD_RESTART_FAILED : UPD_LAUNCH_FAILED));
                CHECK(startCalls==(unsigned)started && g_started==(started && restart));
            }
            CHECK(stopCalls==(unsigned)started);
        }
    puts("PASS 16 update handoff cases: stop gate ordering, launch cancellation, restart failure, initially stopped");return 0;
}
