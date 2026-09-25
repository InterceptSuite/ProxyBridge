#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef struct {LONG cancelled,progress;} UpdWork;
static BOOL UpdCancelled(UpdWork *job){return job->cancelled!=0;}
static DWORD statusCode,bodySize,offset,contentLength,opened,writes,closed;
static BOOL queryFailure,readFailure,writeFailure,shortWrite,cancelRead;
static UpdWork *active;
static BOOL crack(URL_COMPONENTS *url){url->nScheme=INTERNET_SCHEME_HTTPS;url->nPort=443;return TRUE;}
static BOOL headers(DWORD flags,LPVOID out){*(DWORD*)out=(flags&~WINHTTP_QUERY_FLAG_NUMBER)==WINHTTP_QUERY_STATUS_CODE?statusCode:contentLength;return TRUE;}
static BOOL available(DWORD *out){if(queryFailure)return FALSE;*out=bodySize-offset;return TRUE;}
static BOOL read_data(void *buffer,DWORD bytes,DWORD *read){
    if(readFailure)return FALSE;*read=bytes;memset(buffer,'x',bytes);offset+=bytes;
    if(cancelRead)active->cancelled=1;return TRUE;
}
static HANDLE open_file(void){++opened;return (HANDLE)4;}
static BOOL write_data(DWORD bytes,DWORD *written){++writes;*written=shortWrite?bytes-1:bytes;return !writeFailure;}
#define WinHttpCrackUrl(a,b,c,d) crack(d)
#define WinHttpOpen(a,b,c,d,e) ((HINTERNET)1)
#define WinHttpSetTimeouts(a,b,c,d,e) TRUE
#define WinHttpConnect(a,b,c,d) ((HINTERNET)2)
#define WinHttpOpenRequest(a,b,c,d,e,f,g) ((HINTERNET)3)
#define WinHttpSendRequest(a,b,c,d,e,f,g) TRUE
#define WinHttpReceiveResponse(a,b) TRUE
#define WinHttpQueryHeaders(a,b,c,d,e,f) headers(b,d)
#define WinHttpCloseHandle(a) (++closed,TRUE)
#define WinHttpQueryDataAvailable(a,b) available(b)
#define WinHttpReadData(a,b,c,d) read_data(b,c,d)
#define CreateFileW(a,b,c,d,e,f,g) open_file()
#define WriteFile(a,b,c,d,e) write_data(c,d)
#define CloseHandle(a) TRUE
// Macro backends intentionally ignore production arguments in this test.
#pragma warning(disable:4100 4189 4555)
#include "../gui/ui/update-http.h"
#define CHECK(x) do{if(!(x)){printf("FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static void reset(UpdWork *job){
    ZeroMemory(job,sizeof(*job));active=job;statusCode=200;bodySize=contentLength=32769;offset=opened=writes=closed=0;
    queryFailure=readFailure=writeFailure=shortWrite=cancelRead=FALSE;
}
int main(void){
    UpdWork job;DWORD len=0;char *body;
    reset(&job);CHECK(UpdDownload(L"fixture",L"fixture",&job) && opened==1 && writes==3 && job.progress==100 && closed==3);
    reset(&job);statusCode=404;CHECK(!UpdDownload(L"fixture",L"fixture",&job) && !opened && closed==3);
    reset(&job);statusCode=500;CHECK(!UpdHttpGet(L"fixture",&len,&job) && closed==3);
    reset(&job);shortWrite=TRUE;CHECK(!UpdDownload(L"fixture",L"fixture",&job));
    reset(&job);writeFailure=TRUE;CHECK(!UpdDownload(L"fixture",L"fixture",&job));
    reset(&job);contentLength++;CHECK(!UpdDownload(L"fixture",L"fixture",&job));
    reset(&job);bodySize=contentLength=0;CHECK(!UpdDownload(L"fixture",L"fixture",&job));
    reset(&job);job.cancelled=1;CHECK(!UpdDownload(L"fixture",L"fixture",&job) && !opened);
    reset(&job);cancelRead=TRUE;CHECK(!UpdDownload(L"fixture",L"fixture",&job));
    reset(&job);readFailure=TRUE;CHECK(!UpdDownload(L"fixture",L"fixture",&job));
    reset(&job);queryFailure=TRUE;CHECK(!UpdDownload(L"fixture",L"fixture",&job));
    reset(&job);body=UpdHttpGet(L"fixture",&len,&job);CHECK(body && len==bodySize && !body[len]);free(body);
    reset(&job);bodySize=1048577;CHECK(!UpdHttpGet(L"fixture",&len,&job));
    reset(&job);readFailure=TRUE;CHECK(!UpdHttpGet(L"fixture",&len,&job));
    reset(&job);queryFailure=TRUE;CHECK(!UpdHttpGet(L"fixture",&len,&job));
    reset(&job);cancelRead=TRUE;CHECK(!UpdHttpGet(L"fixture",&len,&job));
    puts("PASS updater HTTP: status, cancellation, short/write/read/query failures, empty/truncated payload, feed size bound; all I/O mocked");return 0;
}
