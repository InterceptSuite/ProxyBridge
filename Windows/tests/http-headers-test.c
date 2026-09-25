#include "pb_internal.h"
volatile BOOL running=TRUE;
LogCallback g_log_callback;
#include "tcp-test-sockets.inc"
static HANDLE prefixRead;
static LONG readBytes, prefixLength;
static int tracked_read(SOCKET s,char* data,int length,BOOL write,BOOL exact,const PB_HANDSHAKE_CONTEXT* context)
{
    int n=pb_handshake_io(s,data,length,write,exact,context);
    if (n>0 && !write && InterlockedAdd(&readBytes,n)>=prefixLength) SetEvent(prefixRead);
    return n;
}
#define pb_handshake_io tracked_read
#include "../src/proxy/pb_http_headers.inc"
#undef pb_handshake_io
#define CHECK(x) do { if(!(x)){printf("FAIL headers line %d error %d\n",__LINE__,WSAGetLastError());ExitProcess(1);} } while(0)
typedef struct { SOCKET s; BOOL bounded; int result; char response[4096]; } CASE;
static DWORD WINAPI reader(void* arg)
{
    CASE* c=arg; PB_HANDSHAKE_CONTEXT context={GetTickCount64()+2000};
    c->result=http_read_headers(c->s,c->response,sizeof(c->response),c->bounded ? &context : NULL);
    return 0;
}
int main(void)
{
    setvbuf(stdout,NULL,_IONBF,0); WSADATA wsa; CHECK(!WSAStartup(MAKEWORD(2,2),&wsa));
    const char header[]="HTTP/1.1 200 Connection established\r\nProxy-Agent: test\r\n\r\n";
    int length=(int)strlen(header); unsigned cases=0;
    prefixRead=CreateEventW(NULL,TRUE,FALSE,NULL); CHECK(prefixRead);
    for(int bounded=0;bounded<2;bounded++) {
        running=bounded; // standalone checks must work while Core is stopped
        for(int split=1;split<length;split++) {
            SOCKET server,input; CHECK(socket_pair(&server,&input));
            if(bounded){u_long one=1;CHECK(!ioctlsocket(input,FIONBIO,&one));}
            CASE c={0};c.s=input;c.bounded=bounded;
            readBytes=0;prefixLength=split;ResetEvent(prefixRead);
            HANDLE thread=CreateThread(NULL,0,reader,&c,0,NULL);CHECK(thread);
            CHECK(send_all(server,header,split)==split);
            CHECK(WaitForSingleObject(prefixRead,2000)==WAIT_OBJECT_0);
            CHECK(WaitForSingleObject(thread,0)==WAIT_TIMEOUT);
            char tail[128];int remaining=length-split;
            memcpy(tail,header+split,remaining);memcpy(tail+remaining,"payload",7);
            CHECK(send_all(server,tail,remaining+7)==remaining+7);
            CHECK(WaitForSingleObject(thread,2000)==WAIT_OBJECT_0);
            CHECK(c.result==length && !strcmp(c.response,header));
            // Bytes already sent with final header fragment must remain untouched.
            CHECK(read_exact(input,"payload",7));
            CloseHandle(thread);closesocket(server);closesocket(input);cases++;
        }
    }
    running=TRUE;
    SOCKET server,input;CHECK(socket_pair(&server,&input));
    u_long one=1;CHECK(!ioctlsocket(input,FIONBIO,&one));
    char response[4096]; PB_HANDSHAKE_CONTEXT expired={GetTickCount64()};
    CHECK(http_read_headers(input,response,sizeof(response),&expired)==-1 && WSAGetLastError()==WSAETIMEDOUT);
    char oversized[4095];memset(oversized,'x',sizeof(oversized));CHECK(send_all(server,oversized,sizeof(oversized))==sizeof(oversized));
    PB_HANDSHAKE_CONTEXT live={GetTickCount64()+2000};
    CHECK(http_read_headers(input,response,sizeof(response),&live)==-1 && WSAGetLastError()==WSAEMSGSIZE);
    closesocket(server);closesocket(input);CloseHandle(prefixRead);WSACleanup();
    printf("PASS %u HTTP header split cases, standalone/bounded, payload preservation, deadline and header cap\n",cases);
    return 0;
}
