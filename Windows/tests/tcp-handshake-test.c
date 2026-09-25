#include "pb_internal.h"
volatile BOOL running=TRUE;
LogCallback g_log_callback;
#include "tcp-test-sockets.inc"
#define CHECK(x) do { if(!(x)){printf("FAIL handshake line %d error %d\n",__LINE__,WSAGetLastError());ExitProcess(1);} } while(0)
typedef struct { SOCKET socket; int kind, result; BOOL bounded; PROXY_CONFIG config; } CONNECT_CASE;
static DWORD WINAPI connect_client(void* arg)
{
    CONNECT_CASE* c=arg; PB_HANDSHAKE_CONTEXT deadline={GetTickCount64()+3000};
    const PB_HANDSHAKE_CONTEXT* ctx=c->bounded ? &deadline : NULL;
    UINT8 ip6[16]={0};ip6[15]=1;
    c->result=c->kind==0 ? socks5_connect(c->socket,htonl(INADDR_LOOPBACK),443,&c->config,ctx) :
        c->kind==1 ? socks5_connect_v6(c->socket,ip6,443,&c->config,ctx) :
        socks5_connect_domain(c->socket,"example.test",443,&c->config,ctx);
    return 0;
}
static void protocol_case(int kind, int replyKind, BOOL auth, BOOL bounded, BOOL reject)
{
    SOCKET peer,client;CHECK(socket_pair(&peer,&client));
    running=bounded;
    if(bounded){u_long one=1;CHECK(!ioctlsocket(client,FIONBIO,&one));}
    CONNECT_CASE c={0};c.socket=client;c.kind=kind;c.bounded=bounded;
    if(auth){strcpy_s(c.config.username,sizeof(c.config.username),"user");strcpy_s(c.config.password,sizeof(c.config.password),"secret");}
    HANDLE thread=CreateThread(NULL,0,connect_client,&c,0,NULL);CHECK(thread);
    CHECK(read_exact(peer,auth ? "\x05\x02\x00\x02" : "\x05\x01\x00",auth ? 4 : 3));
    CHECK(send_all(peer,auth ? "\x05\x02" : "\x05\x00",2)==2);
    if(auth){
        const char credentials[]={1,4,'u','s','e','r',6,'s','e','c','r','e','t'};
        CHECK(read_exact(peer,credentials,sizeof(credentials)));
        CHECK(send_all(peer,reject ? "\x01\x01" : "\x01\x00",2)==2);
    }
    if(!reject){
        char request[32]={5,1,0,1};int n;
        if(kind==0){request[4]=127;request[7]=1;n=10;}
        else if(kind==1){request[3]=4;request[19]=1;n=22;}
        else {request[3]=3;request[4]=12;memcpy(request+5,"example.test",12);n=19;}
        request[n-2]=1;request[n-1]=-69;
        CHECK(read_exact(peer,request,n));
        char reply[40]={5,0,0,1};int size;
        if(replyKind==0)size=10;
        else if(replyKind==1){reply[3]=4;size=22;}
        else{reply[3]=3;reply[4]=3;memcpy(reply+5,"bnd",3);size=10;}
        memcpy(reply+size,"early",5);
        CHECK(send_all(peer,reply,size+5)==size+5);
    }
    CHECK(WaitForSingleObject(thread,3000)==WAIT_OBJECT_0);
    CHECK(reject ? c.result!=0 : c.result==0);
    if(!reject)CHECK(read_exact(client,"early",5));
    CloseHandle(thread);closesocket(peer);closesocket(client);
}
typedef struct {SOCKET socket;char* data;int length,result,error,progress;DWORD timeout;} IO_CASE;
static DWORD WINAPI blocked_write(void* arg)
{
    IO_CASE* c=arg;PB_HANDSHAKE_CONTEXT deadline={GetTickCount64()+c->timeout};
    // Reuse one deadline across successive writes, as a multi-stage handshake
    // does. Small requests prevent Winsock buffering one huge send wholesale.
    while(c->progress<c->length){
        int n=pb_handshake_io(c->socket,c->data+c->progress,min(65536,c->length-c->progress),TRUE,TRUE,&deadline);
        if(n==SOCKET_ERROR){c->result=n;break;}
        c->progress+=n;c->result=c->progress;
    }
    c->error=WSAGetLastError();return 0;
}
static void blocked_write_case(BOOL cancel)
{
    SOCKET peer,client;CHECK(socket_pair(&peer,&client));running=TRUE;
    u_long one=1;CHECK(!ioctlsocket(client,FIONBIO,&one));int socketBuffer=4096;
    CHECK(!setsockopt(client,SOL_SOCKET,SO_SNDBUF,(char*)&socketBuffer,sizeof(socketBuffer)));
    CHECK(!setsockopt(peer,SOL_SOCKET,SO_RCVBUF,(char*)&socketBuffer,sizeof(socketBuffer)));
    IO_CASE c={0};c.socket=client;c.length=16*1024*1024;c.timeout=cancel ? 3000 : 600;
    c.data=malloc(c.length);CHECK(c.data);memset(c.data,'x',c.length);
    HANDLE thread=CreateThread(NULL,0,blocked_write,&c,0,NULL);CHECK(thread);
    char byte;CHECK(recv(peer,&byte,1,MSG_PEEK)==1 && byte=='x');
    DWORD wait=WaitForSingleObject(thread,100);
    if(wait!=WAIT_TIMEOUT)printf("blocked write early completion: cancel=%d result=%d error=%d\n",cancel,c.result,c.error);
    CHECK(wait==WAIT_TIMEOUT);
    if(cancel)running=FALSE;
    CHECK(WaitForSingleObject(thread,1500)==WAIT_OBJECT_0);
    CHECK(c.result==SOCKET_ERROR && c.error==(cancel ? WSAEINTR : WSAETIMEDOUT));
    CHECK(c.progress>0 && c.progress<c.length);
    CloseHandle(thread);free(c.data);closesocket(peer);closesocket(client);
}
int main(void)
{
    setvbuf(stdout,NULL,_IONBF,0);WSADATA wsa;CHECK(!WSAStartup(MAKEWORD(2,2),&wsa));
    unsigned cases=0;
    for(int bounded=0;bounded<2;bounded++)for(int auth=0;auth<2;auth++)
        for(int kind=0;kind<3;kind++)for(int reply=0;reply<3;reply++){
            protocol_case(kind,reply,auth,bounded,FALSE);cases++;
        }
    for(int bounded=0;bounded<2;bounded++)for(int kind=0;kind<3;kind++)protocol_case(kind,0,TRUE,bounded,TRUE);
    blocked_write_case(FALSE);blocked_write_case(TRUE);
    WSACleanup();printf("PASS %u SOCKS5 combinations; 6 auth rejections; partial-progress blocked write deadline/Stop\n",cases);return 0;
}

