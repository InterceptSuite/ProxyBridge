// Isolated loopback send API experiment; not a full WFP/proxy throughput test.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d WSA=%d\n",__LINE__,WSAGetLastError());ExitProcess(1);}}while(0)
static SOCKET receiver;
static HANDLE gate;
static volatile LONG sendDone;
static unsigned payloadSize,packetCount,received;
static unsigned burst,idleCount,pollCalls;
static WSAPOLLFD polls[257];
static LONGLONG frequency,lastReceive,*latencies;
static const unsigned char header[22]={0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,187};
static DWORD WINAPI receive_packets(void *unused)
{
    (void)unused;unsigned char data[8214];unsigned long long lastSequence=0;
    CHECK(WaitForSingleObject(gate,10000)==WAIT_OBJECT_0);
    for(;;){
        if(burst){
            int ready=WSAPoll(polls,idleCount+1,100);++pollCalls;CHECK(ready!=SOCKET_ERROR);
            if(!ready){if(InterlockedCompareExchange(&sendDone,0,0))break;continue;}
        }
        BOOL complete=FALSE;
        for(unsigned packet=0;packet<(burst?burst:1);++packet){
        int bytes=recv(receiver,(char*)data,sizeof(data),0);
        if(bytes==SOCKET_ERROR){
            CHECK(WSAGetLastError()==(burst?WSAEWOULDBLOCK:WSAETIMEDOUT));
            complete=InterlockedCompareExchange(&sendDone,0,0)!=0;
            break;
        }
        LARGE_INTEGER now;QueryPerformanceCounter(&now);lastReceive=now.QuadPart;
        CHECK(bytes==(int)(payloadSize+sizeof(header)) && !memcmp(data,header,sizeof(header)));
        unsigned long long sequence;LONGLONG sent;
        memcpy(&sequence,data+sizeof(header),8);memcpy(&sent,data+sizeof(header)+8,8);
        CHECK(sequence<packetCount && (!received || sequence>lastSequence));lastSequence=sequence;
        for(unsigned i=16;i<payloadSize;++i)CHECK(data[sizeof(header)+i]==0x5a);
        CHECK(received<packetCount);latencies[received++]=now.QuadPart-sent;
        }
        if(complete)break;
    }
    return 0;
}
static unsigned long long ticks(FILETIME f){return ((unsigned long long)f.dwHighDateTime<<32)|f.dwLowDateTime;}
static int compare(const void *a,const void *b){LONGLONG x=*(const LONGLONG*)a,y=*(const LONGLONG*)b;return (x>y)-(x<y);}
int main(int argc,char **argv)
{
    CHECK(argc==4 || argc==6);int vector=atoi(argv[1]);payloadSize=(unsigned)atoi(argv[2]);packetCount=(unsigned)atoi(argv[3]);
    if(argc==6){burst=(unsigned)atoi(argv[4]);idleCount=(unsigned)atoi(argv[5]);CHECK(burst>=1 && burst<=32 && idleCount<=256);}
    CHECK((vector==0 || vector==1) && payloadSize>=16 && payloadSize<=8192 && packetCount>=1000 && packetCount<=1000000);
    WSADATA wsa;CHECK(!WSAStartup(MAKEWORD(2,2),&wsa));
    receiver=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);SOCKET sender=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    CHECK(receiver!=INVALID_SOCKET && sender!=INVALID_SOCKET);
    struct sockaddr_in address={0};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    CHECK(!bind(receiver,(struct sockaddr*)&address,sizeof(address)));int size=sizeof(address);
    CHECK(!getsockname(receiver,(struct sockaddr*)&address,&size));
    int buffer=4194304;DWORD timeout=100;
    CHECK(!setsockopt(receiver,SOL_SOCKET,SO_RCVBUF,(char*)&buffer,sizeof(buffer)));
    CHECK(!setsockopt(receiver,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout)));
    CHECK(!setsockopt(sender,SOL_SOCKET,SO_SNDBUF,(char*)&buffer,sizeof(buffer)));
    if(burst){
        u_long nonblock=1;CHECK(!ioctlsocket(receiver,FIONBIO,&nonblock));
        polls[0].fd=receiver;polls[0].events=POLLRDNORM;
        struct sockaddr_in idleAddress=address;idleAddress.sin_port=0;
        for(unsigned i=1;i<=idleCount;++i){
            polls[i].fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(polls[i].fd!=INVALID_SOCKET);
            CHECK(!bind(polls[i].fd,(struct sockaddr*)&idleAddress,sizeof(idleAddress)));polls[i].events=POLLRDNORM;
        }
    }
    latencies=malloc((size_t)packetCount*sizeof(*latencies));CHECK(latencies);
    gate=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(gate);
    HANDLE thread=CreateThread(NULL,0,receive_packets,NULL,0,NULL);CHECK(thread);
    unsigned char body[8192],contiguous[8214];memset(body,0x5a,sizeof(body));
    WSABUF pieces[2]={{sizeof(header),(CHAR*)header},{payloadSize,(CHAR*)body}};
    LARGE_INTEGER fq,begin,end;QueryPerformanceFrequency(&fq);frequency=fq.QuadPart;
    FILETIME created,exited,k0,u0,k1,u1;CHECK(GetProcessTimes(GetCurrentProcess(),&created,&exited,&k0,&u0));
    QueryPerformanceCounter(&begin);CHECK(SetEvent(gate));
    for(unsigned i=0;i<packetCount;++i){
        unsigned long long sequence=i;LARGE_INTEGER stamp;QueryPerformanceCounter(&stamp);
        memcpy(body,&sequence,8);memcpy(body+8,&stamp.QuadPart,8);
        if(vector){DWORD sent=0;CHECK(!WSASendTo(sender,pieces,2,&sent,0,(struct sockaddr*)&address,sizeof(address),NULL,NULL));CHECK(sent==payloadSize+sizeof(header));}
        else {
            memcpy(contiguous,header,sizeof(header));memcpy(contiguous+sizeof(header),body,payloadSize);
            CHECK(sendto(sender,(char*)contiguous,(int)(payloadSize+sizeof(header)),0,(struct sockaddr*)&address,sizeof(address))==(int)(payloadSize+sizeof(header)));
        }
    }
    QueryPerformanceCounter(&end);InterlockedExchange(&sendDone,1);
    CHECK(WaitForSingleObject(thread,10000)==WAIT_OBJECT_0 && received);
    CHECK(GetProcessTimes(GetCurrentProcess(),&created,&exited,&k1,&u1));
    LONGLONG finish=end.QuadPart>lastReceive?end.QuadPart:lastReceive;
    double seconds=(double)(finish-begin.QuadPart)/frequency;
    double cpu=(double)(ticks(k1)+ticks(u1)-ticks(k0)-ticks(u0))/1e7;
    qsort(latencies,received,sizeof(*latencies),compare);
    if(argc==6)printf("%u,%u,%u,",burst,idleCount,pollCalls);
    printf("%s,%u,%u,%u,%.6f,%.1f,%.6f,%.3f,%.3f\n",vector?"vector":"copy",payloadSize,packetCount,received,seconds,received/seconds,cpu,
        (double)latencies[received/2]*1e6/frequency,(double)latencies[(size_t)received*99/100]*1e6/frequency);
    for(unsigned i=1;i<=idleCount;++i)closesocket(polls[i].fd);
    free(latencies);CloseHandle(thread);CloseHandle(gate);closesocket(sender);closesocket(receiver);WSACleanup();return 0;
}
