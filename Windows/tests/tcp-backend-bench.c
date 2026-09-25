#include "pb_internal.h"
#include <tlhelp32.h>
#include <psapi.h>
volatile BOOL running=TRUE;
LogCallback g_log_callback;
#ifdef PB_TCP_INLINE_CANDIDATE
#include "tcp-iocp-inline-candidate.inc"
#elif defined(PB_TCP_BATCH_CANDIDATE)
#include "tcp-iocp-batch-candidate.inc"
#elif defined(PB_TCP_SHARDED_CANDIDATE)
#include "tcp-iocp-sharded-candidate.inc"
#else
#include "../src/relay/pb_tcp_iocp.inc"
#endif
#include "../src/relay/pb_tcp_transfer.inc"
#include "tcp-test-sockets.inc"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL bench line %d WSA %d\n",__LINE__,WSAGetLastError());ExitProcess(1);}}while(0)
typedef struct {SOCKET sender,receiver,a,b;HANDLE writer,reader,legacy;UINT64 blocks;unsigned id;} STREAM;
static HANDLE gate;
static DWORD WINAPI writer(void* arg)
{
    STREAM* stream=arg;char data[65536];memset(data,0x5a,sizeof(data));
    CHECK(WaitForSingleObject(gate,30000)==WAIT_OBJECT_0);
    for(UINT64 i=0;i<stream->blocks;i++){
        UINT64 sequence=i*256+stream->id;memcpy(data,&sequence,sizeof(sequence));
        CHECK(send_all(stream->sender,data,sizeof(data))==sizeof(data));
    }
    CHECK(!shutdown(stream->sender,SD_SEND));CHECK(read_exact(stream->sender,"Y",1));
    char end;CHECK(recv(stream->sender,&end,1,0)==0);return 0;
}
static DWORD WINAPI reader(void* arg)
{
    STREAM* stream=arg;char data[65536],expected[65536];memset(expected,0x5a,sizeof(expected));
    CHECK(WaitForSingleObject(gate,30000)==WAIT_OBJECT_0);
    for(UINT64 i=0;i<stream->blocks;i++){
        UINT64 sequence=i*256+stream->id;memcpy(expected,&sequence,sizeof(sequence));
        CHECK(recv_n(stream->receiver,data,sizeof(data))==sizeof(data));
        CHECK(!memcmp(data,expected,sizeof(data)));
    }
    char end;CHECK(recv(stream->receiver,&end,1,0)==0);
    CHECK(send_all(stream->receiver,"Y",1)==1 && !shutdown(stream->receiver,SD_SEND));return 0;
}
static DWORD threads(void)
{
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);CHECK(snapshot!=INVALID_HANDLE_VALUE);
    THREADENTRY32 entry={sizeof(entry)};DWORD count=0;
    BOOL next=Thread32First(snapshot,&entry);
    while(next){if(entry.th32OwnerProcessID==GetCurrentProcessId())count++;next=Thread32Next(snapshot,&entry);}
    CloseHandle(snapshot);return count;
}
static SIZE_T private_bytes(void)
{
    PROCESS_MEMORY_COUNTERS_EX memory={0};memory.cb=sizeof(memory);
    CHECK(GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&memory,sizeof(memory)));return memory.PrivateUsage;
}
static UINT64 ticks(FILETIME t){return ((UINT64)t.dwHighDateTime<<32)|t.dwLowDateTime;}
int main(int argc,char** argv)
{
    setvbuf(stdout,NULL,_IONBF,0);CHECK(argc==3 || argc==4);
    int relayBuffer=argc==4?atoi(argv[3]):4194304;
    CHECK(relayBuffer>=8192 && relayBuffer<=4194304);
    int mode=atoi(argv[1]),count=atoi(argv[2]);CHECK(mode>=0 && mode<=2 && count>=1 && count<=64);
    WSADATA wsa;CHECK(!WSAStartup(MAKEWORD(2,2),&wsa));
    DWORD initialThreads=threads();SIZE_T initialPrivate=private_bytes();
    if(mode==1)CHECK(tcp_io_start());
    STREAM streams[64]={0};gate=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(gate);
    for(int i=0;i<count;i++){
        STREAM* s=&streams[i];s->id=i;s->blocks=65536/count;s->a=s->b=INVALID_SOCKET;
        CHECK(socket_pair(&s->sender,&s->a));
        if(mode==0){s->receiver=s->a;s->a=INVALID_SOCKET;}
        else{
            CHECK(socket_pair(&s->receiver,&s->b));
            configure_tcp_socket(s->a,relayBuffer,30000);configure_tcp_socket(s->b,relayBuffer,30000);
            if(mode==1)CHECK(tcp_io_attach(s->a,s->b));
            else{
                TRANSFER_CONFIG* config=malloc(sizeof(*config));CHECK(config);
                config->from_socket=s->a;config->to_socket=s->b;
                s->legacy=CreateThread(NULL,0,transfer_handler,config,0,NULL);CHECK(s->legacy);
            }
        }
        configure_tcp_socket(s->sender,4194304,30000);configure_tcp_socket(s->receiver,4194304,30000);
    }
#ifdef PB_TCP_INLINE_CANDIDATE
    if(mode==1) CHECK(tcpIoSkipEnabled==(unsigned)count*2);
#endif
    // Permit newly created legacy upload workers to enter recv before snapshot.
    Sleep(100);DWORD relayThreads=threads()-initialThreads;SIZE_T attachedPrivate=private_bytes();
    for(int i=0;i<count;i++){
        streams[i].reader=CreateThread(NULL,0,reader,&streams[i],0,NULL);CHECK(streams[i].reader);
        streams[i].writer=CreateThread(NULL,0,writer,&streams[i],0,NULL);CHECK(streams[i].writer);
    }
    LARGE_INTEGER frequency,begin,end;FILETIME created,exit,k0,u0,k1,u1;
    CHECK(QueryPerformanceFrequency(&frequency));CHECK(GetProcessTimes(GetCurrentProcess(),&created,&exit,&k0,&u0));
    QueryPerformanceCounter(&begin);CHECK(SetEvent(gate));
    for(int i=0;i<count;i++){
        CHECK(WaitForSingleObject(streams[i].writer,30000)==WAIT_OBJECT_0);
        CHECK(WaitForSingleObject(streams[i].reader,30000)==WAIT_OBJECT_0);
    }
    QueryPerformanceCounter(&end);CHECK(GetProcessTimes(GetCurrentProcess(),&created,&exit,&k1,&u1));
    double seconds=(double)(end.QuadPart-begin.QuadPart)/frequency.QuadPart;
    double cpu=(double)(ticks(k1)+ticks(u1)-ticks(k0)-ticks(u0))/1e7;
    SIZE_T transferredPrivate=private_bytes();
    if(mode==1)tcp_io_stop();
    for(int i=0;i<count;i++){
        STREAM* s=&streams[i];CloseHandle(s->reader);CloseHandle(s->writer);
        if(mode==2){CHECK(WaitForSingleObject(s->legacy,3000)==WAIT_OBJECT_0);CloseHandle(s->legacy);closesocket(s->a);closesocket(s->b);}
        closesocket(s->sender);closesocket(s->receiver);
    }
    CloseHandle(gate);WSACleanup();
    if(argc==4)printf("%d,",relayBuffer);
    printf("%s,%d,4096,%.6f,%.3f,%.6f,%lu,%llu,%llu\n",mode==0 ? "direct" : mode==1 ? "iocp" : "legacy",count,
        seconds,4096.0/seconds,cpu,relayThreads,(unsigned long long)(attachedPrivate-initialPrivate),
        (unsigned long long)transferredPrivate);return 0;
}
