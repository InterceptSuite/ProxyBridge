#include "pb_internal.h"
volatile BOOL running = TRUE;
LogCallback g_log_callback;
#include "tcp-iocp-production-hooks.inc"
#include "tcp-test-sockets.inc"
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); ExitProcess(1); } } while (0)
static BOOL engine_clean(void)
{
    for(int i=0;i<PB_TCP_IO_WORKER_COUNT;i++) if(tcpIoWorkers[i]) return FALSE;
    return !tcpIoPairs && !tcpIoPort;
}
static DWORD WINAPI writer(void* arg)
{
    char data[65536]; memset(data, 'x', sizeof(data));
    for (int i = 0; i < 256; i++)
        if (send_all(*(SOCKET*)arg, data, sizeof(data)) == SOCKET_ERROR) break;
    return 0;
}
static DWORD WINAPI stop_engine(void* arg) { (void)arg; tcp_io_stop(); return 0; }
static DWORD WINAPI start_engine(void* arg) { (void)arg; return tcp_io_start() ? 1 : 0; }
static void test_stop_post_failure(void)
{
    CHECK(tcp_io_start());
    rejectedStopPosts=0; InterlockedExchange(&rejectStopPosts,1);
    HANDLE stopper=CreateThread(NULL,0,stop_engine,NULL,0,NULL); CHECK(stopper);
    CHECK(WaitForSingleObject(stopper,2500)==WAIT_OBJECT_0); CloseHandle(stopper);
    CHECK(rejectedStopPosts==tcpIoWorkerCount && engine_clean());
    CHECK(!liveAllocations && !liveHandles);
    // Partial pool startup must also survive a failed shutdown notification.
    rejectedStopPosts=0; faultNth=tcpIoWorkerCount; faultCalls=0; faultHits=0;
    InterlockedExchange(&faultKind,F_THREAD);
    HANDLE starter=CreateThread(NULL,0,start_engine,NULL,0,NULL); CHECK(starter);
    CHECK(WaitForSingleObject(starter,2500)==WAIT_OBJECT_0);
    DWORD result; CHECK(GetExitCodeThread(starter,&result) && result==0); CloseHandle(starter);
    CHECK(faultHits==1 && rejectedStopPosts==tcpIoWorkerCount-1 && engine_clean());
    CHECK(!liveAllocations && !liveHandles); InterlockedExchange(&faultKind,F_NONE);
    InterlockedExchange(&rejectStopPosts,0);
    CHECK(tcp_io_start()); tcp_io_stop();
    puts("PASS production shutdown notifications fail in normal Stop and partial startup: bounded join, cleanup and restart");
}
static void test_peer_reset(void)
{
    CHECK(tcp_io_start());
    for (int cycle = 0; cycle < 16; cycle++) {
        SOCKET client, input, server, output;
        CHECK(socket_pair(&client,&input) && socket_pair(&server,&output));
        CHECK(tcp_io_attach(input,output));
        // A completed round trip proves both startup packets were handled.
        CHECK(send_all(client,"request",7) == 7 && read_exact(server,"request",7));
        CHECK(send_all(server,"reply",5) == 5 && read_exact(client,"reply",5));
        LONG errorsBefore = InterlockedCompareExchange(&failedCompletions,0,0);
        LONG immediateBefore = InterlockedCompareExchange(&immediateIoErrors,0,0);
        SOCKET resetPeer = cycle & 1 ? server : client;
        SOCKET otherPeer = cycle & 1 ? client : server;
        struct linger reset = {1,0};
        CHECK(!setsockopt(resetPeer,SOL_SOCKET,SO_LINGER,(char*)&reset,sizeof(reset)));
        CHECK(!closesocket(resetPeer));
        // No admission closure or Stop here: the network error must drive cleanup.
        CHECK(WaitForSingleObject(tcpIoPairs->done,3000) == WAIT_OBJECT_0);
        CHECK(tcpIoPairs->closing && tcpIoPairs->claimed && !tcpIoPairs->pending);
        // Reset may precede the next receive submission and fail immediately,
        // or complete an already pending operation with an error.
        CHECK(InterlockedCompareExchange(&failedCompletions,0,0) > errorsBefore ||
            InterlockedCompareExchange(&immediateIoErrors,0,0) > immediateBefore);
        tcp_io_reap(FALSE); CHECK(!tcpIoPairs && !liveAllocations);
        char byte; int rc = recv(otherPeer,&byte,1,0);
        CHECK(rc == 0 || (rc == SOCKET_ERROR && WSAGetLastError() != WSAETIMEDOUT));
        closesocket(otherPeer);
        CHECK(tcpIoAccepting && liveHandles == tcpIoWorkerCount+1);
        // Same pool, immediately after failure: verify successful normal transfer.
        CHECK(socket_pair(&client,&input) && socket_pair(&server,&output));
        CHECK(tcp_io_attach(input,output));
        CHECK(send_all(client,"healthy",7) == 7 && !shutdown(client,SD_SEND));
        CHECK(read_exact(server,"healthy",7) && recv(server,&byte,1,0) == 0);
        CHECK(send_all(server,"ok",2) == 2 && !shutdown(server,SD_SEND));
        CHECK(read_exact(client,"ok",2) && recv(client,&byte,1,0) == 0);
        CHECK(WaitForSingleObject(tcpIoPairs->done,3000) == WAIT_OBJECT_0);
        tcp_io_reap(FALSE); CHECK(!tcpIoPairs && !liveAllocations);
        closesocket(client); closesocket(server);
    }
    tcp_io_stop(); CHECK(!liveAllocations && !liveHandles);
    puts("PASS production 16 peer resets in both directions without Stop; 16 healthy follow-up pairs on same pool");
}
static void test_dequeued_rundown(LONG mode)
{
    CHECK(tcp_io_start());
    completionPaused = CreateEventW(NULL,TRUE,FALSE,NULL);
    completionResume = CreateEventW(NULL,TRUE,FALSE,NULL);
    CHECK(completionPaused && completionResume);
    SOCKET client, input, server, output;
    CHECK(socket_pair(&client,&input) && socket_pair(&server,&output));
    pauseClaimed = 0; InterlockedExchange(&pauseCompletion, mode);
    CHECK(tcp_io_attach(input,output));
    if (mode == 2 || mode == 3) CHECK(send_all(client,"actual socket payload",21) == 21);
    if (mode == 4) {
        // Wait until startup references have become actual pending receives.
        ULONGLONG deadline = GetTickCount64() + 2000; BOOL receiving;
        do {
            AcquireSRWLockExclusive(&tcpIoPairs->lock);
            receiving = !tcpIoPairs->directions[0].starting && !tcpIoPairs->directions[1].starting;
            ReleaseSRWLockExclusive(&tcpIoPairs->lock);
            if (!receiving) SwitchToThread();
        } while (!receiving && GetTickCount64() < deadline);
        CHECK(receiving);
        struct linger reset = {1,0};
        CHECK(!setsockopt(client,SOL_SOCKET,SO_LINGER,(char*)&reset,sizeof(reset)));
        CHECK(!closesocket(client)); client = INVALID_SOCKET;
    }
    CHECK(WaitForSingleObject(completionPaused,2000) == WAIT_OBJECT_0);
    if (mode == 3) CHECK(read_exact(server,"actual socket payload",21));
    tcp_io_close_admission(); tcp_io_close_admission();
    AcquireSRWLockExclusive(&tcpIoPairs->lock);
    CHECK(tcpIoPairs->closing && tcpIoPairs->pending >= 1 && !tcpIoPairs->claimed);
    ReleaseSRWLockExclusive(&tcpIoPairs->lock);
    CHECK(WaitForSingleObject(tcpIoPairs->done,0) == WAIT_TIMEOUT);
    HANDLE stopper = CreateThread(NULL,0,stop_engine,NULL,0,NULL); CHECK(stopper);
    CHECK(WaitForSingleObject(stopper,100) == WAIT_TIMEOUT);
    CHECK(InterlockedCompareExchange(&liveAllocations,0,0) == 1);
    CHECK(SetEvent(completionResume));
    CHECK(WaitForSingleObject(stopper,3000) == WAIT_OBJECT_0);
    InterlockedExchange(&pauseCompletion,0);
    CHECK(!tcpIoPairs && !tcpIoPort && !liveAllocations && !liveHandles);
    CloseHandle(stopper); CloseHandle(completionPaused); CloseHandle(completionResume);
    if (client != INVALID_SOCKET) closesocket(client);
    closesocket(server);
    printf("PASS production dequeued %s completion: repeated cancellation retains pair; Stop waits for completion release\n",
        mode == 1 ? "startup" : mode == 2 ? "WSARecv data" : mode == 3 ? "WSASend data" : "socket reset error");
}
static void test_failures(void)
{
    const LONG cases[][2] = {{F_PORT,1},{F_THREAD,1},{F_THREAD,2},{F_THREAD,3},{F_THREAD,4},
        {F_ALLOC,1},{F_EVENT,1},{F_ASSOCIATE,1},{F_ASSOCIATE,2},
        {F_POST,1},{F_POST,2},{F_RECV,1},{F_RECV,2},{F_SEND,1}};
    unsigned tested=0;
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        LONG kind = cases[i][0];
        if(kind==F_THREAD && cases[i][1]>tcpIoWorkerCount) continue;
        tested++;
        BOOL startup = kind == F_PORT || kind == F_THREAD;
        CHECK(!liveAllocations && !liveHandles);
        if (!startup) CHECK(tcp_io_start());
        faultNth = cases[i][1]; faultCalls = 0; faultHits = 0;
        InterlockedExchange(&faultKind, kind);
        if (startup) CHECK(!tcp_io_start());
        else {
            SOCKET client, input, server, output; char byte;
            CHECK(socket_pair(&client, &input) && socket_pair(&server, &output));
            // Make a send completion path reachable without racing cancellation.
            if (kind == F_SEND) CHECK(send_all(client, "x", 1) == 1);
            BOOL attached = tcp_io_attach(input, output);
            if (kind == F_ALLOC || kind == F_EVENT || kind == F_ASSOCIATE) {
                CHECK(!attached && !tcpIoPairs && !liveAllocations);
                CHECK(send_all(client, "x", 1) == 1 && recv(input, &byte, 1, 0) == 1);
                CHECK(send_all(server, "y", 1) == 1 && recv(output, &byte, 1, 0) == 1);
                closesocket(input); closesocket(output);
            } else {
                CHECK(attached && tcpIoPairs);
                // No Stop-induced cancellation can hide a missing failure path.
                CHECK(WaitForSingleObject(tcpIoPairs->done, 3000) == WAIT_OBJECT_0);
                tcp_io_reap(FALSE); CHECK(!tcpIoPairs && !liveAllocations);
                int type, size = sizeof(type);
                CHECK(getsockopt(input, SOL_SOCKET, SO_TYPE, (char*)&type, &size) == SOCKET_ERROR);
                CHECK(WSAGetLastError() == WSAENOTSOCK);
                CHECK(getsockopt(output, SOL_SOCKET, SO_TYPE, (char*)&type, &size) == SOCKET_ERROR);
                CHECK(WSAGetLastError() == WSAENOTSOCK);
            }
            closesocket(client); closesocket(server);
        }
        CHECK(faultHits == 1); InterlockedExchange(&faultKind, F_NONE);
        HANDLE stopper = CreateThread(NULL,0,stop_engine,NULL,0,NULL); CHECK(stopper);
        CHECK(WaitForSingleObject(stopper,3000) == WAIT_OBJECT_0); CloseHandle(stopper);
        CHECK(engine_clean());
        CHECK(!liveAllocations && !liveHandles);
        CHECK(tcp_io_start()); tcp_io_stop();
        CHECK(!liveAllocations && !liveHandles);
    }
    printf("PASS production %u injected failures with %d workers: allocation/event/port/threads/association/startup packets/recv/send; cleanup and restart\n",tested,tcpIoWorkerCount);
}
typedef struct { SOCKET input, output; BOOL attached; } HANDOFF;
static DWORD WINAPI handoff_and_exit(void* arg)
{
    HANDOFF* handoff = arg;
    handoff->attached = tcp_io_attach(handoff->input, handoff->output);
    return 0;
}
typedef struct { HANDOFF handoff; HANDLE gate; } RACING_HANDOFF;
static DWORD WINAPI racing_handoff(void* arg)
{
    RACING_HANDOFF* item = arg;
    CHECK(WaitForSingleObject(item->gate, 2000) == WAIT_OBJECT_0);
    return handoff_and_exit(&item->handoff);
}
static void test_admission_race(void)
{
    unsigned accepted = 0, rejected = 0;
    for (int cycle = 0; cycle < 10; cycle++) {
        CHECK(tcp_io_start());
        HANDLE gate = CreateEventW(NULL, TRUE, FALSE, NULL); CHECK(gate);
        RACING_HANDOFF items[32]; HANDLE producers[32];
        SOCKET clients[32], servers[32];
        for (int i = 0; i < 32; i++) {
            CHECK(socket_pair(&clients[i], &items[i].handoff.input));
            CHECK(socket_pair(&servers[i], &items[i].handoff.output));
            items[i].handoff.attached = FALSE; items[i].gate = gate;
            producers[i] = CreateThread(NULL, 0, racing_handoff, &items[i], 0, NULL);
            CHECK(producers[i]);
        }
        CHECK(SetEvent(gate));
        tcp_io_close_admission(); // producers may be before, inside or after attach
        CHECK(WaitForMultipleObjects(32, producers, TRUE, 3000) == WAIT_OBJECT_0);
        for (int i = 0; i < 32; i++) {
            CloseHandle(producers[i]);
            if (items[i].handoff.attached) accepted++;
            else {
                char byte; rejected++;
                CHECK(send_all(clients[i], "x", 1) == 1);
                CHECK(recv(items[i].handoff.input, &byte, 1, 0) == 1 && byte == 'x');
                CHECK(send_all(servers[i], "y", 1) == 1);
                CHECK(recv(items[i].handoff.output, &byte, 1, 0) == 1 && byte == 'y');
                closesocket(items[i].handoff.input); closesocket(items[i].handoff.output);
            }
        }
        // Core joins producers before final engine drain; do not test unsupported
        // concurrent Start/Stop ownership of global engine handles.
        HANDLE stopper = CreateThread(NULL, 0, stop_engine, NULL, 0, NULL); CHECK(stopper);
        CHECK(WaitForSingleObject(stopper, 3000) == WAIT_OBJECT_0);
        CloseHandle(stopper); CloseHandle(gate);
        CHECK(engine_clean());
        for (int i = 0; i < 32; i++) { closesocket(clients[i]); closesocket(servers[i]); }
    }
    printf("PASS production admission race: 320 handoffs, accepted=%u rejected=%u, caller ownership and drain\n", accepted, rejected);
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    WSADATA wsa; CHECK(!WSAStartup(MAKEWORD(2,2), &wsa));
    for (int cycle = 0; cycle < 3; cycle++) {
        CHECK(tcp_io_start());
        SOCKET clients[32], servers[32];
        for (int i = 0; i < 32; i++) {
            SOCKET input, output;
            CHECK(socket_pair(&clients[i], &input) && socket_pair(&servers[i], &output));
            HANDOFF handoff = {input, output, FALSE};
            HANDLE producer = CreateThread(NULL,0,handoff_and_exit,&handoff,0,NULL); CHECK(producer);
            CHECK(WaitForSingleObject(producer,2000) == WAIT_OBJECT_0); CloseHandle(producer);
            CHECK(handoff.attached); // initiating handshake thread is already gone
        }
        for (int i = 0; i < 32; i++) {
            SOCKET first = i & 1 ? servers[i] : clients[i];
            CHECK(send_all(first, "request", 7) == 7 && shutdown(first, SD_SEND) == 0);
        }
        for (int i = 0; i < 32; i++) {
            char end;
            SOCKET first = i & 1 ? servers[i] : clients[i];
            SOCKET second = i & 1 ? clients[i] : servers[i];
            CHECK(read_exact(second, "request", 7) && recv(second, &end, 1, 0) == 0);
            CHECK(send_all(second, "reply", 5) == 5 && shutdown(second, SD_SEND) == 0);
            CHECK(read_exact(first, "reply", 5) && recv(first, &end, 1, 0) == 0);
            closesocket(clients[i]); closesocket(servers[i]);
        }
        // Reap normal EOF without initiating cancellation.
        ULONGLONG deadline = GetTickCount64() + 2000;
        do { tcp_io_reap(FALSE); if (!tcpIoPairs) break; SwitchToThread(); } while (GetTickCount64() < deadline);
        CHECK(!tcpIoPairs);
        tcp_io_stop(); CHECK(engine_clean());
    }
    puts("PASS production IOCP:3 start/stop cycles,96 attached pairs, both FIN directions, normal reap");
    CHECK(tcp_io_start());
    SOCKET sender, input, receiver, output;
    CHECK(socket_pair(&sender, &input) && socket_pair(&receiver, &output));
    int bufferSize = 4096;
    CHECK(!setsockopt(output, SOL_SOCKET, SO_SNDBUF, (char*)&bufferSize, sizeof(bufferSize)));
    CHECK(!setsockopt(receiver, SOL_SOCKET, SO_RCVBUF, (char*)&bufferSize, sizeof(bufferSize)));
    CHECK(tcp_io_attach(input, output));
    HANDLE sendThread = CreateThread(NULL,0,writer,&sender,0,NULL); CHECK(sendThread);
    char byte; CHECK(recv(receiver,&byte,1,MSG_PEEK) == 1 && byte == 'x');
    CHECK(WaitForSingleObject(sendThread,200) == WAIT_TIMEOUT);
    ULONGLONG stopAt = GetTickCount64();
    HANDLE stopThread = CreateThread(NULL,0,stop_engine,NULL,0,NULL); CHECK(stopThread);
    CHECK(WaitForSingleObject(stopThread,1000) == WAIT_OBJECT_0);
    printf("PASS production stalled16MiB stop: %llums\n",GetTickCount64()-stopAt);
    CHECK(engine_clean());
    shutdown(sender,SD_BOTH); shutdown(receiver,SD_BOTH);
    CHECK(WaitForSingleObject(sendThread,3000) == WAIT_OBJECT_0);
    CloseHandle(sendThread); CloseHandle(stopThread); closesocket(sender); closesocket(receiver);
    CHECK(socket_pair(&sender,&input) && socket_pair(&receiver,&output));
    CHECK(!tcp_io_attach(input,output)); // rejected sockets remain caller owned
    CHECK(send_all(sender,"x",1) == 1 && recv(input,&byte,1,0) == 1);
    closesocket(sender); closesocket(input); closesocket(receiver); closesocket(output);
    tcp_io_stop(); // idempotent cleanup after stopped/rejected attach
    test_admission_race();
    test_failures();
    for (LONG mode = 1; mode <= 4; mode++) test_dequeued_rundown(mode);
    test_peer_reset();
    test_stop_post_failure();
    WSACleanup();
    puts("PASS production closed admission: caller retains usable sockets; repeated stop");
    return 0;
}
