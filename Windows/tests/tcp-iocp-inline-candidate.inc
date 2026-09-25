// TEST-ONLY inline completion candidate; not fault-qualified.
// Post-handshake data engine. Attach transfers both sockets on success only.
// Registry owns pairs until completion; listener reaps, Stop drains after producers join.
typedef struct PB_IO_PAIR PB_IO_PAIR;
typedef struct {
    OVERLAPPED ov;
    PB_IO_PAIR* pair;
    SOCKET from, to;
    WSABUF buffer;
    DWORD length, offset;
    BOOL sending, eof, starting, skipReceive, skipSend;
    char data[131072];
} PB_IO_DIRECTION;
struct PB_IO_PAIR {
    SRWLOCK lock;
    HANDLE done;
    SOCKET client, proxy;
    unsigned pending;
    BOOL closing, claimed;
    PB_IO_DIRECTION directions[2];
    PB_IO_PAIR* next;
};
#ifndef PB_TCP_IO_WORKER_COUNT
#define PB_TCP_IO_WORKER_COUNT 2
#endif
static HANDLE tcpIoPort, tcpIoWorkers[PB_TCP_IO_WORKER_COUNT];
static SRWLOCK tcpIoRegistryLock = SRWLOCK_INIT;
static PB_IO_PAIR* tcpIoPairs;
static BOOL tcpIoAccepting;
static volatile LONG tcpIoStopping;
static void tcp_io_cancel(PB_IO_PAIR* pair)
{
    if (pair->closing) return;
    pair->closing = TRUE;
    CancelIoEx((HANDLE)pair->client, NULL); CancelIoEx((HANDLE)pair->proxy, NULL);
    shutdown(pair->client, SD_BOTH); shutdown(pair->proxy, SD_BOTH);
}
static unsigned tcpIoSkipEnabled;
static BOOL tcp_io_enable_skip(SOCKET s)
{
    WSAPROTOCOL_INFOW info; int size=sizeof(info);
    BOOL enabled=getsockopt(s,SOL_SOCKET,SO_PROTOCOL_INFOW,(char*)&info,&size)==0 &&
        (info.dwServiceFlags1 & XP1_IFS_HANDLES) &&
        SetFileCompletionNotificationModes((HANDLE)s,FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
    if(enabled) tcpIoSkipEnabled++;
    return enabled;
}
static BOOL tcp_io_advance(PB_IO_DIRECTION* d, BOOL ok, DWORD bytes)
{
    PB_IO_PAIR* p=d->pair;
    if(!ok || bytes>d->buffer.len || (d->sending && !bytes)) {tcp_io_cancel(p);return FALSE;}
    if(d->sending) {d->offset+=bytes;if(d->offset==d->length)d->sending=FALSE;return TRUE;}
    if(!bytes) {d->eof=TRUE;if(shutdown(d->to,SD_SEND)==SOCKET_ERROR)tcp_io_cancel(p);return FALSE;}
    d->length=bytes;d->offset=0;d->sending=TRUE;return TRUE;
}
static void tcp_io_submit(PB_IO_DIRECTION* d)
{
    PB_IO_PAIR* p=d->pair;
    for(int budget=0;budget<16;budget++) {
        if(p->closing || d->eof)return;
        memset(&d->ov,0,sizeof(d->ov));
        d->buffer.buf=d->data+(d->sending ? d->offset : 0);
        d->buffer.len=d->sending ? d->length-d->offset : sizeof(d->data);
        p->pending++;DWORD flags=0;
        int rc=d->sending ? WSASend(d->to,&d->buffer,1,NULL,0,&d->ov,NULL) :
            WSARecv(d->from,&d->buffer,1,NULL,&flags,&d->ov,NULL);
        if(rc==SOCKET_ERROR) {
            if(WSAGetLastError()==WSA_IO_PENDING)return;
            p->pending--;tcp_io_cancel(p);return;
        }
        if(!(d->sending ? d->skipSend : d->skipReceive))return;
        p->pending--;DWORD bytes=0;
        BOOL ok=WSAGetOverlappedResult(d->sending ? d->to : d->from,&d->ov,&bytes,FALSE,&flags);
        if(!tcp_io_advance(d,ok,bytes))return;
    }
    // Yield a bounded synchronous chain; packet owns lifetime like initial startup.
    d->starting=TRUE;p->pending++;
    if(!PostQueuedCompletionStatus(tcpIoPort,0,0,&d->ov)) {p->pending--;tcp_io_cancel(p);}
}
static HANDLE tcp_io_claim_done(PB_IO_PAIR* pair)
{
    if (!pair->claimed && !pair->pending && (pair->closing ||
        (pair->directions[0].eof && pair->directions[1].eof))) {
        pair->claimed = TRUE;
        return pair->done;
    }
    return NULL;
}
static DWORD WINAPI tcp_io_worker(void* arg)
{
    (void)arg;
    for (;;) {
        DWORD bytes; ULONG_PTR key; OVERLAPPED* ov = NULL;
        BOOL ok = GetQueuedCompletionStatus(tcpIoPort, &bytes, &key, &ov, 1000);
        if (!ov) {
            // Normal shutdown wakes immediately through a sentinel. A bounded
            // idle wait also permits exit if posting that sentinel fails.
            if (!ok && GetLastError() == WAIT_TIMEOUT &&
                !InterlockedCompareExchange(&tcpIoStopping, 0, 0)) continue;
            return 0; // port remains valid until every worker is joined
        }
        PB_IO_DIRECTION* direction = CONTAINING_RECORD(ov, PB_IO_DIRECTION, ov);
        PB_IO_PAIR* pair = direction->pair;
        AcquireSRWLockExclusive(&pair->lock);
        pair->pending--;
        if (!pair->closing) {
            if (direction->starting) {
                direction->starting = FALSE;
                tcp_io_submit(direction); // requests originate on a persistent IO worker
            }
            else if(tcp_io_advance(direction,ok,bytes)) tcp_io_submit(direction);
        }
        HANDLE done = tcp_io_claim_done(pair);
        ReleaseSRWLockExclusive(&pair->lock);
        if (done) SetEvent(done); // no pair access after waking its registry owner
    }
}
static BOOL tcp_io_start(void)
{
    InterlockedExchange(&tcpIoStopping, 0); tcpIoSkipEnabled=0;
    tcpIoPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, PB_TCP_IO_WORKER_COUNT);
    if (!tcpIoPort) return FALSE;
    for (int i = 0; i < PB_TCP_IO_WORKER_COUNT; i++) {
        tcpIoWorkers[i] = CreateThread(NULL, 0, tcp_io_worker, NULL, 0, NULL);
        if (!tcpIoWorkers[i]) {
            DWORD error = GetLastError();
            InterlockedExchange(&tcpIoStopping, 1);
            for (int j = 0; j < i; j++) PostQueuedCompletionStatus(tcpIoPort, 0, 0, NULL);
            for (int j = 0; j < i; j++) {
                WaitForSingleObject(tcpIoWorkers[j], INFINITE);
                CloseHandle(tcpIoWorkers[j]); tcpIoWorkers[j] = NULL;
            }
            CloseHandle(tcpIoPort); tcpIoPort = NULL;
            SetLastError(error); return FALSE;
        }
    }
    AcquireSRWLockExclusive(&tcpIoRegistryLock);
    tcpIoAccepting = TRUE;
    ReleaseSRWLockExclusive(&tcpIoRegistryLock);
    return TRUE;
}
static BOOL tcp_io_attach(SOCKET client, SOCKET proxy)
{
    PB_IO_PAIR* pair = calloc(1, sizeof(*pair));
    if (!pair) return FALSE;
    pair->done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!pair->done) { free(pair); return FALSE; }
    pair->client = client; pair->proxy = proxy;
    AcquireSRWLockExclusive(&tcpIoRegistryLock);
    if (!tcpIoAccepting || !running ||
        !CreateIoCompletionPort((HANDLE)client, tcpIoPort, 0, 0) ||
        !CreateIoCompletionPort((HANDLE)proxy, tcpIoPort, 0, 0)) {
        ReleaseSRWLockExclusive(&tcpIoRegistryLock);
        CloseHandle(pair->done); free(pair); return FALSE;
    }
    BOOL skipClient=tcp_io_enable_skip(client), skipProxy=tcp_io_enable_skip(proxy);
    for (int i = 0; i < 2; i++) {
        pair->directions[i].pair = pair;
        pair->directions[i].from = i ? proxy : client;
        pair->directions[i].to = i ? client : proxy;
        pair->directions[i].skipReceive=i ? skipProxy : skipClient;
        pair->directions[i].skipSend=i ? skipClient : skipProxy;
    }
    pair->next = tcpIoPairs; tcpIoPairs = pair;
    AcquireSRWLockExclusive(&pair->lock);
    // A handshake thread may exit immediately after handoff. Never issue its I/O
    // here: Windows can cancel requests when their initiating thread exits.
    for (int i = 0; i < 2 && !pair->closing; i++) {
        pair->directions[i].starting = TRUE;
        pair->pending++; // queued startup packet also owns a reference
        if (!PostQueuedCompletionStatus(tcpIoPort, 0, 0, &pair->directions[i].ov)) {
            pair->pending--; tcp_io_cancel(pair);
        }
    }
    HANDLE done = tcp_io_claim_done(pair);
    ReleaseSRWLockExclusive(&pair->lock);
    if (done) SetEvent(done);
    ReleaseSRWLockExclusive(&tcpIoRegistryLock);
    return TRUE;
}
static void tcp_io_reap(BOOL wait)
{
    AcquireSRWLockExclusive(&tcpIoRegistryLock);
    PB_IO_PAIR** link = &tcpIoPairs;
    while (*link) {
        PB_IO_PAIR* pair = *link;
        if (WaitForSingleObject(pair->done, wait ? INFINITE : 0) == WAIT_OBJECT_0) {
            *link = pair->next;
            closesocket(pair->client); closesocket(pair->proxy);
            CloseHandle(pair->done); free(pair);
        } else link = &pair->next;
    }
    ReleaseSRWLockExclusive(&tcpIoRegistryLock);
}
static void tcp_io_close_admission(void)
{
    AcquireSRWLockExclusive(&tcpIoRegistryLock);
    tcpIoAccepting = FALSE;
    for (PB_IO_PAIR* pair = tcpIoPairs; pair; pair = pair->next) {
        AcquireSRWLockExclusive(&pair->lock);
        tcp_io_cancel(pair);
        HANDLE done = tcp_io_claim_done(pair);
        ReleaseSRWLockExclusive(&pair->lock);
        if (done) SetEvent(done);
    }
    ReleaseSRWLockExclusive(&tcpIoRegistryLock);
}
static void tcp_io_stop(void)
{
    tcp_io_close_admission(); tcp_io_reap(TRUE);
    if (!tcpIoPort) return;
    InterlockedExchange(&tcpIoStopping, 1); // all operation references drained
    for (int i = 0; i < PB_TCP_IO_WORKER_COUNT; i++) PostQueuedCompletionStatus(tcpIoPort, 0, 0, NULL);
    for (int i = 0; i < PB_TCP_IO_WORKER_COUNT; i++) {
        WaitForSingleObject(tcpIoWorkers[i], INFINITE);
        CloseHandle(tcpIoWorkers[i]); tcpIoWorkers[i] = NULL;
    }
    CloseHandle(tcpIoPort); tcpIoPort = NULL;
}
