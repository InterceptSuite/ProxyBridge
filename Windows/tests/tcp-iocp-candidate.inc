// Experimental data-phase backend. Test harness owns sockets and waits per pair;
// production accept/connect/handshake/lifecycle integration is deliberately absent.
typedef struct ASYNC_PAIR ASYNC_PAIR;
typedef struct {
    OVERLAPPED ov;
    ASYNC_PAIR* pair;
    SOCKET from, to;
    BOOL sending, eof;
    DWORD length, offset;
    WSABUF buffer;
    char data[131072];
} ASYNC_DIRECTION;
struct ASYNC_PAIR {
    SRWLOCK lock;
    SOCKET client, proxy;
    HANDLE done;
    unsigned pending;
    BOOL closing, completionClaimed;
    ASYNC_DIRECTION directions[2];
    ASYNC_PAIR* next;
};
static HANDLE completionPort, completionWorkers[2];
static SRWLOCK pairRegistryLock = SRWLOCK_INIT;
static ASYNC_PAIR* pairs;
// Controls change only between fully joined test cases.
static LONG faultStage, submitNumber, sendChunk;
static volatile LONG livePairs, liveEvents, liveRequests, faultHits;
static HANDLE completionPaused, completionResume;
static volatile LONG pauseClaim;
static void async_dispose(ASYNC_PAIR* pair)
{
    if (pair->done) { CloseHandle(pair->done); InterlockedDecrement(&liveEvents); }
    free(pair); InterlockedDecrement(&livePairs);
}
static void async_cancel(ASYNC_PAIR* pair)
{
    if (pair->closing) return;
    pair->closing = TRUE;
    CancelIoEx((HANDLE)pair->client, NULL);
    CancelIoEx((HANDLE)pair->proxy, NULL);
    shutdown(pair->client, SD_BOTH); shutdown(pair->proxy, SD_BOTH);
}
static void async_submit(ASYNC_DIRECTION* direction)
{
    ASYNC_PAIR* pair = direction->pair;
    if (pair->closing || direction->eof) return;
    memset(&direction->ov, 0, sizeof(direction->ov));
    direction->buffer.buf = direction->data + (direction->sending ? direction->offset : 0);
    direction->buffer.len = direction->sending ? direction->length - direction->offset : sizeof(direction->data);
    if (direction->sending && sendChunk > 0 && direction->buffer.len > (DWORD)sendChunk)
        direction->buffer.len = (DWORD)sendChunk;
    pair->pending++; // reserve before a completion can become visible
    InterlockedIncrement(&liveRequests);
    DWORD flags = 0;
    LONG number = InterlockedIncrement(&submitNumber);
    int rc;
    if ((faultStage == 5 && number == 1) || (faultStage == 6 && number == 2) ||
        (faultStage == 7 && direction->sending)) {
        InterlockedIncrement(&faultHits);
        WSASetLastError(WSAENOBUFS); rc = SOCKET_ERROR;
    } else if (faultStage == 8 && direction->sending) {
        // Inject a zero-byte successful send completion; no real send is issued.
        InterlockedIncrement(&faultHits);
        if (!PostQueuedCompletionStatus(completionPort, 0, 0, &direction->ov)) ExitProcess(2);
        rc = 0;
    } else rc = direction->sending
        ? WSASend(direction->to, &direction->buffer, 1, NULL, 0, &direction->ov, NULL)
        : WSARecv(direction->from, &direction->buffer, 1, NULL, &flags, &direction->ov, NULL);
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        pair->pending--; InterlockedDecrement(&liveRequests); async_cancel(pair);
    }
    // Immediate success also posts an IOCP completion: never process it twice.
}
static BOOL async_finished(ASYNC_PAIR* pair)
{
    if (!pair->completionClaimed && pair->pending == 0 && (pair->closing ||
        (pair->directions[0].eof && pair->directions[1].eof))) {
        pair->completionClaimed = TRUE; // exactly one owner may signal the done handle
        return TRUE;
    }
    return FALSE;
}
static DWORD WINAPI async_worker(void* arg)
{
    (void)arg;
    for (;;) {
        DWORD bytes; ULONG_PTR key; OVERLAPPED* ov = NULL;
        BOOL ok = GetQueuedCompletionStatus(completionPort, &bytes, &key, &ov, INFINITE);
        if (!ov) return 0; // test shutdown sentinel, after all pairs have drained
        ASYNC_DIRECTION* direction = CONTAINING_RECORD(ov, ASYNC_DIRECTION, ov);
        ASYNC_PAIR* pair = direction->pair;
        // A dequeued completion still owns its request reference until processed.
        if (faultStage == 12 && InterlockedCompareExchange(&pauseClaim, 1, 0) == 0) {
            SetEvent(completionPaused);
            if (WaitForSingleObject(completionResume, 3000) != WAIT_OBJECT_0) ExitProcess(2);
        }
        AcquireSRWLockExclusive(&pair->lock);
        pair->pending--;
        InterlockedDecrement(&liveRequests);
        if (!pair->closing) {
            if (!ok || bytes > direction->buffer.len || (direction->sending && bytes == 0)) async_cancel(pair);
            else if (direction->sending) {
                direction->offset += bytes;
                if (direction->offset == direction->length) direction->sending = FALSE;
                async_submit(direction);
            } else if (!bytes) {
                direction->eof = TRUE;
                if (shutdown(direction->to, SD_SEND) == SOCKET_ERROR) async_cancel(pair);
            } else {
                direction->length = bytes; direction->offset = 0; direction->sending = TRUE;
                async_submit(direction);
            }
        }
        HANDLE finished = async_finished(pair) ? pair->done : NULL;
        ReleaseSRWLockExclusive(&pair->lock);
        if (finished) SetEvent(finished); // no pair access after signalling its owner
    }
}
static BOOL backend_begin(void)
{
    if (faultStage == 9) { InterlockedIncrement(&faultHits); return FALSE; }
    completionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 2);
    if (!completionPort) return FALSE;
    for (int i = 0; i < 2; i++) {
        if (faultStage == 10 + i) { InterlockedIncrement(&faultHits); completionWorkers[i] = NULL; }
        else completionWorkers[i] = CreateThread(NULL, 0, async_worker, NULL, 0, NULL);
        if (!completionWorkers[i]) {
            for (int j = 0; j < i; j++)
                if (!PostQueuedCompletionStatus(completionPort, 0, 0, NULL)) ExitProcess(2);
            if (i && WaitForMultipleObjects((DWORD)i, completionWorkers, TRUE, 3000) != WAIT_OBJECT_0) ExitProcess(2);
            for (int j = 0; j < i; j++) { CloseHandle(completionWorkers[j]); completionWorkers[j] = NULL; }
            CloseHandle(completionPort); completionPort = NULL;
            return FALSE;
        }
    }
    return TRUE;
}
static void backend_end(void)
{
    if (pairs) ExitProcess(2);
    for (int i = 0; i < 2; i++) PostQueuedCompletionStatus(completionPort, 0, 0, NULL);
    if (WaitForMultipleObjects(2, completionWorkers, TRUE, 3000) != WAIT_OBJECT_0) ExitProcess(2);
    for (int i = 0; i < 2; i++) { CloseHandle(completionWorkers[i]); completionWorkers[i] = NULL; }
    CloseHandle(completionPort); completionPort = NULL;
}
static void stop_transfer(SOCKET client, SOCKET proxy)
{
    AcquireSRWLockShared(&pairRegistryLock);
    for (ASYNC_PAIR* pair = pairs; pair; pair = pair->next) {
        if (pair->client == client && pair->proxy == proxy) {
            AcquireSRWLockExclusive(&pair->lock);
            async_cancel(pair);
            HANDLE finished = async_finished(pair) ? pair->done : NULL;
            ReleaseSRWLockExclusive(&pair->lock);
            if (finished) SetEvent(finished);
            break;
        }
    }
    // Registry lock prevents owner closing/recycling while cancellation runs.
    shutdown(client, SD_BOTH); shutdown(proxy, SD_BOTH);
    ReleaseSRWLockShared(&pairRegistryLock);
}
static ASYNC_PAIR* async_attach(SOCKET client, SOCKET proxy)
{
    ASYNC_PAIR* pair = faultStage == 1 ? NULL : calloc(1, sizeof(*pair));
    if (faultStage == 1) InterlockedIncrement(&faultHits);
    if (!pair) return NULL;
    InterlockedIncrement(&livePairs);
    pair->client = client; pair->proxy = proxy;
    pair->done = faultStage == 2 ? NULL : CreateEventW(NULL, TRUE, FALSE, NULL);
    if (pair->done) InterlockedIncrement(&liveEvents);
    if (faultStage >= 2 && faultStage <= 4) InterlockedIncrement(&faultHits);
    if (!pair->done || faultStage == 3 || !CreateIoCompletionPort((HANDLE)pair->client, completionPort, 0, 0) ||
        faultStage == 4 || !CreateIoCompletionPort((HANDLE)pair->proxy, completionPort, 0, 0)) {
        async_dispose(pair); return NULL;
    }
    for (int i = 0; i < 2; i++) {
        pair->directions[i].pair = pair;
        pair->directions[i].from = i ? pair->proxy : pair->client;
        pair->directions[i].to = i ? pair->client : pair->proxy;
    }
    AcquireSRWLockExclusive(&pairRegistryLock);
    pair->next = pairs; pairs = pair;
    AcquireSRWLockExclusive(&pair->lock);
    async_submit(&pair->directions[0]); async_submit(&pair->directions[1]);
    if (async_finished(pair)) SetEvent(pair->done);
    ReleaseSRWLockExclusive(&pair->lock);
    ReleaseSRWLockExclusive(&pairRegistryLock);
    return pair;
}
static DWORD async_join(ASYNC_PAIR* pair)
{
    WaitForSingleObject(pair->done, INFINITE);
    AcquireSRWLockExclusive(&pairRegistryLock);
    ASYNC_PAIR** link = &pairs;
    while (*link != pair) link = &(*link)->next;
    *link = pair->next;
    DWORD result = pair->closing ? 1 : 0;
    ReleaseSRWLockExclusive(&pairRegistryLock);
    async_dispose(pair);
    return result;
}

DWORD WINAPI transfer_handler(void* arg)
{
    TRANSFER_CONFIG* config = arg;
    ASYNC_PAIR* pair = async_attach(config->from_socket, config->to_socket);
    free(config);
    return pair ? async_join(pair) : 1;
}
