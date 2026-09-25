// Test-only API substitutions around the actual production module.
// No hooks, counters or fault branches are compiled into Core.
enum { F_NONE, F_ALLOC, F_EVENT, F_PORT, F_THREAD, F_ASSOCIATE, F_POST, F_RECV, F_SEND };
static LONG faultKind, faultNth, faultCalls, faultHits, liveAllocations, liveHandles;
static LONG pauseCompletion, pauseClaimed;
static LONG failedCompletions;
static LONG immediateIoErrors;
static LONG rejectStopPosts, rejectedStopPosts;
static BOOL WINAPI test_affinity(HANDLE process, PDWORD_PTR mask, PDWORD_PTR systemMask)
{
#ifdef PB_TEST_PROCESSORS
    (void)process; *mask=*systemMask=((DWORD_PTR)1<<PB_TEST_PROCESSORS)-1; return TRUE;
#else
    return GetProcessAffinityMask(process,mask,systemMask);
#endif
}
static HANDLE completionPaused, completionResume;
static BOOL pause_matches(LPOVERLAPPED ov, BOOL ok, DWORD bytes);
static BOOL WINAPI test_dequeue(HANDLE port, LPDWORD bytes, PULONG_PTR key,
    LPOVERLAPPED* ov, DWORD timeout)
{
    BOOL ok = GetQueuedCompletionStatus(port, bytes, key, ov, timeout);
    if (*ov && !ok) InterlockedIncrement(&failedCompletions);
    if (*ov && pause_matches(*ov, ok, *bytes) &&
        !InterlockedCompareExchange(&pauseClaimed, 1, 0)) {
        SetEvent(completionPaused);
        if (WaitForSingleObject(completionResume, 5000) != WAIT_OBJECT_0) ExitProcess(2);
    }
    return ok;
}
static BOOL inject(LONG kind)
{
    if (InterlockedCompareExchange(&faultKind, 0, 0) != kind) return FALSE;
    if (InterlockedIncrement(&faultCalls) != faultNth) return FALSE;
    InterlockedIncrement(&faultHits); SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    WSASetLastError(WSAENOBUFS); return TRUE;
}
static void* test_calloc(size_t count, size_t size)
{
    if (inject(F_ALLOC)) return NULL;
    void* p = calloc(count, size); if (p) InterlockedIncrement(&liveAllocations); return p;
}
static void test_free(void* p)
{
    if (p) InterlockedDecrement(&liveAllocations); free(p);
}
static HANDLE WINAPI test_event(LPSECURITY_ATTRIBUTES a, BOOL manual, BOOL initial, LPCWSTR name)
{
    if (inject(F_EVENT)) return NULL;
    HANDLE h = CreateEventW(a, manual, initial, name); if (h) InterlockedIncrement(&liveHandles); return h;
}
static HANDLE WINAPI test_port(HANDLE file, HANDLE port, ULONG_PTR key, DWORD threads)
{
    if (inject(port ? F_ASSOCIATE : F_PORT)) return NULL;
    HANDLE h = CreateIoCompletionPort(file, port, key, threads);
    if (h && !port) InterlockedIncrement(&liveHandles); return h;
}
static HANDLE WINAPI test_thread(LPSECURITY_ATTRIBUTES a, SIZE_T size, LPTHREAD_START_ROUTINE entry,
    LPVOID arg, DWORD flags, LPDWORD id)
{
    if (inject(F_THREAD)) return NULL;
    HANDLE h = CreateThread(a, size, entry, arg, flags, id);
    if (h) InterlockedIncrement(&liveHandles); return h;
}
static BOOL WINAPI test_close(HANDLE h)
{
    BOOL ok = CloseHandle(h); if (ok) InterlockedDecrement(&liveHandles); return ok;
}
static BOOL WINAPI test_post(HANDLE port, DWORD bytes, ULONG_PTR key, LPOVERLAPPED ov)
{
    if (!ov && InterlockedCompareExchange(&rejectStopPosts,0,0)) {
        InterlockedIncrement(&rejectedStopPosts); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE;
    }
    if (ov && inject(F_POST)) return FALSE;
    return PostQueuedCompletionStatus(port, bytes, key, ov);
}
static int WSAAPI test_recv(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD bytes,
    LPDWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE callback)
{
    if (inject(F_RECV)) return SOCKET_ERROR;
    int rc = WSARecv(s, buffers, count, bytes, flags, ov, callback);
    int error = WSAGetLastError();
    if (rc == SOCKET_ERROR && error != WSA_IO_PENDING) InterlockedIncrement(&immediateIoErrors);
    WSASetLastError(error); return rc;
}
static int WSAAPI test_send(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD bytes,
    DWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE callback)
{
    if (inject(F_SEND)) return SOCKET_ERROR;
    int rc = WSASend(s, buffers, count, bytes, flags, ov, callback);
    int error = WSAGetLastError();
    if (rc == SOCKET_ERROR && error != WSA_IO_PENDING) InterlockedIncrement(&immediateIoErrors);
    WSASetLastError(error); return rc;
}
#define calloc test_calloc
#define free test_free
#define CreateEventW test_event
#define CreateIoCompletionPort test_port
#define CreateThread test_thread
#define CloseHandle test_close
#define PostQueuedCompletionStatus test_post
#define WSARecv test_recv
#define WSASend test_send
#define GetQueuedCompletionStatus test_dequeue
#define GetProcessAffinityMask test_affinity
#include "../src/relay/pb_tcp_iocp.inc"
#undef calloc
#undef free
#undef CreateEventW
#undef CreateIoCompletionPort
#undef CreateThread
#undef CloseHandle
#undef PostQueuedCompletionStatus
#undef WSARecv
#undef WSASend
#undef GetQueuedCompletionStatus
#undef GetProcessAffinityMask
static BOOL pause_matches(LPOVERLAPPED ov, BOOL ok, DWORD bytes)
{
    LONG mode = InterlockedCompareExchange(&pauseCompletion, 0, 0);
    if (!mode) return FALSE;
    PB_IO_DIRECTION* direction = CONTAINING_RECORD(ov, PB_IO_DIRECTION, operation.ov);
    AcquireSRWLockExclusive(&direction->pair->lock);
    BOOL matches = mode == 1 ? direction->starting :
        mode == 4 ? !direction->starting && !ok :
        !direction->starting && ok && bytes > 0 && (mode == 3 ? direction->sending : !direction->sending);
    ReleaseSRWLockExclusive(&direction->pair->lock);
    return matches;
}
