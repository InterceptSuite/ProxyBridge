// Control and data operations share one IOCP: a connected socket cannot move
// between ports. One pending operation per setup; no per-connection thread.
#include <mswsock.h>
#ifndef PB_TCP_SETUP_LIMIT
#define PB_TCP_SETUP_LIMIT 1024
#endif
#ifndef PB_TCP_SETUP_TIMEOUT_MS
#define PB_TCP_SETUP_TIMEOUT_MS 30000
#endif
typedef enum {
    TCP_SETUP_START, TCP_SETUP_CONNECT, TCP_SETUP_GREETING_SEND,
    TCP_SETUP_GREETING_READ, TCP_SETUP_AUTH_SEND, TCP_SETUP_AUTH_READ,
    TCP_SETUP_REQUEST_SEND, TCP_SETUP_REPLY_HEADER, TCP_SETUP_REPLY_LENGTH,
    TCP_SETUP_REPLY_DRAIN, TCP_SETUP_HTTP_SEND, TCP_SETUP_HTTP_READ
} PB_TCP_SETUP_STATE;
typedef struct PB_TCP_SETUP {
    PB_IO_OPERATION operation;
    SRWLOCK lock;
    CONNECTION_CONFIG* config;
    SOCKET client, proxy;
    HANDLE done;
    BOOL pending, closing, claimed, sending;
    PB_TCP_SETUP_STATE state;
    ULONGLONG deadline;
    DWORD length, used;
    WSABUF buffer;
    char data[4096];
    struct PB_TCP_SETUP* next;
} PB_TCP_SETUP;
static SRWLOCK tcpSetupLock = SRWLOCK_INIT;
static PB_TCP_SETUP* tcpSetups;
static unsigned tcpSetupCount;

// Called with the context lock, including when expiry/Stop races completion.
// Closing cancels the operation but its OVERLAPPED remains alive until dequeued.
static void tcp_setup_cancel(PB_TCP_SETUP* setup)
{
    if (setup->closing) return;
    setup->closing = TRUE;
    if (setup->proxy != INVALID_SOCKET) {
        CancelIoEx((HANDLE)setup->proxy, NULL);
        closesocket(setup->proxy); setup->proxy = INVALID_SOCKET;
    }
    if (setup->client != INVALID_SOCKET) {
        closesocket(setup->client); setup->client = INVALID_SOCKET;
    }
}
static HANDLE tcp_setup_claim_done(PB_TCP_SETUP* setup)
{
    if (setup->closing && !setup->pending && !setup->claimed) {
        setup->claimed = TRUE;
        return setup->done;
    }
    return NULL;
}
static void tcp_setup_submit(PB_TCP_SETUP* setup)
{
    if (!running || GetTickCount64() >= setup->deadline) { tcp_setup_cancel(setup); return; }
    ZeroMemory(&setup->operation.ov, sizeof(setup->operation.ov));
    setup->buffer.buf = setup->data + setup->used;
    setup->buffer.len = setup->length - setup->used;
    DWORD flags = 0;
    setup->pending = TRUE;
    int rc = setup->sending
        ? WSASend(setup->proxy, &setup->buffer, 1, NULL, 0, &setup->operation.ov, NULL)
        : WSARecv(setup->proxy, &setup->buffer, 1, NULL, &flags, &setup->operation.ov, NULL);
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        setup->pending = FALSE; tcp_setup_cancel(setup);
    }
}
static void tcp_setup_transfer(PB_TCP_SETUP* setup, PB_TCP_SETUP_STATE state, BOOL sending, DWORD length)
{
    setup->state = state; setup->sending = sending; setup->length = length; setup->used = 0;
    tcp_setup_submit(setup);
}
static void tcp_setup_handoff(PB_TCP_SETUP* setup, const char* initial, DWORD length)
{
    struct tcp_keepalive keepalive = {1, 300000, 1000}; DWORD bytes = 0;
    WSAIoctl(setup->proxy, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), NULL, 0, &bytes, NULL, NULL);
    WSAIoctl(setup->client, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), NULL, 0, &bytes, NULL, NULL);
    if (running && tcp_io_attach_initial(setup->client, setup->proxy, initial, length, TRUE)) {
        setup->client = setup->proxy = INVALID_SOCKET;
        setup->closing = TRUE; // Data registry now owns both sockets.
    } else tcp_setup_cancel(setup);
}

#include "pb_tcp_setup_protocol.inc"

static void tcp_setup_begin(PB_TCP_SETUP* setup)
{
    const PROXY_CONFIG* proxy = &setup->config->proxy_snapshot;
    if (!proxy->host[0] || !proxy->port) {
        log_message("[RELAY] No proxy config (id=%u) - dropping connection", setup->config->proxy_config_id);
        tcp_setup_cancel(setup); return;
    }
    if (!proxy->resolved_ip || (proxy->type != PROXY_TYPE_SOCKS5 && proxy->type != PROXY_TYPE_HTTP)) {
        tcp_setup_cancel(setup); return;
    }
    setup->proxy = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (setup->proxy == INVALID_SOCKET) { tcp_setup_cancel(setup); return; }
    LPFN_CONNECTEX connectEx = NULL; GUID id = WSAID_CONNECTEX; DWORD bytes = 0;
    struct sockaddr_in local = {0}, remote = {0}; local.sin_family = remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = proxy->resolved_ip; remote.sin_port = htons(proxy->port);
    configure_tcp_socket(setup->proxy, 4194304, 0);
    configure_tcp_socket(setup->client, 4194304, 0);
    if (WSAIoctl(setup->proxy, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id),
            &connectEx, sizeof(connectEx), &bytes, NULL, NULL) == SOCKET_ERROR ||
        bind(setup->proxy, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR ||
        !CreateIoCompletionPort((HANDLE)setup->proxy, tcpIoPort, 0, 0)) {
        tcp_setup_cancel(setup); return;
    }
    setup->state = TCP_SETUP_CONNECT;
    ZeroMemory(&setup->operation.ov, sizeof(setup->operation.ov));
    setup->pending = TRUE;
    if (!connectEx(setup->proxy, (struct sockaddr*)&remote, sizeof(remote), NULL, 0, NULL, &setup->operation.ov) &&
        WSAGetLastError() != WSA_IO_PENDING) {
        setup->pending = FALSE; tcp_setup_cancel(setup);
    }
}
static void tcp_setup_complete(OVERLAPPED* ov, BOOL ok, DWORD bytes)
{
    PB_TCP_SETUP* setup = CONTAINING_RECORD(ov, PB_TCP_SETUP, operation.ov);
    AcquireSRWLockExclusive(&setup->lock);
    setup->pending = FALSE;
    if (!setup->closing) {
        if (!ok || !running || GetTickCount64() >= setup->deadline) tcp_setup_cancel(setup);
        else if (setup->state == TCP_SETUP_START) tcp_setup_begin(setup);
        else if (setup->state == TCP_SETUP_CONNECT) {
            if (setsockopt(setup->proxy, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR)
                tcp_setup_cancel(setup);
            else {
                // Preserve the existing separate connect and handshake budgets.
                setup->deadline = GetTickCount64() + PB_TCP_SETUP_TIMEOUT_MS;
                tcp_setup_protocol_begin(setup);
            }
        } else if (!bytes || bytes > setup->buffer.len) tcp_setup_cancel(setup);
        else {
            DWORD previous = setup->used;
            setup->used += bytes;
            if (setup->state == TCP_SETUP_HTTP_READ) tcp_setup_http_reply(setup, previous);
            else if (setup->used < setup->length) tcp_setup_submit(setup);
            else tcp_setup_protocol_next(setup);
        }
    }
    HANDLE done = tcp_setup_claim_done(setup);
    ReleaseSRWLockExclusive(&setup->lock);
    if (done) SetEvent(done); // No context access after waking its registry owner.
}
static void tcp_setup_reap(BOOL cancel)
{
    AcquireSRWLockExclusive(&tcpSetupLock);
    PB_TCP_SETUP** link = &tcpSetups;
    while (*link) {
        PB_TCP_SETUP* setup = *link;
        AcquireSRWLockExclusive(&setup->lock);
        if (cancel || GetTickCount64() >= setup->deadline) tcp_setup_cancel(setup);
        HANDLE done = tcp_setup_claim_done(setup);
        ReleaseSRWLockExclusive(&setup->lock);
        if (done) SetEvent(done);
        if (WaitForSingleObject(setup->done, 0) == WAIT_OBJECT_0) {
            *link = setup->next; --tcpSetupCount;
            CloseHandle(setup->done);
            SecureZeroMemory(setup->config, sizeof(*setup->config)); free(setup->config);
            SecureZeroMemory(setup, sizeof(*setup)); free(setup);
        } else link = &setup->next;
    }
    ReleaseSRWLockExclusive(&tcpSetupLock);
}
static BOOL start_tcp_worker(CONNECTION_CONFIG* config)
{
    // The listener is the sole producer. Reap only on saturation, not on every accept.
    if (tcpSetupCount >= PB_TCP_SETUP_LIMIT) tcp_setup_reap(FALSE);
    AcquireSRWLockExclusive(&tcpSetupLock);
    if (!running || tcpSetupCount >= PB_TCP_SETUP_LIMIT) {
        ReleaseSRWLockExclusive(&tcpSetupLock); WSASetLastError(WSAENOBUFS); return FALSE;
    }
    PB_TCP_SETUP* setup = calloc(1, sizeof(*setup));
    if (!setup) { ReleaseSRWLockExclusive(&tcpSetupLock); return FALSE; }
    setup->done = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!setup->done) { free(setup); ReleaseSRWLockExclusive(&tcpSetupLock); return FALSE; }
    setup->config = config; setup->client = config->client_socket; setup->proxy = INVALID_SOCKET;
    setup->operation.complete = tcp_setup_complete;
    setup->deadline = GetTickCount64() + PB_TCP_SETUP_TIMEOUT_MS;
    setup->pending = TRUE; // Startup packet owns a completion reference.
    if (!PostQueuedCompletionStatus(tcpIoPort, 0, 0, &setup->operation.ov)) {
        CloseHandle(setup->done); free(setup); ReleaseSRWLockExclusive(&tcpSetupLock); return FALSE;
    }
    setup->next = tcpSetups; tcpSetups = setup; ++tcpSetupCount;
    ReleaseSRWLockExclusive(&tcpSetupLock);
    return TRUE; // Ownership transfers only on success, as with the old worker.
}
static void reap_tcp_workers(void) { tcp_setup_reap(FALSE); tcp_io_reap(FALSE); }
BOOL pb_tcp_start_workers(void) { return tcp_io_start(); }
BOOL pb_tcp_is_worker_thread(void)
{
    DWORD caller = GetCurrentThreadId();
    for (int i = 0; i < PB_TCP_IO_WORKER_COUNT; ++i)
        if (tcpIoWorkers[i] && GetThreadId(tcpIoWorkers[i]) == caller) return TRUE;
    return FALSE;
}
void pb_tcp_stop_workers(void)
{
    // Listener already joined; completion workers remain alive until setup AND
    // data references drain. Admission closes before a racing setup can hand off.
    tcp_io_close_admission();
    tcp_setup_reap(TRUE);
    while (tcpSetups) {
        WaitForSingleObject(tcpSetups->done, INFINITE);
        tcp_setup_reap(TRUE);
    }
    tcp_io_stop();
}
