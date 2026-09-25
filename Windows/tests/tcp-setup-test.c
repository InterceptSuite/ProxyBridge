#include "pb_internal.h"
volatile BOOL running = TRUE;
LogCallback g_log_callback;
static BOOL cachedDomain;
BOOL dns_cache_lookup(UINT32 ip, char* out, size_t size)
{ (void)ip; if (cachedDomain) strcpy_s(out, size, "example.test"); return cachedDomain; }
BOOL dns_cache_lookup_v6(const UINT8 ip[16], char* out, size_t size)
{ (void)ip; return dns_cache_lookup(0, out, size); }
static volatile LONG fragmentIo, failSend, failReceive;
static volatile LONG pauseNext;
static HANDLE completionPaused, completionResume;
static BOOL WINAPI setup_dequeue(HANDLE port, LPDWORD bytes, PULONG_PTR key, LPOVERLAPPED* ov, DWORD timeout)
{
    BOOL ok = GetQueuedCompletionStatus(port, bytes, key, ov, timeout);
    if (*ov && InterlockedCompareExchange(&pauseNext, 0, 1) == 1) {
        SetEvent(completionPaused);
        if (WaitForSingleObject(completionResume, 5000) != WAIT_OBJECT_0) ExitProcess(2);
    }
    return ok;
}
static int WSAAPI setup_send(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD bytes,
    DWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE callback)
{
    if (InterlockedExchange(&failSend, 0)) { WSASetLastError(WSAENOBUFS); return SOCKET_ERROR; }
    WSABUF part = buffers[0]; if (fragmentIo && part.len > 3) part.len = 3;
    return WSASend(s, &part, count, bytes, flags, ov, callback);
}
static int WSAAPI setup_receive(SOCKET s, LPWSABUF buffers, DWORD count, LPDWORD bytes,
    LPDWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE callback)
{
    if (InterlockedExchange(&failReceive, 0)) { WSASetLastError(WSAENOBUFS); return SOCKET_ERROR; }
    WSABUF part = buffers[0]; if (fragmentIo && part.len > 1) part.len = 1;
    return WSARecv(s, &part, count, bytes, flags, ov, callback);
}
#define PB_TCP_SETUP_LIMIT 64
#define WSASend setup_send
#define WSARecv setup_receive
#define GetQueuedCompletionStatus setup_dequeue
#include "../src/relay/pb_tcp_iocp.inc"
#include "../src/relay/pb_tcp_setup.inc"
#undef WSASend
#undef WSARecv
#undef GetQueuedCompletionStatus
#include "tcp-test-sockets.inc"
#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s (WSA=%d)\n", __LINE__, #x, WSAGetLastError()); ExitProcess(1); } } while (0)
static SOCKET proxy_listener(UINT16* port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); CHECK(s != INVALID_SOCKET);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(!bind(s, (struct sockaddr*)&a, sizeof(a)) && !listen(s, SOMAXCONN));
    int size = sizeof(a); CHECK(!getsockname(s, (struct sockaddr*)&a, &size)); *port = ntohs(a.sin_port); return s;
}
static SOCKET accept_proxy(SOCKET listener)
{
    fd_set ready; FD_ZERO(&ready); FD_SET(listener, &ready); struct timeval wait = {3, 0};
    CHECK(select(0, &ready, NULL, NULL, &wait) == 1);
    SOCKET s = accept(listener, NULL, NULL); CHECK(s != INVALID_SOCKET);
    configure_tcp_socket(s, 65536, 3000); return s;
}
static CONNECTION_CONFIG* make_config(SOCKET input, UINT16 port, int kind, BOOL auth, BOOL http)
{
    CONNECTION_CONFIG* c = calloc(1, sizeof(*c)); CHECK(c);
    c->client_socket = input; c->is_ipv6 = kind == 1; c->orig_dest_ip = htonl(INADDR_LOOPBACK);
    c->orig_dest_ip6[15] = 1; c->orig_dest_port = 443;
    strcpy_s(c->proxy_snapshot.host, sizeof(c->proxy_snapshot.host), "127.0.0.1");
    c->proxy_snapshot.resolved_ip = htonl(INADDR_LOOPBACK); c->proxy_snapshot.port = port;
    c->proxy_snapshot.type = http ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
    c->proxy_snapshot.send_domain_to_proxy = kind == 2;
    if (auth) {
        strcpy_s(c->proxy_snapshot.username, sizeof(c->proxy_snapshot.username), "user");
        strcpy_s(c->proxy_snapshot.password, sizeof(c->proxy_snapshot.password), "secret");
    }
    return c;
}
static void wait_setup_done(void)
{
    CHECK(tcpSetups && WaitForSingleObject(tcpSetups->done, 3000) == WAIT_OBJECT_0);
    tcp_setup_reap(FALSE);
}
static void round_trip_and_half_close(SOCKET client, SOCKET server)
{
    CHECK(send_all(client, "request", 7) == 7 && read_exact(server, "request", 7));
    CHECK(!shutdown(client, SD_SEND)); char byte;
    CHECK(recv(server, &byte, 1, 0) == 0);
    CHECK(send_all(server, "response", 8) == 8 && read_exact(client, "response", 8));
    CHECK(!shutdown(server, SD_SEND) && recv(client, &byte, 1, 0) == 0);
    CHECK(tcpIoPairs && WaitForSingleObject(tcpIoPairs->done, 3000) == WAIT_OBJECT_0);
    tcp_io_reap(FALSE);
}
static void socks_case(int kind, int replyKind, BOOL auth, int reject)
{
    UINT16 port; SOCKET listener = proxy_listener(&port), client, input;
    CHECK(socket_pair(&client, &input)); cachedDomain = kind == 2;
    CHECK(start_tcp_worker(make_config(input, port, kind, auth, FALSE)));
    SOCKET server = accept_proxy(listener); closesocket(listener);
    CHECK(read_exact(server, auth ? "\x05\x02\x00\x02" : "\x05\x01\x00", auth ? 4 : 3));
    CHECK(send_all(server, reject == 1 ? "\x05\xff" : auth ? "\x05\x02" : "\x05\x00", 2) == 2);
    if (reject != 1 && auth) {
        const char credentials[] = {1,4,'u','s','e','r',6,'s','e','c','r','e','t'};
        CHECK(read_exact(server, credentials, sizeof(credentials)));
        CHECK(send_all(server, reject == 2 ? "\x01\x01" : "\x01\x00", 2) == 2);
    }
    if (reject != 1 && reject != 2) {
        char request[32] = {5,1,0,1}; int n;
        if (kind == 0) { request[4] = 127; request[7] = 1; n = 10; }
        else if (kind == 1) { request[3] = 4; request[19] = 1; n = 22; }
        else { request[3] = 3; request[4] = 12; memcpy(request + 5, "example.test", 12); n = 19; }
        request[n-2] = 1; request[n-1] = -69;
        CHECK(read_exact(server, request, n));
        char reply[40] = {5,0,0,1}; int size;
        if (replyKind == 0) size = 10;
        else if (replyKind == 1) { reply[3] = 4; size = 22; }
        else { reply[3] = 3; reply[4] = 3; memcpy(reply + 5, "bnd", 3); size = 10; }
        if (reject == 3) reply[1] = 5;
        if (reject == 4) reply[3] = 0;
        memcpy(reply + size, "early\0binary", 12);
        CHECK(send_all(server, reply, size + 12) == size + 12);
    }
    wait_setup_done();
    if (!reject) {
        CHECK(read_exact(client, "early\0binary", 12)); round_trip_and_half_close(client, server);
    } else { char byte; CHECK(recv(client, &byte, 1, 0) <= 0 && !tcpIoPairs); }
    closesocket(client); closesocket(server);
    CHECK(!tcpSetups && !tcpSetupCount && !tcpIoPairs);
}
static void http_case(int kind, BOOL auth, int reject)
{
    unsigned baseline = tcpSetupCount;
    UINT16 port; SOCKET listener = proxy_listener(&port), client, input;
    CHECK(socket_pair(&client, &input)); cachedDomain = kind == 2;
    CHECK(start_tcp_worker(make_config(input, port, kind, auth, TRUE)));
    SOCKET server = accept_proxy(listener); closesocket(listener);
    char request[2048] = {0}; int n = 0;
    while (n < sizeof(request)-1 && !strstr(request, "\r\n\r\n")) CHECK(recv(server, request + n++, 1, 0) == 1);
    CHECK(strstr(request, kind == 0 ? "CONNECT 127.0.0.1:443 HTTP/1.1\r\n" :
        kind == 1 ? "CONNECT [::1]:443 HTTP/1.1\r\n" : "CONNECT example.test:443 HTTP/1.1\r\n") == request);
    CHECK((strstr(request, "Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n") != NULL) == auth);
    const char* reply = reject == 1 ? "HTTP/1.1 407 Denied\r\n\r\n" :
        reject == 2 ? "HTTP/1.1 2000 Bad\r\n\r\n" :
        reject == 3 ? "garbage 200 OK\r\n\r\n" : "HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nearly";
    CHECK(send_all(server, reply, (int)strlen(reply)) == strlen(reply));
    wait_setup_done();
    if (!reject) { CHECK(read_exact(client, "early", 5)); round_trip_and_half_close(client, server); }
    else { char byte; CHECK(recv(client, &byte, 1, 0) <= 0 && !tcpIoPairs); }
    closesocket(client); closesocket(server);
    CHECK(tcpSetupCount == baseline && !tcpIoPairs);
}
static void stalled_and_capacity(void)
{
    SOCKET clients[PB_TCP_SETUP_LIMIT], servers[PB_TCP_SETUP_LIMIT]; UINT16 port;
    SOCKET listener = proxy_listener(&port);
    for (unsigned i = 0; i < PB_TCP_SETUP_LIMIT - 1; ++i) {
        SOCKET input; CHECK(socket_pair(&clients[i], &input));
        CHECK(start_tcp_worker(make_config(input, port, 0, FALSE, FALSE)));
        servers[i] = accept_proxy(listener); CHECK(read_exact(servers[i], "\x05\x01\x00", 3));
    }
    // Every setup worker can service a healthy flow while63 peers never reply.
    ULONGLONG before = GetTickCount64();
    http_case(0, FALSE, 0);
    CHECK(GetTickCount64() - before < 2500);
    SOCKET input; CHECK(socket_pair(&clients[PB_TCP_SETUP_LIMIT-1], &input));
    CHECK(start_tcp_worker(make_config(input, port, 0, FALSE, FALSE)));
    servers[PB_TCP_SETUP_LIMIT-1] = accept_proxy(listener);
    CHECK(read_exact(servers[PB_TCP_SETUP_LIMIT-1], "\x05\x01\x00", 3));
    SOCKET rejected, rejectedInput; CHECK(socket_pair(&rejected, &rejectedInput));
    CONNECTION_CONFIG* extra = make_config(rejectedInput, port, 0, FALSE, FALSE);
    CHECK(!start_tcp_worker(extra) && tcpSetupCount == PB_TCP_SETUP_LIMIT);
    free(extra); closesocket(rejected); closesocket(rejectedInput);
    running = FALSE; before = GetTickCount64(); pb_tcp_stop_workers();
    CHECK(GetTickCount64() - before < 2500 && !tcpSetups && !tcpSetupCount && !tcpIoPort);
    for (unsigned i = 0; i < PB_TCP_SETUP_LIMIT; ++i) { closesocket(clients[i]); closesocket(servers[i]); }
    closesocket(listener); running = TRUE; CHECK(pb_tcp_start_workers());
    puts("PASS bounded admission, healthy flow among63 stalled setups, Stop drains64 and restart");
}
static void expiry_and_faults(void)
{
    for (int fault = 0; fault < 3; ++fault) {
        UINT16 port; SOCKET listener = proxy_listener(&port), client, input;
        CHECK(socket_pair(&client, &input));
        if (fault == 1) InterlockedExchange(&failSend, 1);
        if (fault == 2) InterlockedExchange(&failReceive, 1);
        CHECK(start_tcp_worker(make_config(input, port, 0, FALSE, FALSE)));
        SOCKET server = accept_proxy(listener); closesocket(listener);
        if (!fault) {
            CHECK(read_exact(server, "\x05\x01\x00", 3));
            AcquireSRWLockExclusive(&tcpSetups->lock); tcpSetups->deadline = 0; ReleaseSRWLockExclusive(&tcpSetups->lock);
            tcp_setup_reap(FALSE);
        }
        if (tcpSetups) wait_setup_done();
        CHECK(!tcpSetupCount && !tcpIoPairs); closesocket(client); closesocket(server);
    }
    puts("PASS pending receive expiry and immediate send/receive submission failures");
}
static DWORD WINAPI stop_setup(void* unused) { (void)unused; pb_tcp_stop_workers(); return 0; }
static void completion_lifetime(BOOL startup)
{
    UINT16 port; SOCKET listener = proxy_listener(&port), client, input, server = INVALID_SOCKET;
    CHECK(socket_pair(&client, &input));
    completionPaused = CreateEventW(NULL, TRUE, FALSE, NULL);
    completionResume = CreateEventW(NULL, TRUE, FALSE, NULL); CHECK(completionPaused && completionResume);
    if (startup) InterlockedExchange(&pauseNext, 1);
    CHECK(start_tcp_worker(make_config(input, port, 0, FALSE, FALSE)));
    if (!startup) {
        server = accept_proxy(listener); CHECK(read_exact(server, "\x05\x01\x00", 3));
        InterlockedExchange(&pauseNext, 1); CHECK(send_all(server, "\x05\x00", 2) == 2);
    }
    CHECK(WaitForSingleObject(completionPaused, 3000) == WAIT_OBJECT_0);
    running = FALSE;
    HANDLE stopper = CreateThread(NULL, 0, stop_setup, NULL, 0, NULL); CHECK(stopper);
    CHECK(WaitForSingleObject(stopper, 100) == WAIT_TIMEOUT);
    AcquireSRWLockExclusive(&tcpSetups->lock);
    BOOL retained = tcpSetups->closing && tcpSetups->pending && !tcpSetups->claimed;
    ReleaseSRWLockExclusive(&tcpSetups->lock); CHECK(retained);
    SetEvent(completionResume);
    CHECK(WaitForSingleObject(stopper, 3000) == WAIT_OBJECT_0);
    CloseHandle(stopper); CloseHandle(completionPaused); CloseHandle(completionResume);
    closesocket(client); closesocket(listener); if (server != INVALID_SOCKET) closesocket(server);
    CHECK(!tcpSetups && !tcpSetupCount && !tcpIoPairs && !tcpIoPort);
    running = TRUE; CHECK(pb_tcp_start_workers());
    printf("PASS Stop retains dequeued %s completion until worker drains it\n", startup ? "startup" : "receive");
}
static void connect_refused(void)
{
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), client, input;
    CHECK(listener != INVALID_SOCKET);
    // Reserve a port without listening; another process cannot take it.
    struct sockaddr_in address = {0}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(!bind(listener, (struct sockaddr*)&address, sizeof(address)));
    int size = sizeof(address); CHECK(!getsockname(listener, (struct sockaddr*)&address, &size));
    CHECK(socket_pair(&client, &input));
    CHECK(start_tcp_worker(make_config(input, ntohs(address.sin_port), 0, FALSE, FALSE)));
    wait_setup_done(); CHECK(!tcpSetupCount && !tcpIoPairs);
    closesocket(listener); closesocket(client);
    puts("PASS asynchronous connect refusal releases setup");
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0); WSADATA wsa; CHECK(!WSAStartup(MAKEWORD(2,2), &wsa));
    CHECK(pb_tcp_start_workers());
    for (int fragmented = 0; fragmented < 2; ++fragmented) {
        InterlockedExchange(&fragmentIo, fragmented);
        for (int kind = 0; kind < 3; ++kind) for (int auth = 0; auth < 2; ++auth) {
            for (int reply = 0; reply < 3; ++reply) socks_case(kind, reply, auth, 0);
            http_case(kind, auth, 0);
        }
        for (int reject = 1; reject <= 4; ++reject) socks_case(0, 0, TRUE, reject);
        for (int reject = 1; reject <= 3; ++reject) http_case(0, FALSE, reject);
        printf("PASS SOCKS5/HTTP auth/address/reply/early-data/half-close and rejection matrix; fragmented=%d\n", fragmented);
    }
    InterlockedExchange(&fragmentIo, 0);
    expiry_and_faults();
    stalled_and_capacity();
    completion_lifetime(TRUE); completion_lifetime(FALSE);
    connect_refused();
    running = FALSE; pb_tcp_stop_workers(); CHECK(!tcpSetups && !tcpIoPairs && !tcpIoPort);
    WSACleanup(); puts("PASS async TCP setup"); return 0;
}
