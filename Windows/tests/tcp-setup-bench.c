#include "pb_internal.h"
#include <psapi.h>
#include <tlhelp32.h>

// This benchmark includes the production setup and IOCP implementations.  It
// measures their process footprint on loopback; kernel socket-buffer memory and
// a real network/proxy are deliberately outside its scope.
volatile BOOL running = TRUE;
LogCallback g_log_callback;
BOOL dns_cache_lookup(UINT32 ip, char* out, size_t size)
{ (void)ip; (void)out; (void)size; return FALSE; }
BOOL dns_cache_lookup_v6(const UINT8 ip[16], char* out, size_t size)
{ (void)ip; (void)out; (void)size; return FALSE; }
#include "../src/relay/pb_tcp_iocp.inc"
#include "../src/relay/pb_tcp_setup.inc"
#include "tcp-test-sockets.inc"

#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s (WSA=%d Win=%lu)\n", __LINE__, #x, WSAGetLastError(), GetLastError()); return FALSE; } } while (0)

typedef struct {
    ULONGLONG cpu100ns;
    SIZE_T privateBytes;
    DWORD handles, threads;
} METRICS;

typedef struct {
    SOCKET* client;
    SOCKET* server;
    unsigned count;
} STALLS;

static SOCKET proxy_listener(UINT16* port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (s == INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int size = sizeof(a);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) || listen(s, SOMAXCONN) ||
        getsockname(s, (struct sockaddr*)&a, &size)) { closesocket(s); return INVALID_SOCKET; }
    *port = ntohs(a.sin_port); return s;
}
static SOCKET accept_proxy(SOCKET listener)
{
    fd_set ready; FD_ZERO(&ready); FD_SET(listener, &ready); struct timeval wait = {5, 0};
    if (select(0, &ready, NULL, NULL, &wait) != 1) return INVALID_SOCKET;
    SOCKET s = accept(listener, NULL, NULL);
    if (s != INVALID_SOCKET) configure_tcp_socket(s, 65536, 5000);
    return s;
}
static CONNECTION_CONFIG* make_config(SOCKET input, UINT16 port)
{
    CONNECTION_CONFIG* c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->client_socket = input; c->orig_dest_ip = htonl(INADDR_LOOPBACK); c->orig_dest_port = 443;
    strcpy_s(c->proxy_snapshot.host, sizeof(c->proxy_snapshot.host), "127.0.0.1");
    c->proxy_snapshot.resolved_ip = htonl(INADDR_LOOPBACK); c->proxy_snapshot.port = port;
    c->proxy_snapshot.type = PROXY_TYPE_HTTP;
    return c;
}
static DWORD process_threads(void)
{
    DWORD result = 0, pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 entry = {.dwSize = sizeof(entry)};
    if (snap != INVALID_HANDLE_VALUE) {
        for (BOOL ok = Thread32First(snap, &entry); ok; ok = Thread32Next(snap, &entry))
            if (entry.th32OwnerProcessID == pid) result++;
        CloseHandle(snap);
    }
    return result;
}
static METRICS snapshot(void)
{
    METRICS result = {0}; FILETIME create, exit, kernel, user;
    PROCESS_MEMORY_COUNTERS_EX memory = {.cb = sizeof(memory)};
    GetProcessTimes(GetCurrentProcess(), &create, &exit, &kernel, &user);
    result.cpu100ns = ((ULONGLONG)kernel.dwHighDateTime << 32 | kernel.dwLowDateTime) +
        ((ULONGLONG)user.dwHighDateTime << 32 | user.dwLowDateTime);
    GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&memory, sizeof(memory));
    GetProcessHandleCount(GetCurrentProcess(), &result.handles);
    result.privateBytes = memory.PrivateUsage; result.threads = process_threads(); return result;
}
static double elapsed_ms(LARGE_INTEGER first, LARGE_INTEGER last, LARGE_INTEGER frequency)
{ return (double)(last.QuadPart - first.QuadPart) * 1000.0 / frequency.QuadPart; }
static int compare_double(const void* a, const void* b)
{ double x = *(const double*)a, y = *(const double*)b; return x < y ? -1 : x > y; }
static double percentile(double* values, unsigned count, double fraction)
{
    if (!count) return -1.0;
    qsort(values, count, sizeof(*values), compare_double);
    unsigned index = (unsigned)ceil(fraction * count); return values[index ? index - 1 : 0];
}
static BOOL wait_for_pair(PB_IO_PAIR* before)
{
    ULONGLONG limit = GetTickCount64() + 5000;
    while (GetTickCount64() < limit) {
        if (tcpIoPairs != before) return TRUE;
        Sleep(1);
    }
    return FALSE;
}
static BOOL healthy_http(SOCKET listener, UINT16 port, LARGE_INTEGER frequency, double* latency)
{
    SOCKET client, input; CHECK(socket_pair(&client, &input));
    CONNECTION_CONFIG* config = make_config(input, port); CHECK(config);
    PB_IO_PAIR* before = tcpIoPairs; LARGE_INTEGER start, end; QueryPerformanceCounter(&start);
    if (!start_tcp_worker(config)) { free(config); closesocket(input); closesocket(client); return FALSE; }
    SOCKET server = accept_proxy(listener); CHECK(server != INVALID_SOCKET);
    char request[1024] = {0}; int used = 0;
    while (used < (int)sizeof(request) - 1 && !strstr(request, "\r\n\r\n"))
        CHECK(recv(server, request + used++, 1, 0) == 1);
    CHECK(strstr(request, "CONNECT 127.0.0.1:443 HTTP/1.1\r\n") == request);
    CHECK(send(server, "HTTP/1.1 200 OK\r\n\r\nE", 20, 0) == 20);
    CHECK(read_exact(client, "E", 1)); QueryPerformanceCounter(&end);
    CHECK(wait_for_pair(before)); *latency = elapsed_ms(start, end, frequency);
    closesocket(client); closesocket(server);
    if (tcpIoPairs) CHECK(WaitForSingleObject(tcpIoPairs->done, 5000) == WAIT_OBJECT_0);
    tcp_io_reap(FALSE); tcp_setup_reap(FALSE); return TRUE;
}
static BOOL create_stalls(SOCKET listener, UINT16 port, unsigned count, STALLS* stalls)
{
    ZeroMemory(stalls, sizeof(*stalls));
    stalls->client = calloc(count ? count : 1, sizeof(*stalls->client));
    stalls->server = calloc(count ? count : 1, sizeof(*stalls->server)); CHECK(stalls->client && stalls->server);
    for (unsigned i = 0; i < count; ++i) {
        SOCKET input; CHECK(socket_pair(&stalls->client[i], &input));
        CONNECTION_CONFIG* config = make_config(input, port); CHECK(config && start_tcp_worker(config));
        stalls->server[i] = accept_proxy(listener); CHECK(stalls->server[i] != INVALID_SOCKET);
        static const char request[] = "CONNECT 127.0.0.1:443 HTTP/1.1\r\n";
        CHECK(read_exact(stalls->server[i], request, (int)strlen(request)));
        // Do not send a proxy reply: this is the pending-handshake pressure case.
        stalls->count++;
    }
    return TRUE;
}
static void close_stalls(STALLS* stalls)
{
    for (unsigned i = 0; i < stalls->count; ++i) { closesocket(stalls->client[i]); closesocket(stalls->server[i]); }
    free(stalls->client); free(stalls->server); ZeroMemory(stalls, sizeof(*stalls));
}
static BOOL run_case(FILE* csv, const char* name, unsigned stalled, unsigned repeat, BOOL churn)
{
    UINT16 port; SOCKET listener = proxy_listener(&port); CHECK(listener != INVALID_SOCKET);
    CHECK(pb_tcp_start_workers()); Sleep(20); METRICS base = snapshot(); STALLS slots;
    CHECK(create_stalls(listener, port, stalled, &slots)); CHECK(tcpSetupCount == stalled);
    METRICS pressure = snapshot(); LARGE_INTEGER frequency; QueryPerformanceFrequency(&frequency);
    double latencies[32] = {0}; unsigned samples = 0;
    if (!churn && stalled < PB_TCP_SETUP_LIMIT) {
        for (; samples < 25; ++samples) CHECK(healthy_http(listener, port, frequency, &latencies[samples]));
    } else if (churn) {
        for (; samples < 1000; ++samples) CHECK(healthy_http(listener, port, frequency, &latencies[samples % 32]));
    } else {
        SOCKET rejected, input; CHECK(socket_pair(&rejected, &input));
        CONNECTION_CONFIG* config = make_config(input, port); CHECK(config && !start_tcp_worker(config));
        free(config); closesocket(input); closesocket(rejected);
    }
    double p50 = churn ? -1.0 : percentile(latencies, samples, .50);
    double p99 = churn ? -1.0 : percentile(latencies, samples, .99);
    if (churn) { samples = 32; p50 = percentile(latencies, samples, .50); p99 = percentile(latencies, samples, .99); }
    running = FALSE; pb_tcp_stop_workers(); running = TRUE; close_stalls(&slots); closesocket(listener);
    Sleep(30); METRICS after = snapshot();
    fprintf(csv, "%s,%u,%u,%u,%.3f,%.3f,%.3f,%lu,%lu,%lu,%lu,%lu,%lu,%llu,%llu,%llu\n",
        name, repeat, stalled, churn ? 1000 : samples, p50, p99,
        (double)(after.cpu100ns - base.cpu100ns) / 10000.0,
        base.threads, pressure.threads, after.threads, base.handles, pressure.handles, after.handles,
        (unsigned long long)base.privateBytes, (unsigned long long)pressure.privateBytes, (unsigned long long)after.privateBytes);
    fflush(csv);
    printf("PASS %s repeat=%u stalled=%u samples=%u p50=%.3fms p99=%.3fms\n", name, repeat, stalled, churn ? 1000 : samples, p50, p99);
    return TRUE;
}
int main(int argc, char** argv)
{
    if (argc != 2) return 2; setvbuf(stdout, NULL, _IONBF, 0);
    WSADATA wsa; if (WSAStartup(MAKEWORD(2,2), &wsa)) return 3;
    FILE* csv = fopen(argv[1], "w"); if (!csv) return 4;
    fprintf(csv, "scenario,repeat,stalled,healthy_samples,p50_ms,p99_ms,cpu_ms,threads_base,threads_pressure,threads_after_stop,handles_base,handles_pressure,handles_after_stop,private_base,private_pressure,private_after_stop\n");
    unsigned cases[] = {0, 64, 256, 1023, 1024};
    BOOL ok = TRUE;
    for (unsigned repeat = 1; repeat <= 3 && ok; ++repeat)
        for (unsigned i = 0; i < ARRAYSIZE(cases) && ok; ++i) ok = run_case(csv, "stalled", cases[i], repeat, FALSE);
    if (ok) ok = run_case(csv, "churn", 0, 1, TRUE);
    fclose(csv); WSACleanup(); return ok ? 0 : 1;
}
