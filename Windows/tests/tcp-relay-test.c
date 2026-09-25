#include "pb_internal.h"
#ifdef PB_TCP_IOCP_CANDIDATE
#include "tcp-iocp-candidate.inc"
#else
#include "../src/relay/pb_tcp_transfer.inc"
static BOOL backend_begin(void) { return TRUE; }
static void backend_end(void) {}
static void stop_transfer(SOCKET a, SOCKET b) { shutdown(a, SD_BOTH); shutdown(b, SD_BOTH); }
#endif

// Globals used by pb_util.c; no Core lifecycle or driver is started.
volatile BOOL running = TRUE;
LogCallback g_log_callback = NULL;

// Exercise the production transfer_handler using real loopback sockets, without
// starting Core or opening a driver. Deadlines make a regression fail, not hang.
#include "tcp-test-sockets.inc"

static BOOL run_case(BOOL reverse, BOOL cancel)
{
    SOCKET client = INVALID_SOCKET, clientRelay = INVALID_SOCKET;
    SOCKET server = INVALID_SOCKET, serverRelay = INVALID_SOCKET;
    HANDLE thread = NULL;
    BOOL ok = FALSE;
    if (!socket_pair(&client, &clientRelay) || !socket_pair(&server, &serverRelay)) goto done;
    TRANSFER_CONFIG *config = malloc(sizeof(*config));
    if (!config) goto done;
    config->from_socket = clientRelay;
    config->to_socket = serverRelay;
    thread = CreateThread(NULL, 0, transfer_handler, config, 0, NULL);
    if (!thread) { free(config); goto done; }
    if (cancel) {
        stop_transfer(clientRelay, serverRelay);
        ok = WaitForSingleObject(thread, 3000) == WAIT_OBJECT_0;
    } else {
        SOCKET sender = reverse ? server : client;
        SOCKET receiver = reverse ? client : server;
        const char request[] = "request before FIN";
        const char reply[] = "response after FIN: all bytes must survive";
        char end;
        ok = send_all(sender, request, sizeof(request)) == sizeof(request) &&
             shutdown(sender, SD_SEND) == 0 &&
             read_exact(receiver, request, sizeof(request)) &&
             recv(receiver, &end, 1, 0) == 0;
        // Receiving FIN establishes ordering: the reply is sent only AFTER the
        // relay observed EOF. No timing-dependent sleep is needed.
        if (ok) ok = send_all(receiver, reply, sizeof(reply)) == sizeof(reply) &&
                     shutdown(receiver, SD_SEND) == 0 &&
                     read_exact(sender, reply, sizeof(reply)) &&
                     recv(sender, &end, 1, 0) == 0;
        if (ok) ok = WaitForSingleObject(thread, 3000) == WAIT_OBJECT_0;
    }
done:
    if (clientRelay != INVALID_SOCKET) shutdown(clientRelay, SD_BOTH);
    if (serverRelay != INVALID_SOCKET) shutdown(serverRelay, SD_BOTH);
    if (thread) {
        if (WaitForSingleObject(thread, 3000) != WAIT_OBJECT_0) {
            fputs("FAIL: relay worker failed to drain\n", stderr);
            ExitProcess(2); // Never recycle sockets still owned by a worker.
        }
        CloseHandle(thread);
    }
    if (client != INVALID_SOCKET) closesocket(client);
    if (server != INVALID_SOCKET) closesocket(server);
    if (clientRelay != INVALID_SOCKET) closesocket(clientRelay);
    if (serverRelay != INVALID_SOCKET) closesocket(serverRelay);
    return ok;
}

#include "tcp-throughput.inc"
#include "tcp-concurrency.inc"
#ifdef PB_TCP_IOCP_CANDIDATE
#include "tcp-iocp-faults.inc"
#endif

int main(int argc, char **argv)
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    if (!backend_begin()) return 2;
    if (argc == 2 && strcmp(argv[1], "--bench") == 0) {
        int result = benchmark_main();
        backend_end();
        WSACleanup();
        return result;
    }
    int failures = 0;
    for (int i = 0; i < 3; ++i) {
        BOOL ok = run_case(i == 1, i == 2);
        printf("%s: %s\n", i == 0 ? "client-half-close" : i == 1 ? "server-half-close" : "forced-stop", ok ? "PASS" : "FAIL");
        if (!ok) ++failures;
    }
    BOOL concurrent = concurrent_cases();
    printf("16 parallel clients /144 half-close and stop cases: %s\n", concurrent ? "PASS" : "FAIL");
    if (!concurrent) ++failures;
    BOOL stalled = stalled_write_stop();
    printf("stalled16MiB writer /relay stop deadline1s: %s\n", stalled ? "PASS" : "FAIL");
    if (!stalled) ++failures;
#ifdef PB_TCP_IOCP_CANDIDATE
    if (!iocp_fault_tests()) ++failures;
    BOOL pausedCancel = iocp_paused_completion_cancel();
    printf("IOCP dequeued completion / two concurrent cancellers / retained ownership: %s\n", pausedCancel ? "PASS" : "FAIL");
    if (!pausedCancel) ++failures;
    if (!iocp_without_owner_threads()) ++failures;
#endif
    backend_end();
#ifdef PB_TCP_IOCP_CANDIDATE
    if (!iocp_startup_fault_tests()) ++failures;
#endif
    WSACleanup();
    return failures ? 1 : 0;
}
