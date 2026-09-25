// Microbenchmark of the production byte pump, not WFP/proxy/network performance.
typedef struct {
    SOCKET socket;
    UINT64 expected;
    BOOL ok;
} BENCH_RECEIVER;

static DWORD WINAPI benchmark_receive(LPVOID parameter)
{
    BENCH_RECEIVER *receiver = parameter;
    unsigned char buffer[65536];
    UINT64 received = 0;
    BOOL valid = TRUE;
    int length;
    while ((length = recv(receiver->socket, (char *)buffer, sizeof(buffer), 0)) > 0) {
        for (int i = 0; i < length; ++i)
            if (buffer[i] != (unsigned char)((received + i) % 251)) valid = FALSE;
        received += length;
        if (received > receiver->expected) { valid = FALSE; break; }
    }
    receiver->ok = valid && length == 0 && received == receiver->expected;
    char acknowledgement = receiver->ok ? 'Y' : 'N';
    send_all(receiver->socket, &acknowledgement, 1);
    shutdown(receiver->socket, SD_SEND);
    return receiver->ok ? 0 : 1;
}

static UINT64 filetime_ticks(FILETIME value)
{
    return ((UINT64)value.dwHighDateTime << 32) | value.dwLowDateTime;
}

static BOOL benchmark_once(BOOL relay, unsigned iteration)
{
    const UINT64 bytes = 2ull * 1024 * 1024 * 1024;
    SOCKET sender = INVALID_SOCKET, first = INVALID_SOCKET;
    SOCKET receiver = INVALID_SOCKET, second = INVALID_SOCKET;
    HANDLE transfer = NULL, reader = NULL;
    BOOL ok = FALSE;
    if (!socket_pair(&sender, &first)) goto done;
    if (relay) {
        if (!socket_pair(&receiver, &second)) goto done;
        // Match the current connection_handler's relay-side socket policy.
        configure_tcp_socket(first, 4194304, 30000);
        configure_tcp_socket(second, 4194304, 30000);
        TRANSFER_CONFIG *config = malloc(sizeof(*config));
        if (!config) goto done;
        config->from_socket = first; config->to_socket = second;
        transfer = CreateThread(NULL, 0, transfer_handler, config, 0, NULL);
        if (!transfer) { free(config); goto done; }
    } else {
        receiver = first;
        first = INVALID_SOCKET;
    }
    BENCH_RECEIVER state = {receiver, bytes, FALSE};
    LARGE_INTEGER frequency, start, end;
    FILETIME created, exited, kernelBefore, userBefore, kernelAfter, userAfter;
    if (!QueryPerformanceFrequency(&frequency) ||
        !GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernelBefore, &userBefore)) goto done;
    QueryPerformanceCounter(&start);
    reader = CreateThread(NULL, 0, benchmark_receive, &state, 0, NULL);
    if (!reader) goto done;
    unsigned char buffer[65536];
    UINT64 sent = 0;
    while (sent < bytes) {
        for (unsigned i = 0; i < sizeof(buffer); ++i)
            buffer[i] = (unsigned char)((sent + i) % 251);
        if (send_all(sender, (char *)buffer, sizeof(buffer)) != sizeof(buffer)) goto done;
        sent += sizeof(buffer);
    }
    if (shutdown(sender, SD_SEND) != 0 || !read_exact(sender, "Y", 1)) goto done;
    char eof;
    if (recv(sender, &eof, 1, 0) != 0 || WaitForSingleObject(reader, 5000) != WAIT_OBJECT_0 || !state.ok) goto done;
    if (transfer && WaitForSingleObject(transfer, 5000) != WAIT_OBJECT_0) goto done;
    QueryPerformanceCounter(&end);
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernelAfter, &userAfter)) goto done;
    double seconds = (double)(end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
    double cpu = (double)(filetime_ticks(kernelAfter) + filetime_ticks(userAfter) -
                          filetime_ticks(kernelBefore) - filetime_ticks(userBefore)) / 1e7;
    printf("%s,%u,%llu,%.6f,%.3f,%.6f\n", relay ? "relay" : "direct", iteration,
        (unsigned long long)bytes, seconds, (double)bytes / 1048576.0 / seconds, cpu);
    ok = TRUE;
done:
    if (sender != INVALID_SOCKET) shutdown(sender, SD_BOTH);
    if (receiver != INVALID_SOCKET) shutdown(receiver, SD_BOTH);
    if (first != INVALID_SOCKET) shutdown(first, SD_BOTH);
    if (second != INVALID_SOCKET) shutdown(second, SD_BOTH);
    HANDLE threads[] = {reader, transfer};
    for (int i = 0; i < 2; ++i) if (threads[i]) {
        if (WaitForSingleObject(threads[i], 5000) != WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(threads[i]);
    }
    SOCKET sockets[] = {sender, receiver, first, second};
    for (int i = 0; i < 4; ++i) if (sockets[i] != INVALID_SOCKET) closesocket(sockets[i]);
    if (!ok) fputs("FAIL: throughput run incomplete or corrupted\n", stderr);
    return ok;
}

static int benchmark_main(void)
{
    puts("mode,iteration,bytes,seconds,MiB_per_second,process_cpu_seconds");
    // Alternate order so a systematic warm-up/load drift does not favor a mode.
    for (unsigned i = 0; i < 4; ++i)
        for (unsigned j = 0; j < 2; ++j)
            if (!benchmark_once(((i + j) % 2) != 0, i)) return 1;
    return 0;
}
