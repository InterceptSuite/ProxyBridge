// Regression gates for replacing the production byte pump. No Core/driver start.
static DWORD WINAPI parallel_cases(LPVOID arg)
{
    (void)arg;
    for (int round = 0; round < 3; round++)
        for (int kind = 0; kind < 3; kind++)
            if (!run_case(kind == 1, kind == 2)) return 1;
    return 0;
}
static BOOL concurrent_cases(void)
{
    HANDLE workers[16] = {0};
    int count = 0;
    BOOL ok = TRUE;
    for (; count < 16; count++) {
        workers[count] = CreateThread(NULL, 0, parallel_cases, NULL, 0, NULL);
        if (!workers[count]) { ok = FALSE; break; }
    }
    for (int i = 0; i < count; i++) {
        if (WaitForSingleObject(workers[i], 30000) != WAIT_OBJECT_0) ExitProcess(2);
        DWORD result;
        if (!GetExitCodeThread(workers[i], &result) || result) ok = FALSE;
        CloseHandle(workers[i]);
    }
    return ok;
}
static DWORD WINAPI large_write(LPVOID arg)
{
    SOCKET socket = *(SOCKET*)arg;
    char buffer[65536]; memset(buffer, 'x', sizeof(buffer));
    for (int i = 0; i < 256; i++)
        if (send_all(socket, buffer, sizeof(buffer)) == SOCKET_ERROR) return 1;
    return 0;
}
static BOOL stalled_write_stop(void)
{
    SOCKET sender = INVALID_SOCKET, input = INVALID_SOCKET;
    SOCKET receiver = INVALID_SOCKET, output = INVALID_SOCKET;
    HANDLE relay = NULL, writer = NULL;
    BOOL ok = FALSE;
    if (!socket_pair(&sender, &input) || !socket_pair(&receiver, &output)) goto done;
    int socketBufferBytes = 4096;
    if (setsockopt(output, SOL_SOCKET, SO_SNDBUF, (char*)&socketBufferBytes, sizeof(socketBufferBytes)) ||
        setsockopt(receiver, SOL_SOCKET, SO_RCVBUF, (char*)&socketBufferBytes, sizeof(socketBufferBytes))) goto done;
    DWORD noTimeout = 0; // match connection_handler's production transfer phase
    if (setsockopt(input, SOL_SOCKET, SO_RCVTIMEO, (char*)&noTimeout, sizeof(noTimeout)) ||
        setsockopt(input, SOL_SOCKET, SO_SNDTIMEO, (char*)&noTimeout, sizeof(noTimeout)) ||
        setsockopt(output, SOL_SOCKET, SO_RCVTIMEO, (char*)&noTimeout, sizeof(noTimeout)) ||
        setsockopt(output, SOL_SOCKET, SO_SNDTIMEO, (char*)&noTimeout, sizeof(noTimeout))) goto done;
    TRANSFER_CONFIG* config = malloc(sizeof(*config));
    if (!config) goto done;
    config->from_socket = input; config->to_socket = output;
    relay = CreateThread(NULL, 0, transfer_handler, config, 0, NULL);
    if (!relay) { free(config); goto done; }
    writer = CreateThread(NULL, 0, large_write, &sender, 0, NULL);
    if (!writer) goto done;
    char byte;
    // Prove bytes reached the far socket, but leave its receive buffer unread.
    if (recv(receiver, &byte, 1, MSG_PEEK) != 1 || byte != 'x') { puts("stalled setup: first byte missing"); goto done; }
    if (WaitForSingleObject(writer, 200) != WAIT_TIMEOUT) { puts("stalled setup: writer already completed"); goto done; }
    ULONGLONG stopAt = GetTickCount64();
    stop_transfer(input, output);
    ok = WaitForSingleObject(relay, 1000) == WAIT_OBJECT_0;
    printf("stalled relay: stop wait=%llums, complete=%d\n", GetTickCount64() - stopAt, ok);
done:
    if (input != INVALID_SOCKET) shutdown(input, SD_BOTH);
    if (output != INVALID_SOCKET) shutdown(output, SD_BOTH);
    if (sender != INVALID_SOCKET) shutdown(sender, SD_BOTH);
    if (receiver != INVALID_SOCKET) shutdown(receiver, SD_BOTH);
    HANDLE threads[] = {relay, writer};
    for (int i = 0; i < 2; i++) if (threads[i]) {
        if (WaitForSingleObject(threads[i], 3000) != WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(threads[i]);
    }
    SOCKET sockets[] = {sender, input, receiver, output};
    for (int i = 0; i < 4; i++) if (sockets[i] != INVALID_SOCKET) closesocket(sockets[i]);
    return ok;
}
