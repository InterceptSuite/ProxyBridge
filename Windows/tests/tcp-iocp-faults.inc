static BOOL iocp_fault_case(LONG stage)
{
    SOCKET sender = INVALID_SOCKET, input = INVALID_SOCKET;
    SOCKET receiver = INVALID_SOCKET, output = INVALID_SOCKET;
    HANDLE owner = NULL;
    BOOL ok = FALSE;
    if (!socket_pair(&sender, &input) || !socket_pair(&receiver, &output)) goto done;
    TRANSFER_CONFIG* config = malloc(sizeof(*config));
    if (!config) goto done;
    config->from_socket = input; config->to_socket = output;
    submitNumber = 0; faultHits = 0; faultStage = stage;
    owner = CreateThread(NULL, 0, transfer_handler, config, 0, NULL);
    if (!owner) { free(config); goto done; }
    if (stage >= 7) send_all(sender, "trigger-send", 12);
    if (WaitForSingleObject(owner, 3000) != WAIT_OBJECT_0) goto done;
    DWORD result;
    ok = GetExitCodeThread(owner, &result) && result == 1 && faultHits > 0;
done:
    if (owner) {
        stop_transfer(input, output);
        if (WaitForSingleObject(owner, 3000) != WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(owner);
    }
    SOCKET sockets[] = {sender, input, receiver, output};
    for (int i = 0; i < 4; i++) if (sockets[i] != INVALID_SOCKET) closesocket(sockets[i]);
    faultStage = 0;
    return ok && !livePairs && !liveEvents && !liveRequests && !pairs;
}
static BOOL iocp_fault_tests(void)
{
    BOOL ok = TRUE;
    for (LONG stage = 1; stage <= 8; stage++) {
        BOOL passed = iocp_fault_case(stage);
        printf("IOCP injected failure %ld: %s\n", stage, passed ? "PASS" : "FAIL");
        if (!passed) ok = FALSE;
    }
    sendChunk = 7; // real socket writes split into <=7-byte requests, preserving offsets
    BOOL chunks = run_case(FALSE, FALSE) && run_case(TRUE, FALSE);
    sendChunk = 0;
    printf("IOCP seven-byte send chunks / both FIN directions: %s\n", chunks ? "PASS" : "FAIL");
    printf("IOCP outstanding pairs/events/requests: %ld/%ld/%ld\n", livePairs, liveEvents, liveRequests);
    return ok && chunks && !livePairs && !liveEvents && !liveRequests && !pairs;
}
static BOOL iocp_startup_fault_tests(void)
{
    BOOL ok = TRUE;
    for (LONG stage = 9; stage <= 11; stage++) {
        faultStage = stage; faultHits = 0;
        BOOL started = backend_begin();
        if (started) backend_end();
        BOOL passed = !started && faultHits == 1 && !completionPort &&
            !completionWorkers[0] && !completionWorkers[1];
        printf("IOCP pool startup failure %ld / cleanup: %s\n", stage, passed ? "PASS" : "FAIL");
        if (!passed) ok = FALSE;
    }
    faultStage = 0;
    // Recovery after partial startup must permit a normal fresh pool.
    if (!backend_begin()) return FALSE;
    BOOL recovered = run_case(FALSE, FALSE);
    backend_end();
    return ok && recovered && !livePairs && !liveEvents && !liveRequests;
}
typedef struct { SOCKET input, output; } CANCEL_TARGET;
static BOOL iocp_without_owner_threads(void)
{
    enum { COUNT = 32 };
    struct { SOCKET sender, input, receiver, output; ASYNC_PAIR* pair; } cases[COUNT];
    for (int i = 0; i < COUNT; i++) {
        cases[i].sender = cases[i].input = cases[i].receiver = cases[i].output = INVALID_SOCKET;
        cases[i].pair = NULL;
    }
    BOOL ok = FALSE;
    for (int i = 0; i < COUNT; i++) {
        if (!socket_pair(&cases[i].sender, &cases[i].input) ||
            !socket_pair(&cases[i].receiver, &cases[i].output)) goto done;
        cases[i].pair = async_attach(cases[i].input, cases[i].output);
        if (!cases[i].pair) goto done;
    }
    if (livePairs != COUNT) goto done;
    for (int i = 0; i < COUNT; i++)
        if (send_all(cases[i].sender, "payload", 7) != 7 || shutdown(cases[i].sender, SD_SEND)) goto done;
    for (int i = 0; i < COUNT; i++) {
        char end;
        if (!read_exact(cases[i].receiver, "payload", 7) || recv(cases[i].receiver, &end, 1, 0) != 0 ||
            send_all(cases[i].receiver, "reply", 5) != 5 || shutdown(cases[i].receiver, SD_SEND)) goto done;
    }
    for (int i = 0; i < COUNT; i++) {
        char end;
        if (!read_exact(cases[i].sender, "reply", 5) || recv(cases[i].sender, &end, 1, 0) != 0 ||
            WaitForSingleObject(cases[i].pair->done, 2000) != WAIT_OBJECT_0) goto done;
        DWORD status = async_join(cases[i].pair); cases[i].pair = NULL;
        if (status) goto done;
    }
    ok = TRUE;
done:
    for (int i = 0; i < COUNT; i++) {
        if (cases[i].pair) {
            stop_transfer(cases[i].input, cases[i].output);
            if (WaitForSingleObject(cases[i].pair->done, 3000) != WAIT_OBJECT_0) ExitProcess(2);
            async_join(cases[i].pair);
        }
        SOCKET sockets[] = {cases[i].sender, cases[i].input, cases[i].receiver, cases[i].output};
        for (int j = 0; j < 4; j++) if (sockets[j] != INVALID_SOCKET) closesocket(sockets[j]);
    }
    printf("IOCP32 attached pairs /2 shared workers /no pair-owner threads: %s\n", ok ? "PASS" : "FAIL");
    return ok && !livePairs && !liveEvents && !liveRequests && !pairs;
}
static DWORD WINAPI concurrent_cancel(void* arg)
{
    CANCEL_TARGET* target = arg;
    stop_transfer(target->input, target->output);
    return 0;
}
static BOOL iocp_paused_completion_cancel(void)
{
    SOCKET sender = INVALID_SOCKET, input = INVALID_SOCKET;
    SOCKET receiver = INVALID_SOCKET, output = INVALID_SOCKET;
    HANDLE owner = NULL, cancellers[2] = {0};
    CANCEL_TARGET target;
    BOOL ok = FALSE;
    if (!socket_pair(&sender, &input) || !socket_pair(&receiver, &output)) goto done;
    completionPaused = CreateEventW(NULL, TRUE, FALSE, NULL);
    completionResume = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!completionPaused || !completionResume) goto done;
    TRANSFER_CONFIG* config = malloc(sizeof(*config));
    if (!config) goto done;
    config->from_socket = input; config->to_socket = output;
    faultStage = 12; pauseClaim = 0;
    owner = CreateThread(NULL, 0, transfer_handler, config, 0, NULL);
    if (!owner) { free(config); goto done; }
    if (send_all(sender, "pause", 5) != 5 ||
        WaitForSingleObject(completionPaused, 2000) != WAIT_OBJECT_0) goto done;
    target.input = input; target.output = output;
    for (int i = 0; i < 2; i++) {
        cancellers[i] = CreateThread(NULL, 0, concurrent_cancel, &target, 0, NULL);
        if (!cancellers[i]) goto done;
    }
    if (WaitForMultipleObjects(2, cancellers, TRUE, 1000) != WAIT_OBJECT_0) goto done;
    // Cancellation is finished, but the paused completion must keep storage alive.
    if (WaitForSingleObject(owner, 0) != WAIT_TIMEOUT || livePairs != 1 ||
        liveEvents != 1 || liveRequests < 1) goto done;
    SetEvent(completionResume);
    if (WaitForSingleObject(owner, 2000) != WAIT_OBJECT_0) goto done;
    DWORD result;
    ok = GetExitCodeThread(owner, &result) && result == 1;
done:
    if (completionResume) SetEvent(completionResume);
    for (int i = 0; i < 2; i++) if (cancellers[i]) {
        if (WaitForSingleObject(cancellers[i], 3000) != WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(cancellers[i]);
    }
    if (owner) {
        stop_transfer(input, output);
        if (WaitForSingleObject(owner, 3000) != WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(owner);
    }
    if (completionPaused) CloseHandle(completionPaused);
    if (completionResume) CloseHandle(completionResume);
    completionPaused = completionResume = NULL;
    faultStage = 0;
    SOCKET sockets[] = {sender, input, receiver, output};
    for (int i = 0; i < 4; i++) if (sockets[i] != INVALID_SOCKET) closesocket(sockets[i]);
    return ok && !livePairs && !liveEvents && !liveRequests && !pairs;
}
