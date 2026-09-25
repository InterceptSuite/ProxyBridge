// One-directional relay: reads from `from` and writes to `to`.
// Runs as a dedicated thread so upload and download never block each other.
// Uses a shared RELAY_PAIR reference count for safe socket cleanup:
//   - normal EOF forwards FIN to the destination while the other direction drains;
//     an error stops both directions. Core Stop also shuts down both sockets.
//   - the last direction frees RELAY_PAIR; the connection owner closes sockets
//     only after joining the upload thread.
DWORD WINAPI one_way_relay(LPVOID arg)
{
    ONE_WAY_CONFIG *cfg = (ONE_WAY_CONFIG *)arg;
    RELAY_PAIR *pair = cfg->pair;
    SOCKET from = cfg->from;
    SOCKET to   = cfg->to;
    free(cfg);

    int len = SOCKET_ERROR;
    char *buf = (char *)malloc(131072);  // 128 KB per-direction buffer
    if (buf)
    {
        while ((len = recv(from, buf, 131072, 0)) > 0)
        {
            if (send_all(to, buf, len) == SOCKET_ERROR)
                break;
        }
        free(buf);
    }

    // EOF closes only this direction. The peer may still be preparing a reply.
    // Allocation, receive, send or FIN propagation failure aborts the pair.
    if (len != 0 || shutdown(to, SD_SEND) == SOCKET_ERROR) {
        shutdown(pair->sock_client, SD_BOTH);
        shutdown(pair->sock_proxy, SD_BOTH);
    }

    // Last direction frees the shared pair; socket ownership stays with the caller.
    if (InterlockedDecrement(&pair->refs) == 0)
    {
        free(pair);
    }

    return 0;
}

// Bidirectional relay: spawns one thread for upload (client→proxy) and runs
// the download (proxy→client) direction in the calling thread.  Blocks until
// both directions have finished so the caller (connection_handler) can return
// cleanly and its thread handle can be closed.
DWORD WINAPI transfer_handler(LPVOID arg)
{
    TRANSFER_CONFIG *config = (TRANSFER_CONFIG *)arg;
    SOCKET sock_client = config->from_socket;
    SOCKET sock_proxy  = config->to_socket;
    free(config);

    RELAY_PAIR *pair = (RELAY_PAIR *)malloc(sizeof(RELAY_PAIR));
    if (!pair)
    {
        return 1;
    }
    pair->sock_client = sock_client;
    pair->sock_proxy  = sock_proxy;
    pair->refs        = 2;

    // Upload: client → proxy  (dedicated thread - may block on slow proxy send)
    ONE_WAY_CONFIG *up = (ONE_WAY_CONFIG *)malloc(sizeof(ONE_WAY_CONFIG));
    // Download: proxy → client (runs in this thread - loopback, rarely blocks)
    ONE_WAY_CONFIG *dn = (ONE_WAY_CONFIG *)malloc(sizeof(ONE_WAY_CONFIG));

    if (!up || !dn)
    {
        free(up);
        free(dn);
        free(pair);
        return 1;
    }

    up->pair = pair;  up->from = sock_client;  up->to = sock_proxy;
    dn->pair = pair;  dn->from = sock_proxy;   dn->to = sock_client;

    // Spawn the upload relay in its own thread.
    HANDLE upload_thread = CreateThread(NULL, 0, one_way_relay, up, 0, NULL);
    if (!upload_thread)
    {
        free(up);
        free(dn);
        free(pair);
        return 1;
    }

    // Run the download relay in this thread (blocks until done).
    one_way_relay(dn);

    // Wait for the upload relay thread to finish, then clean up its handle.
    WaitForSingleObject(upload_thread, INFINITE);
    CloseHandle(upload_thread);

    return 0;
}
