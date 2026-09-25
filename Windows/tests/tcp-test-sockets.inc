static BOOL socket_pair(SOCKET *outside, SOCKET *inside)
{
    *outside = *inside = INVALID_SOCKET;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return FALSE;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int size = sizeof(address);
    BOOL ok = bind(listener, (struct sockaddr *)&address, size) == 0 &&
              listen(listener, 1) == 0 &&
              getsockname(listener, (struct sockaddr *)&address, &size) == 0;
    if (ok) {
        *outside = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok = *outside != INVALID_SOCKET &&
             connect(*outside, (struct sockaddr *)&address, size) == 0;
    }
    if (ok) { *inside = accept(listener, NULL, NULL); ok = *inside != INVALID_SOCKET; }
    closesocket(listener);
    if (!ok) {
        if (*outside != INVALID_SOCKET) closesocket(*outside);
        if (*inside != INVALID_SOCKET) closesocket(*inside);
        *outside = *inside = INVALID_SOCKET;
        return FALSE;
    }
    DWORD timeout = 2000;
    SOCKET sockets[] = {*outside, *inside};
    for (int i = 0; i < 2; ++i) {
        if (setsockopt(sockets[i], SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) ||
            setsockopt(sockets[i], SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)))
            return FALSE;
    }
    return TRUE;
}

static BOOL read_exact(SOCKET socket, const char *expected, int length)
{
    char buffer[256];
    int offset = 0;
    while (offset < length) {
        int received = recv(socket, buffer, min((int)sizeof(buffer), length - offset), 0);
        if (received <= 0 || memcmp(buffer, expected + offset, received)) return FALSE;
        offset += received;
    }
    return TRUE;
}

