#include "pb_internal.h"

// Utilities: logging, string/IP helpers, token parsing, socket setup, base64.

#include "pb_logging.inc"

// Extract filename from full path  C:\path\chrome.exe  >> chrome.exe
const char* extract_filename(const char* path)
{
    if (!path) return "";
    const char* last_backslash = strrchr(path, '\\');
    const char* last_slash = strrchr(path, '/');
    const char* last_separator = (last_backslash > last_slash) ? last_backslash : last_slash;
    return last_separator ? (last_separator + 1) : path;
}

char* skip_whitespace(char *str)
{
    while (*str == ' ' || *str == '\t')
        str++;
    return str;
}

void format_ip_address(UINT32 ip, char *buffer, size_t size)
{
    snprintf(buffer, size, "%d.%d.%d.%d",
        (ip >> 0) & 0xFF, (ip >> 8) & 0xFF,
        (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

BOOL parse_token_list(const char *list, const char *delimiters, token_match_func match_func, const void *match_data)
{
    if (list == NULL || list[0] == '\0' || strcmp(list, "*") == 0)
        return TRUE;

    // strtok_s needs a writable copy. Use a stack buffer for the common (short) case and
    // only fall back to malloc for unusually long lists - avoids a heap alloc on the
    // packet thread for every rule that has a specific host/port filter.
    char   stackbuf[256];
    size_t len    = strnlen_s(list, MAX_LIST_SIZE) + 1;
    size_t dstsz  = len;
    char  *list_copy;
    BOOL   on_heap = FALSE;
    if (len <= sizeof(stackbuf))
    {
        list_copy = stackbuf;
        dstsz     = sizeof(stackbuf);
    }
    else
    {
        list_copy = (char *)malloc(len);
        if (list_copy == NULL)
            return FALSE;
        on_heap = TRUE;
    }

    strncpy_s(list_copy, dstsz, list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;
    char *token = strtok_s(list_copy, delimiters, &context);
    while (token != NULL)
    {
        token = skip_whitespace(token);
        if (match_func(token, match_data))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, delimiters, &context);
    }
    if (on_heap)
        free(list_copy);
    return matched;
}

void configure_tcp_socket(SOCKET sock, int bufsize, DWORD timeout)
{
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
}

// The caller owns this socket exclusively until connect finishes. Relay calls
// observe Stop every 100 ms; standalone checkers can use the non-cancellable API.
static int connect_bounded(SOCKET s, const struct sockaddr *addr, int addrlen,
                           int timeout_ms, BOOL cancelOnStop)
{
    if (timeout_ms <= 0) { WSASetLastError(WSAEINVAL); return SOCKET_ERROR; }
    if (cancelOnStop && !running) { WSASetLastError(WSAEINTR); return SOCKET_ERROR; }
    u_long nonblock = 1;
    if (ioctlsocket(s, FIONBIO, &nonblock) == SOCKET_ERROR) return SOCKET_ERROR;
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)timeout_ms;
    int error = 0;
    if (connect(s, addr, addrlen) == SOCKET_ERROR) {
        error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK) {
            for (;;) {
                if (cancelOnStop && !running) { error = WSAEINTR; break; }
                ULONGLONG now = GetTickCount64();
                if (now >= deadline) { error = WSAETIMEDOUT; break; }
                int waitMs = (int)(deadline - now);
                if (cancelOnStop && waitMs > 100) waitMs = 100;
                fd_set writes, errors;
                FD_ZERO(&writes); FD_SET(s, &writes);
                FD_ZERO(&errors); FD_SET(s, &errors);
                struct timeval timeout = { waitMs / 1000, (waitMs % 1000) * 1000 };
                int selected = select(0, NULL, &writes, &errors, &timeout);
                if (selected == SOCKET_ERROR) { error = WSAGetLastError(); break; }
                if (selected == 0) continue;
                int length = sizeof(error);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &length) == SOCKET_ERROR)
                    error = WSAGetLastError();
                else if (error == 0 && FD_ISSET(s, &errors))
                    error = WSAECONNABORTED;
                break;
            }
        }
    }
    if (error == 0 && cancelOnStop && !running) error = WSAEINTR;
    u_long blocking = 0;
    if (ioctlsocket(s, FIONBIO, &blocking) == SOCKET_ERROR && error == 0)
        error = WSAGetLastError();
    if (error != 0) { WSASetLastError(error); return SOCKET_ERROR; }
    return 0;
}

int connect_with_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, int timeout_ms)
{
    return connect_bounded(s, addr, addrlen, timeout_ms, FALSE);
}

int pb_connect_relay(SOCKET s, const struct sockaddr *addr, int addrlen, int timeout_ms)
{
    return connect_bounded(s, addr, addrlen, timeout_ms, TRUE);
}

void configure_udp_socket(SOCKET sock, int bufsize, DWORD timeout)
{
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

#ifdef _WIN32
    #ifndef SIO_UDP_CONNRESET
    #define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
    #endif
    BOOL bNewBehavior = FALSE;
    DWORD dwBytesReturned = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &dwBytesReturned, NULL, NULL);
#endif
}

int send_all(SOCKET sock, const char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n == SOCKET_ERROR) return SOCKET_ERROR;
        sent += n;
    }
    return sent;
}

// Read exactly n bytes, looping over partial TCP segments. SOCKS5/HTTP replies can be
// split across multiple segments (common on high-latency remote proxies); a single
// recv() may return fewer bytes than requested, so the fixed-length handshake reads
// must accumulate. Returns n on success, or SOCKET_ERROR on error / peer close.
int recv_n(SOCKET s, char *buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return SOCKET_ERROR;  // 0 = peer closed, <0 = error/timeout
        got += r;
    }
    return n;
}

UINT32 parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf_s(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}

// Resolve hostname to IPv4 address (supports both IP addresses and domain names)
UINT32 resolve_hostname(const char *hostname)
{
    if (hostname == NULL || hostname[0] == '\0')
        return 0;

    // First try to parse as IP address
    UINT32 ip = parse_ipv4(hostname);
    if (ip != 0)
        return ip;

    WSADATA wsa;
    int wsaError = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsaError != 0) { SetLastError((DWORD)wsaError); return 0; }

    // Not an IP address, try DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4 only
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
    {
        WSACleanup();
        log_message("Failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET)
    {
        if (result != NULL)
            freeaddrinfo(result);
        WSACleanup();
        log_message("No IPv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    UINT32 resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);
    WSACleanup();

    log_message("Resolved %s to %d.%d.%d.%d", hostname,
        (resolved_ip >> 0) & 0xFF, (resolved_ip >> 8) & 0xFF,
        (resolved_ip >> 16) & 0xFF, (resolved_ip >> 24) & 0xFF);

    return resolved_ip;
}

void base64_encode(const char* input, char* output, size_t output_size)
{
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Need >=5 bytes (one 4-char quantum + NUL). Guard first: the loop bound `output_size - 4`
    // is size_t math, so output_size < 4 would wrap to a huge value and overrun `output`.
    if (output == NULL || output_size == 0) return;
    if (output_size < 5) { output[0] = '\0'; return; }
    size_t input_len = strnlen_s(input, output_size * 2);
    size_t output_len = 0;

    for (size_t i = 0; i < input_len && output_len < output_size - 4; i += 3)
    {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;

        output[output_len++] = base64_chars[b1 >> 2];
        output[output_len++] = base64_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}


#include "pb_handshake_io.inc"
