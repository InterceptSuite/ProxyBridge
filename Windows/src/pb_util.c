#include "pb_internal.h"

// Utilities: logging, string/IP helpers, token parsing, socket setup, base64.

void log_message(const char *msg, ...)
{
    if (g_log_callback == NULL) return;
    char buffer[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    g_log_callback(buffer);
}

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

// connect() with a bounded timeout. A blocking connect() to an unreachable host stalls
// for the OS SYN timeout (~21s on Windows), and the UDP relay runs on a single thread -
// so one dead/unreachable proxy config would freeze the whole relay (and delay real
// packets) while it waits. This does a non-blocking connect + select so a dead proxy
// fails in `timeout_ms` instead. Returns 0 on success, SOCKET_ERROR otherwise.
int connect_with_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, int timeout_ms)
{
    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    int result = 0;
    if (connect(s, addr, addrlen) == SOCKET_ERROR)
    {
        if (WSAGetLastError() != WSAEWOULDBLOCK)
        {
            result = SOCKET_ERROR;
        }
        else
        {
            fd_set wfds, efds;
            FD_ZERO(&wfds); FD_SET(s, &wfds);
            FD_ZERO(&efds); FD_SET(s, &efds);
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            int sel = select(0, NULL, &wfds, &efds, &tv);
            if (sel <= 0 || FD_ISSET(s, &efds))
            {
                result = SOCKET_ERROR;   // timed out or connect failed
            }
            else
            {
                int so_err = 0;
                int errlen = sizeof(so_err);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_err, &errlen);
                if (so_err != 0)
                    result = SOCKET_ERROR;
            }
        }
    }

    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);   // restore blocking for the handshake reads
    return result;
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

    // Not an IP address, try DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4 only
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0)
    {
        log_message("Failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET)
    {
        if (result != NULL)
            freeaddrinfo(result);
        log_message("No IPv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    UINT32 resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);

    log_message("Resolved %s to %d.%d.%d.%d", hostname,
        (resolved_ip >> 0) & 0xFF, (resolved_ip >> 8) & 0xFF,
        (resolved_ip >> 16) & 0xFF, (resolved_ip >> 24) & 0xFF);

    return resolved_ip;
}

void base64_encode(const char* input, char* output, size_t output_size)
{
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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

