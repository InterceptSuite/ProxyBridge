// Incremental association setup. Each call performs bounded nonblocking work;
// the relay schedules the next step while continuing to serve other sockets.
enum { UDP_IDLE, UDP_CONNECTING, UDP_GREETING_SEND, UDP_GREETING_RECV,
       UDP_AUTH_SEND, UDP_AUTH_RECV, UDP_REQUEST_SEND, UDP_REPLY_HEADER,
       UDP_REPLY_ADDRESS, UDP_READY };

short pb_udp_setup_events(const PB_UDP_ASSOCIATION *a)
{
    if (a->setup_phase == UDP_IDLE || a->setup_phase == UDP_READY) return 0;
    return a->setup_phase == UDP_CONNECTING || a->setup_phase == UDP_GREETING_SEND ||
           a->setup_phase == UDP_AUTH_SEND || a->setup_phase == UDP_REQUEST_SEND ?
           POLLWRNORM : POLLRDNORM;
}

static void udp_reset_transport(PB_UDP_ASSOCIATION *a)
{
    if (a->udp_tcp_ctrl != INVALID_SOCKET) closesocket(a->udp_tcp_ctrl);
    if (a->udp_send_sock != INVALID_SOCKET) closesocket(a->udp_send_sock);
    a->udp_tcp_ctrl = a->udp_send_sock = INVALID_SOCKET;
    a->udp_connected = FALSE;
    a->setup_phase = UDP_IDLE;
    a->setup_ready = FALSE;
}

void pb_udp_association_close(PB_UDP_ASSOCIATION *a)
{
    udp_reset_transport(a);
    pb_udp_queue_clear(&a->pending);
}

static void udp_setup_stage(PB_UDP_ASSOCIATION *a, int phase, int length)
{
    a->setup_phase = phase;
    a->setup_offset = 0;
    a->setup_length = length;
}

static void udp_setup_request(PB_UDP_ASSOCIATION *a)
{
    memset(a->setup_buffer, 0, 10);
    a->setup_buffer[0] = SOCKS5_VERSION;
    a->setup_buffer[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    a->setup_buffer[3] = SOCKS5_ATYP_IPV4;
    udp_setup_stage(a, UDP_REQUEST_SEND, 10);
}

BOOL establish_udp_associate(PB_UDP_ASSOCIATION *a)
{
    if (a == NULL) return FALSE;
    if (!running) { pb_udp_association_close(a); return FALSE; }
    if (a->udp_connected) return TRUE;
    const PROXY_CONFIG *cfg = &a->config;
    if (cfg->type != PROXY_TYPE_SOCKS5 || cfg->resolved_ip == 0 || cfg->port == 0)
        return FALSE;
    ULONGLONG now = GetTickCount64();
    if (a->setup_phase == UDP_IDLE || a->setup_phase == UDP_READY) {
        if (now - a->last_udp_attempt < 1000) return FALSE;
        // Preserve already queued datagrams while starting transport setup.
        udp_reset_transport(a);
        a->last_udp_attempt = now;
        a->udp_tcp_ctrl = socket(AF_INET, SOCK_STREAM, 0);
        if (a->udp_tcp_ctrl == INVALID_SOCKET) goto failed;
        configure_tcp_socket(a->udp_tcp_ctrl, 8192, 0); // control channel carries only setup/keepalive
        u_long nonblock = 1;
        if (ioctlsocket(a->udp_tcp_ctrl, FIONBIO, &nonblock) == SOCKET_ERROR) goto failed;
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = cfg->resolved_ip;
        addr.sin_port = htons(cfg->port);
        int result = connect(a->udp_tcp_ctrl, (struct sockaddr *)&addr, sizeof(addr));
        if (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) goto failed;
        a->setup_phase = UDP_CONNECTING;
        a->setup_deadline = now + 2000;
    }
    if (now >= a->setup_deadline) goto failed;
    for (int step = 0; step < 8; ++step) {
        if (a->setup_phase == UDP_CONNECTING) {
            fd_set writes, errors;
            FD_ZERO(&writes); FD_SET(a->udp_tcp_ctrl, &writes);
            FD_ZERO(&errors); FD_SET(a->udp_tcp_ctrl, &errors);
            struct timeval zero = {0, 0};
            int selected = select(0, NULL, &writes, &errors, &zero);
            if (selected == SOCKET_ERROR) goto failed;
            if (selected == 0) return FALSE;
            int error = 0, length = sizeof(error);
            if (getsockopt(a->udp_tcp_ctrl, SOL_SOCKET, SO_ERROR, (char *)&error, &length) == SOCKET_ERROR ||
                error != 0 || FD_ISSET(a->udp_tcp_ctrl, &errors)) goto failed;
            a->setup_deadline = GetTickCount64() + 3000;
            a->setup_buffer[0] = SOCKS5_VERSION;
            a->setup_buffer[1] = cfg->username[0] ? 2 : 1;
            a->setup_buffer[2] = SOCKS5_AUTH_NONE;
            a->setup_buffer[3] = 2;
            udp_setup_stage(a, UDP_GREETING_SEND, cfg->username[0] ? 4 : 3);
        }
        BOOL writing = a->setup_phase == UDP_GREETING_SEND ||
                       a->setup_phase == UDP_AUTH_SEND || a->setup_phase == UDP_REQUEST_SEND;
        char *buffer = (char *)a->setup_buffer + a->setup_offset;
        int remaining = a->setup_length - a->setup_offset;
        int count = writing ? send(a->udp_tcp_ctrl, buffer, remaining, 0)
                            : recv(a->udp_tcp_ctrl, buffer, remaining, 0);
        if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) return FALSE;
        if (count <= 0) goto failed;
        a->setup_offset += count;
        if (a->setup_offset < a->setup_length) continue;
        switch (a->setup_phase) {
        case UDP_GREETING_SEND: udp_setup_stage(a, UDP_GREETING_RECV, 2); break;
        case UDP_GREETING_RECV:
            if (a->setup_buffer[0] != SOCKS5_VERSION) goto failed;
            if (a->setup_buffer[1] == SOCKS5_AUTH_NONE) { udp_setup_request(a); break; }
            if (a->setup_buffer[1] != 2 || cfg->username[0] == 0) goto failed;
            {
                size_t ul = strnlen_s(cfg->username, sizeof(cfg->username));
                size_t pl = strnlen_s(cfg->password, sizeof(cfg->password));
                if (ul > 255 || pl > 255) goto failed;
                a->setup_buffer[0] = 1; a->setup_buffer[1] = (unsigned char)ul;
                memcpy(a->setup_buffer + 2, cfg->username, ul);
                a->setup_buffer[2 + ul] = (unsigned char)pl;
                memcpy(a->setup_buffer + 3 + ul, cfg->password, pl);
                udp_setup_stage(a, UDP_AUTH_SEND, (int)(3 + ul + pl));
            }
            break;
        case UDP_AUTH_SEND: udp_setup_stage(a, UDP_AUTH_RECV, 2); break;
        case UDP_AUTH_RECV:
            if (a->setup_buffer[0] != 1 || a->setup_buffer[1] != 0) goto failed;
            udp_setup_request(a); break;
        case UDP_REQUEST_SEND: udp_setup_stage(a, UDP_REPLY_HEADER, 4); break;
        case UDP_REPLY_HEADER:
            if (a->setup_buffer[0] != SOCKS5_VERSION || a->setup_buffer[1] != 0 ||
                a->setup_buffer[2] != 0 || a->setup_buffer[3] != SOCKS5_ATYP_IPV4) goto failed;
            udp_setup_stage(a, UDP_REPLY_ADDRESS, 6); break;
        case UDP_REPLY_ADDRESS: {
            memset(&a->udp_relay_addr, 0, sizeof(a->udp_relay_addr));
            a->udp_relay_addr.sin_family = AF_INET;
            memcpy(&a->udp_relay_addr.sin_addr.s_addr, a->setup_buffer, 4);
            memcpy(&a->udp_relay_addr.sin_port, a->setup_buffer + 4, 2);
            if (a->udp_relay_addr.sin_port == 0) goto failed;
            if (a->udp_relay_addr.sin_addr.s_addr == INADDR_ANY)
                a->udp_relay_addr.sin_addr.s_addr = cfg->resolved_ip;
            a->udp_send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (a->udp_send_sock == INVALID_SOCKET) goto failed;
            configure_udp_socket(a->udp_send_sock, 65536, 0); // bounded per-client kernel buffer request
            u_long nonblock = 1;
            if (ioctlsocket(a->udp_send_sock, FIONBIO, &nonblock) == SOCKET_ERROR) goto failed;
            BOOL on = TRUE;
            setsockopt(a->udp_tcp_ctrl, SOL_SOCKET, SO_KEEPALIVE, (const char *)&on, sizeof(on));
            struct tcp_keepalive ka = {1, 10000, 2000};
            DWORD bytes;
            WSAIoctl(a->udp_tcp_ctrl, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes, NULL, NULL);
            a->setup_phase = UDP_READY;
            a->udp_connected = TRUE;
            return TRUE;
        }
        default: goto failed;
        }
    }
    return FALSE;
failed:
    pb_udp_association_close(a);
    return FALSE;
}
