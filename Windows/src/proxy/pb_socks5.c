#include "pb_internal.h"

// SOCKS5: CONNECT (IPv4/IPv6/domain) and UDP ASSOCIATE.

// Read and validate a SOCKS5 CONNECT reply accoring to RFC 1928
// Goal -  The proxy picks the BND.ADDR
// type in its reply  seperatly of the request's ATYP few proxies answer an IPv6 CONNECT with a 4-byte IPv4 0.0.0.0 BND.addr
//  parse the 4-byte header
// (VER REP RSV ATYP) and then drain the variable-length BND.ADDR + BND.PORT by ATYP
int socks5_read_connect_reply(SOCKET s, int *reply)
{
    unsigned char hdr[4];
    int len = recv_n(s, (char*)hdr, 4);
    if (reply) *reply = (len >= 2) ? hdr[1] : -1;
    if (len != 4 || hdr[0] != SOCKS5_VERSION || hdr[1] != 0x00) return -1;

    int drain;
    if      (hdr[3] == SOCKS5_ATYP_IPV4) drain = 4 + 2;
    else if (hdr[3] == SOCKS5_ATYP_IPV6) drain = 16 + 2;
    else if (hdr[3] == SOCKS5_ATYP_DOMAIN)
    {
        unsigned char dlen;
        if (recv_n(s, (char*)&dlen, 1) != 1) return -1;
        drain = (int)dlen + 2;
    }
    else return -1;   // unknown ATYP

    unsigned char scratch[270];   // max drain = 255 + 2 (domain) < 270
    if (drain > 0 && recv_n(s, (char*)scratch, drain) != drain) return -1;
    return 0;
}

// SOCKS5 CONNECT with ATYP_DOMAIN

int socks5_connect_domain(SOCKET s, const char *hostname, UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth) { buf[1] = 0x02; buf[2] = SOCKS5_AUTH_NONE; buf[3] = 0x02; if (send(s, (char*)buf, 4, 0) != 4) return -1; }
    else          { buf[1] = 0x01; buf[2] = SOCKS5_AUTH_NONE;                 if (send(s, (char*)buf, 3, 0) != 3) return -1; }

    len = recv_n(s, (char*)buf, 2);
    if (len != 2 || buf[0] != SOCKS5_VERSION) return -1;

    if (buf[1] == 0x02)
    {
        if (!use_auth) return -1;
        size_t user_len = strnlen_s(cfg->username, sizeof(cfg->username));
        size_t pass_len = strnlen_s(cfg->password, sizeof(cfg->password));
        if (user_len > 255 || pass_len > 255) return -1;
        buf[0] = 0x01; buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], cfg->username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], cfg->password, pass_len);
        if (send(s, (char*)buf, (int)(3 + user_len + pass_len), 0) != (int)(3 + user_len + pass_len)) return -1;
        len = recv_n(s, (char*)buf, 2);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00) return -1;
    }
    else if (buf[1] != SOCKS5_AUTH_NONE) return -1;

    // Build CONNECT request with ATYP_DOMAIN
    size_t hlen = strnlen_s(hostname, 255);
    if (hlen == 0 || hlen > 255) return -1;

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_DOMAIN;
    buf[4] = (unsigned char)hlen;
    memcpy(&buf[5], hostname, hlen);
    buf[5 + hlen] = (dest_port >> 8) & 0xFF;
    buf[6 + hlen] = (dest_port >> 0) & 0xFF;
    int req_len = (int)(7 + hlen);

    if (send(s, (char*)buf, req_len, 0) != req_len) return -1;

    int reply;
    if (socks5_read_connect_reply(s, &reply) != 0)
    {
        log_message("SOCKS5 domain: CONNECT failed (reply=%d)", reply);
        return -1;
    }
    return 0;
}

int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;  // Username/password auth
        if (send(s, (char*)buf, 4, 0) != 4)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }
    else
    {
        buf[1] = 0x01;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }

    len = recv_n(s, (char*)buf, 2);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
    {
        log_message("SOCKS5: Invalid auth response");
        return -1;
    }

    // Handle authentication
    if (buf[1] == 0x02)  // Username/password required
    {
        if (!use_auth)
        {
            log_message("SOCKS5: Server requires authentication but no credentials provided");
            return -1;
        }

        // Send username/password (RFC 1929)
        size_t user_len = strnlen_s(cfg->username, sizeof(cfg->username));
        size_t pass_len = strnlen_s(cfg->password, sizeof(cfg->password));
        if (user_len > 255 || pass_len > 255)
        {
            log_message("SOCKS5: Username or password too long");
            return -1;
        }

        buf[0] = 0x01;  // Version of username/password auth
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], cfg->username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], cfg->password, pass_len);

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len))
        {
            log_message("SOCKS5: Failed to send credentials");
            return -1;
        }

        len = recv_n(s, (char*)buf, 2);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
        {
            log_message("SOCKS5: Authentication failed");
            return -1;
        }
        log_message("SOCKS5: Authentication successful");
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        log_message("SOCKS5: Unsupported auth method: 0x%02X", buf[1]);
        return -1;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = (dest_ip >> 0) & 0xFF;
    buf[5] = (dest_ip >> 8) & 0xFF;
    buf[6] = (dest_ip >> 16) & 0xFF;
    buf[7] = (dest_ip >> 24) & 0xFF;
    buf[8] = (dest_port >> 8) & 0xFF;
    buf[9] = (dest_port >> 0) & 0xFF;

    if (send(s, (char*)buf, 10, 0) != 10)
    {
        log_message("SOCKS5: Failed to send CONNECT");
        return -1;
    }

    int reply;
    if (socks5_read_connect_reply(s, &reply) != 0)
    {
        log_message("SOCKS5: CONNECT failed (reply=%d)", reply);
        return -1;
    }

    return 0;
}

int socks5_connect_v6(SOCKET s, const UINT8 dest_ip6[16], UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth) { buf[1] = 0x02; buf[2] = SOCKS5_AUTH_NONE; buf[3] = 0x02; if (send(s, (char*)buf, 4, 0) != 4) return -1; }
    else          { buf[1] = 0x01; buf[2] = SOCKS5_AUTH_NONE;                 if (send(s, (char*)buf, 3, 0) != 3) return -1; }

    len = recv_n(s, (char*)buf, 2);
    if (len != 2 || buf[0] != SOCKS5_VERSION) return -1;

    if (buf[1] == 0x02)
    {
        if (!use_auth) return -1;
        size_t ul = strnlen_s(cfg->username, sizeof(cfg->username));
        size_t pl = strnlen_s(cfg->password, sizeof(cfg->password));
        if (ul > 255 || pl > 255) return -1;
        buf[0] = 0x01; buf[1] = (unsigned char)ul;
        memcpy(&buf[2], cfg->username, ul);
        buf[2 + ul] = (unsigned char)pl;
        memcpy(&buf[3 + ul], cfg->password, pl);
        if (send(s, (char*)buf, (int)(3 + ul + pl), 0) != (int)(3 + ul + pl)) return -1;
        len = recv_n(s, (char*)buf, 2);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00) return -1;
    }
    else if (buf[1] != SOCKS5_AUTH_NONE) return -1;

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV6;
    memcpy(&buf[4], dest_ip6, 16);
    buf[20] = (dest_port >> 8) & 0xFF;
    buf[21] = (dest_port >> 0) & 0xFF;

    if (send(s, (char*)buf, 22, 0) != 22) return -1;

    // The proxy may reply with any BND.ADDR type (often IPv4 0.0.0.0), not necessarily
    // IPv6 - so parse the reply by ATYP instead of demanding a fixed 22-byte response.
    int reply;
    if (socks5_read_connect_reply(s, &reply) != 0)
    {
        log_message("SOCKS5 IPv6: CONNECT failed (reply=%d)", reply);
        return -1;
    }
    return 0;
}

int socks5_udp_associate_with_config(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG *cfg)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth)
    {
        buf[1] = 0x02;
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02;
        if (send(s, (char*)buf, 4, 0) != 4)
            return -1;
    }
    else
    {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3)
            return -1;
    }

    len = recv_n(s, (char*)buf, 2);
    if (len != 2 || buf[0] != SOCKS5_VERSION)
        return -1;

    if (buf[1] == 0x02)
    {
        if (!use_auth)
            return -1;

        size_t user_len = strnlen_s(cfg->username, sizeof(cfg->username));
        size_t pass_len = strnlen_s(cfg->password, sizeof(cfg->password));
        if (user_len > 255 || pass_len > 255)
            return -1;

        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], cfg->username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], cfg->password, pass_len);

        if (send(s, (char*)buf, 3 + user_len + pass_len, 0) != (int)(3 + user_len + pass_len))
            return -1;

        len = recv_n(s, (char*)buf, 2);
        if (len != 2 || buf[0] != 0x01 || buf[1] != 0x00)
            return -1;
    }
    else if (buf[1] != SOCKS5_AUTH_NONE)
    {
        return -1;
    }

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 0;
    buf[8] = 0;
    buf[9] = 0;

    if (send(s, (char*)buf, 10, 0) != 10)
        return -1;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT. The proxy picks the BND.ADDR type
    // independently (RFC 1928), and the reply can split across TCP segments - so read
    // the 4-byte header first, then the bound endpoint by ATYP. We relay UDP over IPv4,
    // so an IPv4 bound endpoint is required (0.0.0.0 is handled by the caller).
    unsigned char rep[4];
    if (recv_n(s, (char*)rep, 4) != 4 || rep[0] != SOCKS5_VERSION || rep[1] != 0x00)
        return -1;
    if (rep[3] != SOCKS5_ATYP_IPV4)
        return -1;   // non-IPv4 relay endpoint can't be used by the IPv4 UDP send socket
    unsigned char ap[6];
    if (recv_n(s, (char*)ap, 6) != 6)
        return -1;

    relay_addr->sin_family = AF_INET;
    memcpy(&relay_addr->sin_addr.s_addr, ap, 4);
    memcpy(&relay_addr->sin_port, ap + 4, 2);

    return 0;
}

// connect UDP ASSOCIATE with SOCKS5 proxy (per proxy config)
BOOL establish_udp_associate_for_config(PROXY_CONFIG *cfg)
{
    if (cfg == NULL || cfg->host[0] == '\0' || cfg->port == 0)
        return FALSE;
    if (cfg->type != PROXY_TYPE_SOCKS5)
        return FALSE;

    // Prevent retry spam - only try every 1 second per config
    ULONGLONG now = GetTickCount64();
    if (now - cfg->last_udp_attempt < 1000)
    {
        log_message("[UDP ASSOC] Retry guard active for %s:%d, skipping", cfg->host, cfg->port);
        return FALSE;
    }

    cfg->last_udp_attempt = now;

    // Close existing connections if any
    if (cfg->udp_tcp_ctrl != INVALID_SOCKET)
    {
        closesocket(cfg->udp_tcp_ctrl);
        cfg->udp_tcp_ctrl = INVALID_SOCKET;
    }
    if (cfg->udp_send_sock != INVALID_SOCKET)
    {
        closesocket(cfg->udp_send_sock);
        cfg->udp_send_sock = INVALID_SOCKET;
    }

    // Create TCP control connection
    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET)
        return FALSE;

    configure_tcp_socket(tcp_sock, 262144, 3000);

    UINT32 socks5_ip = resolve_hostname(cfg->host);
    if (socks5_ip == 0)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = socks5_ip;
    socks_addr.sin_port = htons(cfg->port);

    // Bounded connect: a dead/unreachable proxy config fails in ~2s instead of stalling
    // the single-threaded relay for the full OS SYN timeout (~21s), which was delaying
    // real packets that use a *different*, working proxy config.
    if (connect_with_timeout(tcp_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr), 2000) == SOCKET_ERROR)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    if (socks5_udp_associate_with_config(tcp_sock, &cfg->udp_relay_addr, cfg) != 0)
    {
        closesocket(tcp_sock);
        return FALSE;
    }

    // Many SOCKS5 servers return 0.0.0.0 as BND.ADDR in
    // the UDP ASSOCIATE reply as per RFC 1928 says "use the same address
    // as the TCP control connection".  sendto(0.0.0.0:PORT) fails with
    // WSAEADDRNOTAVAIL (10049), so replace it with the proxy's resolved IP.
    if (cfg->udp_relay_addr.sin_addr.s_addr == INADDR_ANY)
        cfg->udp_relay_addr.sin_addr.s_addr = socks5_ip;

    // haandshake completed remove the 3second timeout so the control socket stays open indefinitely
    // keepalives below will detect actual disconnection.
    DWORD zero_timeout = 0;
    setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&zero_timeout, sizeof(zero_timeout));
    setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&zero_timeout, sizeof(zero_timeout));

    // we can enable TCP keepalives so the SOCKS5 proxy dont idleclose the control
    // connection (few proxies terminate it after 60 second of silence, killing UDP ASSOCIATE).
    BOOL ka_on = TRUE;
    setsockopt(tcp_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&ka_on, sizeof(ka_on));
    struct tcp_keepalive ka = { 1, 10000, 2000 }; // idle 10s, retry every 2s
    DWORD ka_bytes;
    WSAIoctl(tcp_sock, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &ka_bytes, NULL, NULL);

    cfg->udp_tcp_ctrl = tcp_sock;

    // create UDP socket for sending to SOCKS5 proxy
    cfg->udp_send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (cfg->udp_send_sock == INVALID_SOCKET)
    {
        closesocket(cfg->udp_tcp_ctrl);
        cfg->udp_tcp_ctrl = INVALID_SOCKET;
        cfg->udp_connected = FALSE;
        return FALSE;
    }

    configure_udp_socket(cfg->udp_send_sock, 262144, 30000);

    cfg->udp_connected = TRUE;
    log_message("UDP ASSOCIATE established with SOCKS5 proxy %s:%d (UDP relay at %s:%d)",
        cfg->host, cfg->port,
        inet_ntoa(cfg->udp_relay_addr.sin_addr), ntohs(cfg->udp_relay_addr.sin_port));
    return TRUE;
}

