#include "pb_internal.h"

// SOCKS5: CONNECT (IPv4/IPv6/domain) and UDP ASSOCIATE.

// Read and validate a SOCKS5 CONNECT reply accoring to RFC 1928
// Goal -  The proxy picks the BND.ADDR
// type in its reply  seperatly of the request's ATYP few proxies answer an IPv6 CONNECT with a 4-byte IPv4 0.0.0.0 BND.addr
//  parse the 4-byte header
// (VER REP RSV ATYP) and then drain the variable-length BND.ADDR + BND.PORT by ATYP
int socks5_read_connect_reply(SOCKET s, int *reply, const PB_HANDSHAKE_CONTEXT* context)
{
    unsigned char hdr[4];
    int len = pb_handshake_io(s, (char*)hdr, 4, FALSE, TRUE, context);
    if (reply) *reply = (len >= 2) ? hdr[1] : -1;
    if (len != 4 || hdr[0] != SOCKS5_VERSION || hdr[1] != 0x00) return -1;

    int drain;
    if      (hdr[3] == SOCKS5_ATYP_IPV4) drain = 4 + 2;
    else if (hdr[3] == SOCKS5_ATYP_IPV6) drain = 16 + 2;
    else if (hdr[3] == SOCKS5_ATYP_DOMAIN)
    {
        unsigned char dlen;
        if (pb_handshake_io(s, (char*)&dlen, 1, FALSE, TRUE, context) != 1) return -1;
        drain = (int)dlen + 2;
    }
    else return -1;   // unknown ATYP

    unsigned char scratch[270];   // max drain = 255 + 2 (domain) < 270
    if (drain > 0 && pb_handshake_io(s, (char*)scratch, drain, FALSE, TRUE, context) != drain) return -1;
    return 0;
}

// SOCKS5 CONNECT with ATYP_DOMAIN

int socks5_connect_domain(SOCKET s, const char *hostname, UINT16 dest_port, const PROXY_CONFIG *cfg, const PB_HANDSHAKE_CONTEXT* context)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth) { buf[1] = 0x02; buf[2] = SOCKS5_AUTH_NONE; buf[3] = 0x02; if (pb_handshake_io(s, (char*)buf, 4, TRUE, TRUE, context) != 4) return -1; }
    else          { buf[1] = 0x01; buf[2] = SOCKS5_AUTH_NONE;                 if (pb_handshake_io(s, (char*)buf, 3, TRUE, TRUE, context) != 3) return -1; }

    len = pb_handshake_io(s, (char*)buf, 2, FALSE, TRUE, context);
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
        if (pb_handshake_io(s, (char*)buf, (int)(3 + user_len + pass_len), TRUE, TRUE, context) != (int)(3 + user_len + pass_len)) return -1;
        len = pb_handshake_io(s, (char*)buf, 2, FALSE, TRUE, context);
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

    if (pb_handshake_io(s, (char*)buf, req_len, TRUE, TRUE, context) != req_len) return -1;

    int reply;
    if (socks5_read_connect_reply(s, &reply, context) != 0)
    {
        log_message("SOCKS5 domain: CONNECT failed (reply=%d)", reply);
        return -1;
    }
    return 0;
}

int socks5_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg, const PB_HANDSHAKE_CONTEXT* context)
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
        if (pb_handshake_io(s, (char*)buf, 4, TRUE, TRUE, context) != 4)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }
    else
    {
        buf[1] = 0x01;  // Number of methods
        buf[2] = SOCKS5_AUTH_NONE;
        if (pb_handshake_io(s, (char*)buf, 3, TRUE, TRUE, context) != 3)
        {
            log_message("SOCKS5: Failed to send auth methods");
            return -1;
        }
    }

    len = pb_handshake_io(s, (char*)buf, 2, FALSE, TRUE, context);
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

        if (pb_handshake_io(s, (char*)buf, (int)(3 + user_len + pass_len), TRUE, TRUE, context) != (int)(3 + user_len + pass_len))
        {
            log_message("SOCKS5: Failed to send credentials");
            return -1;
        }

        len = pb_handshake_io(s, (char*)buf, 2, FALSE, TRUE, context);
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

    if (pb_handshake_io(s, (char*)buf, 10, TRUE, TRUE, context) != 10)
    {
        log_message("SOCKS5: Failed to send CONNECT");
        return -1;
    }

    int reply;
    if (socks5_read_connect_reply(s, &reply, context) != 0)
    {
        log_message("SOCKS5: CONNECT failed (reply=%d)", reply);
        return -1;
    }

    return 0;
}

int socks5_connect_v6(SOCKET s, const UINT8 dest_ip6[16], UINT16 dest_port, const PROXY_CONFIG *cfg, const PB_HANDSHAKE_CONTEXT* context)
{
    unsigned char buf[SOCKS5_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth) { buf[1] = 0x02; buf[2] = SOCKS5_AUTH_NONE; buf[3] = 0x02; if (pb_handshake_io(s, (char*)buf, 4, TRUE, TRUE, context) != 4) return -1; }
    else          { buf[1] = 0x01; buf[2] = SOCKS5_AUTH_NONE;                 if (pb_handshake_io(s, (char*)buf, 3, TRUE, TRUE, context) != 3) return -1; }

    len = pb_handshake_io(s, (char*)buf, 2, FALSE, TRUE, context);
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
        if (pb_handshake_io(s, (char*)buf, (int)(3 + ul + pl), TRUE, TRUE, context) != (int)(3 + ul + pl)) return -1;
        len = pb_handshake_io(s, (char*)buf, 2, FALSE, TRUE, context);
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

    if (pb_handshake_io(s, (char*)buf, 22, TRUE, TRUE, context) != 22) return -1;

    // The proxy may reply with any BND.ADDR type (often IPv4 0.0.0.0), not necessarily
    // IPv6 - so parse the reply by ATYP instead of demanding a fixed 22-byte response.
    int reply;
    if (socks5_read_connect_reply(s, &reply, context) != 0)
    {
        log_message("SOCKS5 IPv6: CONNECT failed (reply=%d)", reply);
        return -1;
    }
    return 0;
}

// Nonblocking control-socket I/O with a deadline shared by the entire handshake.
// This runs only during association setup, not in the UDP packet path.
static int udp_handshake_io(SOCKET s, char *buffer, int length, BOOL write,
                            ULONGLONG deadline, BOOL cancelOnStop)
{
    int done = 0;
    while (done < length) {
        if (cancelOnStop && !running) { WSASetLastError(WSAEINTR); return -1; }
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) { WSASetLastError(WSAETIMEDOUT); return -1; }
        int count = write ? send(s, buffer + done, length - done, 0)
                          : recv(s, buffer + done, length - done, 0);
        if (count > 0) { done += count; continue; }
        if (count == 0) { WSASetLastError(WSAECONNRESET); return -1; }
        if (WSAGetLastError() != WSAEWOULDBLOCK) return -1;
        now = GetTickCount64();
        if (now >= deadline) { WSASetLastError(WSAETIMEDOUT); return -1; }
        int waitMs = (int)(deadline - now);
        if (cancelOnStop && waitMs > 100) waitMs = 100;
        fd_set ready;
        FD_ZERO(&ready); FD_SET(s, &ready);
        struct timeval timeout = { waitMs / 1000, (waitMs % 1000) * 1000 };
        if (select(0, write ? NULL : &ready, write ? &ready : NULL, NULL, &timeout) == SOCKET_ERROR)
            return -1;
    }
    return length;
}

static int udp_associate_exchange(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG *cfg,
                                  ULONGLONG deadline, BOOL cancelOnStop)
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
        if (udp_handshake_io(s, (char*)buf, (int)(4), TRUE, deadline, cancelOnStop) != 4)
            return -1;
    }
    else
    {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (udp_handshake_io(s, (char*)buf, (int)(3), TRUE, deadline, cancelOnStop) != 3)
            return -1;
    }

    len = udp_handshake_io(s, (char*)buf, 2, FALSE, deadline, cancelOnStop);
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

        if (udp_handshake_io(s, (char*)buf, (int)(3 + user_len + pass_len), TRUE, deadline, cancelOnStop) != (int)(3 + user_len + pass_len))
            return -1;

        len = udp_handshake_io(s, (char*)buf, 2, FALSE, deadline, cancelOnStop);
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

    if (udp_handshake_io(s, (char*)buf, (int)(10), TRUE, deadline, cancelOnStop) != 10)
        return -1;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT. The proxy picks the BND.ADDR type
    // independently (RFC 1928), and the reply can split across TCP segments - so read
    // the 4-byte header first, then the bound endpoint by ATYP. We relay UDP over IPv4,
    // so an IPv4 bound endpoint is required (0.0.0.0 is handled by the caller).
    unsigned char rep[4];
    if (udp_handshake_io(s, (char*)rep, 4, FALSE, deadline, cancelOnStop) != 4 || rep[0] != SOCKS5_VERSION || rep[1] != 0x00)
        return -1;
    if (rep[3] != SOCKS5_ATYP_IPV4)
        return -1;   // non-IPv4 relay endpoint can't be used by the IPv4 UDP send socket
    unsigned char ap[6];
    if (udp_handshake_io(s, (char*)ap, 6, FALSE, deadline, cancelOnStop) != 6)
        return -1;

    relay_addr->sin_family = AF_INET;
    memcpy(&relay_addr->sin_addr.s_addr, ap, 4);
    memcpy(&relay_addr->sin_port, ap + 4, 2);

    return 0;
}

static int udp_associate_bounded(SOCKET s, struct sockaddr_in *relay_addr,
                                 const PROXY_CONFIG *cfg, BOOL cancelOnStop)
{
    u_long nonblock = 1;
    if (ioctlsocket(s, FIONBIO, &nonblock) == SOCKET_ERROR) return -1;
    int result = udp_associate_exchange(s, relay_addr, cfg, GetTickCount64() + 3000, cancelOnStop);
    int error = result == 0 ? 0 : WSAGetLastError();
    u_long blocking = 0;
    if (ioctlsocket(s, FIONBIO, &blocking) == SOCKET_ERROR && result == 0) {
        result = -1;
        error = WSAGetLastError();
    }
    if (result != 0) WSASetLastError(error);
    return result;
}

int socks5_udp_associate_with_config(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG *cfg)
{
    // Standalone checker is valid while capture is stopped.
    return udp_associate_bounded(s, relay_addr, cfg, FALSE);
}

#include "pb_udp_setup.inc"
