// Incremental SOCKS5/HTTP setup. Cache lookup behavior is unchanged; no DNS query.
static BOOL tcp_setup_domain(const CONNECTION_CONFIG* config, char domain[256])
{
    return config->proxy_snapshot.send_domain_to_proxy && (config->is_ipv6
        ? dns_cache_lookup_v6(config->orig_dest_ip6, domain, 256)
        : dns_cache_lookup(config->orig_dest_ip, domain, 256));
}
static void tcp_setup_request(PB_TCP_SETUP* setup)
{
    const CONNECTION_CONFIG* config = setup->config;
    unsigned char* data = (unsigned char*)setup->data;
    char domain[256]; DWORD length;
    data[0] = 5; data[1] = 1; data[2] = 0;
    if (tcp_setup_domain(config, domain)) {
        size_t n = strnlen_s(domain, sizeof(domain));
        if (!n || n > 255) { tcp_setup_cancel(setup); return; }
        data[3] = 3; data[4] = (unsigned char)n; memcpy(data + 5, domain, n); length = (DWORD)n + 7;
    } else if (config->is_ipv6) {
        data[3] = 4; memcpy(data + 4, config->orig_dest_ip6, 16); length = 22;
    } else {
        data[3] = 1; memcpy(data + 4, &config->orig_dest_ip, 4); length = 10;
    }
    data[length - 2] = (unsigned char)(config->orig_dest_port >> 8);
    data[length - 1] = (unsigned char)config->orig_dest_port;
    tcp_setup_transfer(setup, TCP_SETUP_REQUEST_SEND, TRUE, length);
}
static void tcp_setup_http_begin(PB_TCP_SETUP* setup)
{
    const CONNECTION_CONFIG* config = setup->config;
    const PROXY_CONFIG* proxy = &config->proxy_snapshot;
    char domain[256], host[270], ip6[64], credentials[SOCKS5_BUFFER_SIZE], encoded[HTTP_BUFFER_SIZE];
    if (tcp_setup_domain(config, domain)) strcpy_s(host, sizeof(host), domain);
    else if (config->is_ipv6) {
        if (!inet_ntop(AF_INET6, config->orig_dest_ip6, ip6, sizeof(ip6))) { tcp_setup_cancel(setup); return; }
        snprintf(host, sizeof(host), "[%s]", ip6);
    } else format_ip_address(config->orig_dest_ip, host, sizeof(host));
    int n;
    if (proxy->username[0]) {
        snprintf(credentials, sizeof(credentials), "%s:%s", proxy->username, proxy->password);
        base64_encode(credentials, encoded, sizeof(encoded));
        n = snprintf(setup->data, sizeof(setup->data),
            "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nProxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\n\r\n",
            host, config->orig_dest_port, host, config->orig_dest_port, encoded);
        SecureZeroMemory(credentials, sizeof(credentials)); SecureZeroMemory(encoded, sizeof(encoded));
    } else n = snprintf(setup->data, sizeof(setup->data),
        "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\nProxy-Connection: keep-alive\r\n\r\n",
        host, config->orig_dest_port, host, config->orig_dest_port);
    if (n <= 0 || n >= sizeof(setup->data)) { tcp_setup_cancel(setup); return; }
    tcp_setup_transfer(setup, TCP_SETUP_HTTP_SEND, TRUE, (DWORD)n);
}
static void tcp_setup_protocol_begin(PB_TCP_SETUP* setup)
{
    if (setup->config->proxy_snapshot.type == PROXY_TYPE_HTTP) { tcp_setup_http_begin(setup); return; }
    BOOL auth = setup->config->proxy_snapshot.username[0] != 0;
    setup->data[0] = 5; setup->data[1] = auth ? 2 : 1;
    setup->data[2] = 0; setup->data[3] = 2;
    tcp_setup_transfer(setup, TCP_SETUP_GREETING_SEND, TRUE, auth ? 4 : 3);
}
static void tcp_setup_http_reply(PB_TCP_SETUP* setup, DWORD previous)
{
    // Only new bytes plus the possible split delimiter: linear work even when
    // a peer supplies the entire maximum-size header one byte at a time.
    for (DWORD i = previous > 3 ? previous - 3 : 0; i + 3 < setup->used; ++i) {
        if (memcmp(setup->data + i, "\r\n\r\n", 4)) continue;
        // Strict status-line token, accepting the existing success code 200.
        // Parse only the header: binary tunnel bytes need no terminator.
        if (i < 12 || memcmp(setup->data, "HTTP/1.", 7) ||
            (setup->data[7] != '0' && setup->data[7] != '1') || setup->data[8] != ' ' ||
            memcmp(setup->data + 9, "200", 3) ||
            (setup->data[12] != ' ' && setup->data[12] != '\r')) { tcp_setup_cancel(setup); return; }
        DWORD header = i + 4;
        tcp_setup_handoff(setup, setup->data + header, setup->used - header);
        return;
    }
    if (setup->used == setup->length) tcp_setup_cancel(setup);
    else tcp_setup_submit(setup);
}
static void tcp_setup_protocol_next(PB_TCP_SETUP* setup)
{
    const PROXY_CONFIG* proxy = &setup->config->proxy_snapshot;
    unsigned char* data = (unsigned char*)setup->data;
    switch (setup->state) {
    case TCP_SETUP_GREETING_SEND:
        tcp_setup_transfer(setup, TCP_SETUP_GREETING_READ, FALSE, 2); break;
    case TCP_SETUP_GREETING_READ:
        if (data[0] != 5) { tcp_setup_cancel(setup); break; }
        if (data[1] == 0) { tcp_setup_request(setup); break; }
        if (data[1] != 2 || !proxy->username[0]) { tcp_setup_cancel(setup); break; }
        {
            size_t user = strnlen_s(proxy->username, sizeof(proxy->username));
            size_t pass = strnlen_s(proxy->password, sizeof(proxy->password));
            if (user > 255 || pass > 255) { tcp_setup_cancel(setup); break; }
            data[0] = 1; data[1] = (unsigned char)user;
            memcpy(data + 2, proxy->username, user); data[2 + user] = (unsigned char)pass;
            memcpy(data + 3 + user, proxy->password, pass);
            tcp_setup_transfer(setup, TCP_SETUP_AUTH_SEND, TRUE, (DWORD)(3 + user + pass));
        }
        break;
    case TCP_SETUP_AUTH_SEND:
        tcp_setup_transfer(setup, TCP_SETUP_AUTH_READ, FALSE, 2); break;
    case TCP_SETUP_AUTH_READ:
        if (data[0] != 1 || data[1] != 0) tcp_setup_cancel(setup);
        else tcp_setup_request(setup);
        break;
    case TCP_SETUP_REQUEST_SEND:
        tcp_setup_transfer(setup, TCP_SETUP_REPLY_HEADER, FALSE, 4); break;
    case TCP_SETUP_REPLY_HEADER:
        if (data[0] != 5 || data[1] != 0 || data[2] != 0) { tcp_setup_cancel(setup); break; }
        if (data[3] == 1 || data[3] == 4)
            tcp_setup_transfer(setup, TCP_SETUP_REPLY_DRAIN, FALSE, data[3] == 1 ? 6 : 18);
        else if (data[3] == 3) tcp_setup_transfer(setup, TCP_SETUP_REPLY_LENGTH, FALSE, 1);
        else tcp_setup_cancel(setup);
        break;
    case TCP_SETUP_REPLY_LENGTH:
        tcp_setup_transfer(setup, TCP_SETUP_REPLY_DRAIN, FALSE, (DWORD)data[0] + 2); break;
    case TCP_SETUP_REPLY_DRAIN:
        tcp_setup_handoff(setup, NULL, 0); break;
    case TCP_SETUP_HTTP_SEND:
        tcp_setup_transfer(setup, TCP_SETUP_HTTP_READ, FALSE, sizeof(setup->data) - 1); break;
    default:
        tcp_setup_cancel(setup); break;
    }
}
