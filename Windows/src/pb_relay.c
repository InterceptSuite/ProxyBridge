#include "pb_internal.h"

// Relay: TCP/UDP relay servers and per-connection worker threads.

DWORD WINAPI udp_relay_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in local_addr = {0}, from_addr = {0};
    unsigned char recv_buf[MAXBUF];
    unsigned char send_buf[MAXBUF];
    int recv_len, from_len = 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return 1;

    udp_relay_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket == INVALID_SOCKET)
    {
        WSACleanup();
        return 1;
    }

    int on = 1;
    setsockopt(udp_relay_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    configure_udp_socket(udp_relay_socket, 262144, 30000);

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // must be any WinDivert swaps src/dst IPs for
    local_addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);// tracked connections so packets arrive at the
                                                      // machines real ip and not 127.0.0.1

    if (bind(udp_relay_socket, (struct sockaddr *)&local_addr, sizeof(local_addr)) == SOCKET_ERROR)
    {
        closesocket(udp_relay_socket);
        udp_relay_socket = INVALID_SOCKET;
        WSACleanup();
        return 1;
    }

    // IPv6 UDP relay socket on ::1:34011
    udp_relay_socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket6 != INVALID_SOCKET)
    {
        int v6only = 1;
        setsockopt(udp_relay_socket6, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));
        setsockopt(udp_relay_socket6, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
        configure_udp_socket(udp_relay_socket6, 262144, 30000);
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof(a6));
        a6.sin6_family = AF_INET6;
        a6.sin6_addr = in6addr_any;   // same tracked packets arrive at machines real IPv6
        a6.sin6_port = htons(LOCAL_UDP_RELAY_PORT);
        if (bind(udp_relay_socket6, (struct sockaddr*)&a6, sizeof(a6)) == SOCKET_ERROR)
        {
            closesocket(udp_relay_socket6);
            udp_relay_socket6 = INVALID_SOCKET;
        }
    }

    // Try initial UDP ASSOCIATE only for SOCKS5 configs that an enabled rule actually uses.
    // Skipping unreferenced configs avoids stalling the relay on dead/unused proxies.
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        if (g_proxy_configs[i].type == PROXY_TYPE_SOCKS5 &&
            is_proxy_config_referenced(g_proxy_configs[i].config_id))
        {
            establish_udp_associate_for_config(&g_proxy_configs[i]);
        }
    }

    log_message("UDP relay listening on port %d", LOCAL_UDP_RELAY_PORT);

    while (running)
    {
        // Set whenever an association's sockets are closed and recreated this iteration.
        // Windows reuses closed SOCKET handle values, so the current read_fds (from the
        // select() below) can falsely report the NEW socket ready -> recvfrom on it
        // returns WSAEINVAL (or, on the blocking send socket, stalls ~30s). We must
        // restart the loop and rebuild read_fds before inspecting the new sockets (#183).
        int assoc_replaced = 0;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_relay_socket, &read_fds);
        if (udp_relay_socket6 != INVALID_SOCKET)
            FD_SET(udp_relay_socket6, &read_fds);

        // Add all SOCKS5 configs' TCP control and UDP send sockets
        for (int i = 0; i < g_proxy_config_count; i++)
        {
            PROXY_CONFIG *cfg = &g_proxy_configs[i];
            if (cfg->type != PROXY_TYPE_SOCKS5) continue;
            if (cfg->udp_connected && cfg->udp_tcp_ctrl != INVALID_SOCKET)
                FD_SET(cfg->udp_tcp_ctrl, &read_fds);
            if (cfg->udp_connected && cfg->udp_send_sock != INVALID_SOCKET)
                FD_SET(cfg->udp_send_sock, &read_fds);
        }

        struct timeval timeout = {1, 0};
        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0)
        {
            // Select timed out proactively reconnect any dropped UDP ASSOCIATEs so
            // the connection is ready before the next client packet arrives.
            // Real time communication need real time packet transfer, a single UDP Associate connction can take 1 to 2 seconds and it break the UDP steam for client app
            // fuck you udp this cause slight increase in performance but needed for udp
            for (int i = 0; i < g_proxy_config_count; i++)
            {
                PROXY_CONFIG *rc = &g_proxy_configs[i];
                if (rc->type == PROXY_TYPE_SOCKS5 && !rc->udp_connected &&
                    is_proxy_config_referenced(rc->config_id))
                    establish_udp_associate_for_config(rc);
            }
            continue;
        }

        // Check if any SOCKS5 proxy TCP control socket disconnected
        for (int i = 0; i < g_proxy_config_count; i++)
        {
            PROXY_CONFIG *cfg = &g_proxy_configs[i];
            if (cfg->type != PROXY_TYPE_SOCKS5 || !cfg->udp_connected) continue;
            if (cfg->udp_tcp_ctrl != INVALID_SOCKET && FD_ISSET(cfg->udp_tcp_ctrl, &read_fds))
            {
                char test_buf[1];
                int result = recv(cfg->udp_tcp_ctrl, test_buf, sizeof(test_buf), MSG_PEEK);
                if (result == 0 || (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK))
                {
                    log_message("[UDP RELAY] TCP control connection closed for proxy %s:%d - reconnecting", cfg->host, cfg->port);
                    closesocket(cfg->udp_tcp_ctrl);
                    cfg->udp_tcp_ctrl = INVALID_SOCKET;
                    if (cfg->udp_send_sock != INVALID_SOCKET)
                    {
                        closesocket(cfg->udp_send_sock);
                        cfg->udp_send_sock = INVALID_SOCKET;
                    }
                    cfg->udp_connected = FALSE;
                    // Reconnect immediately so the next client packet is not dropped.
                    establish_udp_associate_for_config(cfg);
                    assoc_replaced = 1;   // sockets replaced - read_fds is now stale
                }
            }
        }
        if (assoc_replaced) continue;   // rebuild read_fds before touching new sockets

        // Check if packet is from local application
        if (FD_ISSET(udp_relay_socket, &read_fds))
        {
            from_len = sizeof(from_addr);
            recv_len = recvfrom(udp_relay_socket, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len == SOCKET_ERROR)
            {
                // take the error  unreachable so
                // https://github.com/InterceptSuite/ProxyBridge/issues/89
                // select() does not immediately return readable again, causing a spin.
                continue;
            }

            if (recv_len > 0)
            {
                // Buffer overflow protection
                if (recv_len > MAXBUF - 10) continue;

                UINT16 from_port = ntohs(from_addr.sin_port);
                UINT32 dest_ip;
                UINT16 dest_port;

                if (get_connection(from_port, TRUE, &dest_ip, &dest_port))
                {
                    UINT32 proxy_config_id = get_connection_proxy_id(from_port, TRUE);
                    PROXY_CONFIG *cfg = find_proxy_config(proxy_config_id);

                    if (cfg == NULL || cfg->type != PROXY_TYPE_SOCKS5)
                    {
                        log_message("[UDP RELAY] No SOCKS5 config for port %d", from_port);
                        continue;
                    }

                    // UDP ASSOCIATE is established (reconnect if dropped).
                    // If reconnect succeeds, fall through and send the current packet
                    // immediately so real-time streams lose at most one packet.
                    if (!cfg->udp_connected)
                    {
                        if (!establish_udp_associate_for_config(cfg))
                        {
                            log_message("[UDP RELAY] UDP ASSOCIATE unavailable for %s:%d - dropping packet", cfg->host, cfg->port);
                            continue;
                        }
                        assoc_replaced = 1;   // new sockets created - read_fds is stale
                    }

                    send_buf[0] = 0;
                    send_buf[1] = 0;
                    send_buf[2] = 0;
                    send_buf[3] = SOCKS5_ATYP_IPV4;
                    send_buf[4] = (dest_ip >> 0) & 0xFF;
                    send_buf[5] = (dest_ip >> 8) & 0xFF;
                    send_buf[6] = (dest_ip >> 16) & 0xFF;
                    send_buf[7] = (dest_ip >> 24) & 0xFF;
                    send_buf[8] = (dest_port >> 8) & 0xFF;
                    send_buf[9] = (dest_port >> 0) & 0xFF;
                    memcpy(&send_buf[10], recv_buf, recv_len);

                    int sent = sendto(cfg->udp_send_sock, (char*)send_buf, 10 + recv_len, 0,
                          (struct sockaddr *)&cfg->udp_relay_addr, sizeof(cfg->udp_relay_addr));

                    if (sent == SOCKET_ERROR) {
                        int err = WSAGetLastError();
                        log_message("[UDP RELAY ERROR] sendto proxy %s:%d failed: %d - reconnecting and retrying", cfg->host, cfg->port, err);
                        if (cfg->udp_tcp_ctrl != INVALID_SOCKET) { closesocket(cfg->udp_tcp_ctrl); cfg->udp_tcp_ctrl = INVALID_SOCKET; }
                        if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
                        cfg->udp_connected = FALSE;
                        // Reconnect and retry the current packet so real-time streams
                        // lose at most one packet during a proxy reconnect event.
                        if (establish_udp_associate_for_config(cfg))
                        {
                            sendto(cfg->udp_send_sock, (char*)send_buf, 10 + recv_len, 0,
                                   (struct sockaddr *)&cfg->udp_relay_addr, sizeof(cfg->udp_relay_addr));
                        }
                        assoc_replaced = 1;   // sockets replaced - read_fds is stale
                    }
                }
            }
        }
        if (assoc_replaced) continue;   // rebuild read_fds before inspecting new sockets

        // Check if packet is from any SOCKS5 proxy's UDP socket
        for (int i = 0; i < g_proxy_config_count; i++)
        {
            PROXY_CONFIG *cfg = &g_proxy_configs[i];
            if (cfg->type != PROXY_TYPE_SOCKS5 || !cfg->udp_connected) continue;
            if (cfg->udp_send_sock == INVALID_SOCKET) continue;
            // If not signalled by the outer select, do a zero-timeout check for
            // sockets that were created this iteration (e.g. just after reconnect).
            if (!FD_ISSET(cfg->udp_send_sock, &read_fds))
            {
                fd_set quick;
                FD_ZERO(&quick);
                FD_SET(cfg->udp_send_sock, &quick);
                struct timeval zero_tv = {0, 0};
                if (select(0, &quick, NULL, NULL, &zero_tv) <= 0 || !FD_ISSET(cfg->udp_send_sock, &quick))
                    continue;
            }

            from_len = sizeof(from_addr);
            recv_len = recvfrom(cfg->udp_send_sock, (char*)recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr *)&from_addr, &from_len);

            if (recv_len == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                log_message("[UDP RELAY ERROR] Failed to receive from proxy %s:%d: %d - closing", cfg->host, cfg->port, err);
                if (cfg->udp_tcp_ctrl != INVALID_SOCKET) { closesocket(cfg->udp_tcp_ctrl); cfg->udp_tcp_ctrl = INVALID_SOCKET; }
                closesocket(cfg->udp_send_sock);
                cfg->udp_send_sock = INVALID_SOCKET;
                cfg->udp_connected = FALSE;
                continue;
            }

            if (recv_len > 0)
            {
                // Packet from SOCKS5 proxy - decapsulate and forward to original sender
                if (recv_len < 10) continue;

                // SOCKS5 UDP: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT(2) + DATA
                if (recv_buf[2] != 0x00) continue;  // FRAG must be 0

                if (recv_buf[3] == SOCKS5_ATYP_IPV4 && recv_len >= 10)
                {
                    UINT32 src_ip = (recv_buf[4]<<0)|(recv_buf[5]<<8)|(recv_buf[6]<<16)|(recv_buf[7]<<24);
                    UINT16 src_port = (recv_buf[8]<<8)|recv_buf[9];

                    BOOL found = FALSE;
                    UINT32 target_ip = 0;
                    UINT16 target_port = 0;
                    CONNECTION_INFO *winner_conn = NULL;

                    AcquireSRWLockShared(&lock);
                    ULONGLONG best_activity = 0;
                    // O(1): only the reverse bucket for this (dest ip, dest port) - not the
                    // whole table - then pick the most-recently-active matching client.
                    for (CONNECTION_INFO *conn = connection_rev_table[rev_hash_v4(src_ip, src_port)];
                         conn != NULL; conn = conn->rev_next)
                    {
                        if (conn->is_udp && !conn->is_ipv6 && conn->orig_dest_ip == src_ip && conn->orig_dest_port == src_port)
                        {
                            if (!found || conn->last_activity > best_activity)
                            {
                                target_ip    = conn->src_ip;
                                target_port  = conn->src_port;
                                best_activity = conn->last_activity;
                                found        = TRUE;
                                winner_conn  = conn;
                                // Do NOT update last_activity here; doing so mid-loop corrupts
                                // best_activity comparisons for later entries. Update after.
                            }
                        }
                    }
                    // Keep winner's session alive (update outside loop so comparisons above
                    // use the original, unmodified timestamps for all candidates).
                    if (winner_conn != NULL)
                        InterlockedExchange64((LONGLONG volatile*)&winner_conn->last_activity, (LONGLONG)GetTickCount64());
                    ReleaseSRWLockShared(&lock);

                    if (found)
                    {
                        struct sockaddr_in target_addr;
                        memset(&target_addr, 0, sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        target_addr.sin_addr.s_addr = target_ip;
                        target_addr.sin_port = htons(target_port);
                        int fwd = sendto(udp_relay_socket, (char*)&recv_buf[10], recv_len-10, 0,
                               (struct sockaddr*)&target_addr, sizeof(target_addr));
                        if (fwd == SOCKET_ERROR)
                            log_message("[UDP RELAY] sendto client port %d failed: %d", target_port, WSAGetLastError());
                    }
                    else
                    {
                        log_message("[UDP RELAY] No session found for proxy response from %d.%d.%d.%d:%d - dropped",
                            recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7], src_port);
                    }
                }
                else if (recv_buf[3] == SOCKS5_ATYP_IPV6 && recv_len >= 22)
                {
                    UINT8 src_ip6[16];
                    memcpy(src_ip6, &recv_buf[4], 16);
                    UINT16 src_port = (recv_buf[20]<<8)|recv_buf[21];

                    UINT8 target_ip6[16];
                    UINT16 target_port = 0;
                    if (find_v6_udp_sender(src_ip6, src_port, target_ip6, &target_port) && udp_relay_socket6 != INVALID_SOCKET)
                    {
                        struct sockaddr_in6 t6;
                        memset(&t6, 0, sizeof(t6));
                        t6.sin6_family = AF_INET6;
                        memcpy(&t6.sin6_addr, target_ip6, 16);
                        t6.sin6_port = htons(target_port);
                        sendto(udp_relay_socket6, (char*)&recv_buf[22], recv_len-22, 0,
                               (struct sockaddr*)&t6, sizeof(t6));
                    }
                }
            }
        }

        // IPv6 UDP packets from application
        if (udp_relay_socket6 != INVALID_SOCKET && FD_ISSET(udp_relay_socket6, &read_fds))
        {
            struct sockaddr_in6 from_addr6 = {0};
            int fl = sizeof(from_addr6);
            recv_len = recvfrom(udp_relay_socket6, (char*)recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr*)&from_addr6, &fl);
            if (recv_len > 0 && recv_len <= MAXBUF - 22)
            {
                UINT16 from_port = ntohs(from_addr6.sin6_port);
                UINT8  dest_ip6[16];
                UINT16 dest_port = 0;
                UINT32 proxy_config_id = 0;

                if (get_connection_full_v6(from_port, TRUE, dest_ip6, &dest_port, &proxy_config_id))
                {
                    PROXY_CONFIG *cfg = find_proxy_config(proxy_config_id);
                    if (cfg != NULL && cfg->type == PROXY_TYPE_SOCKS5)
                    {
                        if (!cfg->udp_connected) establish_udp_associate_for_config(cfg);
                        if (cfg->udp_connected)
                        {
                            send_buf[0] = 0; send_buf[1] = 0; send_buf[2] = 0;
                            send_buf[3] = SOCKS5_ATYP_IPV6;
                            memcpy(&send_buf[4], dest_ip6, 16);
                            send_buf[20] = (dest_port>>8)&0xFF;
                            send_buf[21] = (dest_port>>0)&0xFF;
                            memcpy(&send_buf[22], recv_buf, recv_len);
                            sendto(cfg->udp_send_sock, (char*)send_buf, 22+recv_len, 0,
                                   (struct sockaddr*)&cfg->udp_relay_addr, sizeof(cfg->udp_relay_addr));
                        }
                    }
                }
            }
        }
    }

    // Clean up all proxy UDP sockets
    for (int i = 0; i < g_proxy_config_count; i++)
    {
        PROXY_CONFIG *cfg = &g_proxy_configs[i];
        if (cfg->udp_tcp_ctrl != INVALID_SOCKET) { closesocket(cfg->udp_tcp_ctrl); cfg->udp_tcp_ctrl = INVALID_SOCKET; }
        if (cfg->udp_send_sock != INVALID_SOCKET) { closesocket(cfg->udp_send_sock); cfg->udp_send_sock = INVALID_SOCKET; }
        cfg->udp_connected = FALSE;
    }
    closesocket(udp_relay_socket);
    udp_relay_socket = INVALID_SOCKET;
    if (udp_relay_socket6 != INVALID_SOCKET) { closesocket(udp_relay_socket6); udp_relay_socket6 = INVALID_SOCKET; }
    WSACleanup();
    return 0;
}

DWORD WINAPI local_proxy_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in addr;
    SOCKET listen_sock;
    int on = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
    {
        log_message("WSAStartup failed (%lu)", GetLastError());
        return 1;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET)
    {
        log_message("Socket creation failed (%d)", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    int nodelay = 1;
    setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);  // must be ANY: WinDivert swaps src/dst IPs for
    addr.sin_port = htons(g_local_relay_port); // non-loopback traffic, so redirected SYNs arrive
                                               // at the machine's real IP, not 127.0.0.1

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        log_message("Bind failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR)
    {
        log_message("Listen failed (%d)", WSAGetLastError());
        closesocket(listen_sock);
        WSACleanup();
        return 1;
    }

    // IPv6 loopback listener for redirected IPv6 TCP
    SOCKET listen_sock6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_sock6 != INVALID_SOCKET)
    {
        int v6only = 1;
        setsockopt(listen_sock6, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));
        setsockopt(listen_sock6, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
        setsockopt(listen_sock6, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;   // same reason as IPv4: accept on any local address
        addr6.sin6_port = htons(g_local_relay_port);
        if (bind(listen_sock6, (struct sockaddr*)&addr6, sizeof(addr6)) == SOCKET_ERROR ||
            listen(listen_sock6, SOMAXCONN) == SOCKET_ERROR)
        {
            log_message("IPv6 listen failed (%d)", WSAGetLastError());
            closesocket(listen_sock6);
            listen_sock6 = INVALID_SOCKET;
        }
        else
        {
            log_message("Local proxy IPv6 listening on [::]:%d", g_local_relay_port);
        }
    }

    log_message("Local proxy listening on port %d", g_local_relay_port);

    while (running)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        if (listen_sock6 != INVALID_SOCKET)
            FD_SET(listen_sock6, &read_fds);
        struct timeval timeout = {1, 0};

        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0)
            continue;

        // helper lambda-like macro to accept and dispatch a connection
        #define ACCEPT_AND_DISPATCH(sock, saddr_type, addr_field) do { \
            saddr_type ca; int cl = sizeof(ca); \
            SOCKET cs = accept(sock, (struct sockaddr*)&ca, &cl); \
            if (cs == INVALID_SOCKET) break; \
            CONNECTION_CONFIG *cc = (CONNECTION_CONFIG*)malloc(sizeof(CONNECTION_CONFIG)); \
            if (cc == NULL) { closesocket(cs); break; } \
            cc->client_socket = cs; \
            UINT16 cp = ntohs(((saddr_type*)&ca)->addr_field); \
            BOOL ok = cc->is_ipv6 ? \
                get_connection_full_v6(cp, FALSE, cc->orig_dest_ip6, &cc->orig_dest_port, &cc->proxy_config_id) : \
                get_connection_full(cp, FALSE, &cc->orig_dest_ip, &cc->orig_dest_port, &cc->proxy_config_id); \
            if (!ok) { closesocket(cs); free(cc); break; } \
            HANDLE t = CreateThread(NULL, 1, connection_handler, (LPVOID)cc, 0, NULL); \
            if (t == NULL) { closesocket(cs); free(cc); break; } \
            CloseHandle(t); \
        } while(0)

        if (FD_ISSET(listen_sock, &read_fds))
        {
            struct sockaddr_in client_addr;
            int addr_len = sizeof(client_addr);
            SOCKET client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);

            if (client_sock != INVALID_SOCKET)
            {
                CONNECTION_CONFIG *conn_config = (CONNECTION_CONFIG *)malloc(sizeof(CONNECTION_CONFIG));
                if (conn_config != NULL)
                {
                    conn_config->client_socket = client_sock;
                    conn_config->is_ipv6 = FALSE;

                    UINT16 client_port = ntohs(client_addr.sin_port);
                    if (get_connection_full(client_port, FALSE, &conn_config->orig_dest_ip, &conn_config->orig_dest_port, &conn_config->proxy_config_id))
                    {
                        HANDLE conn_thread = CreateThread(NULL, 1, connection_handler, (LPVOID)conn_config, 0, NULL);
                        if (conn_thread != NULL) { CloseHandle(conn_thread); }
                        else { closesocket(client_sock); free(conn_config); }
                    }
                    else { closesocket(client_sock); free(conn_config); }
                }
                else { closesocket(client_sock); }
            }
        }

        if (listen_sock6 != INVALID_SOCKET && FD_ISSET(listen_sock6, &read_fds))
        {
            struct sockaddr_in6 client_addr6;
            int addr_len6 = sizeof(client_addr6);
            SOCKET client_sock6 = accept(listen_sock6, (struct sockaddr*)&client_addr6, &addr_len6);

            if (client_sock6 != INVALID_SOCKET)
            {
                CONNECTION_CONFIG *conn_config = (CONNECTION_CONFIG *)malloc(sizeof(CONNECTION_CONFIG));
                if (conn_config != NULL)
                {
                    conn_config->client_socket = client_sock6;
                    conn_config->is_ipv6 = TRUE;

                    UINT16 client_port = ntohs(client_addr6.sin6_port);
                    if (get_connection_full_v6(client_port, FALSE, conn_config->orig_dest_ip6, &conn_config->orig_dest_port, &conn_config->proxy_config_id))
                    {
                        HANDLE conn_thread = CreateThread(NULL, 1, connection_handler, (LPVOID)conn_config, 0, NULL);
                        if (conn_thread != NULL) { CloseHandle(conn_thread); }
                        else { closesocket(client_sock6); free(conn_config); }
                    }
                    else { closesocket(client_sock6); free(conn_config); }
                }
                else { closesocket(client_sock6); }
            }
        }
    }

    #undef ACCEPT_AND_DISPATCH

    closesocket(listen_sock);
    if (listen_sock6 != INVALID_SOCKET) closesocket(listen_sock6);
    WSACleanup();
    return 0;
}

DWORD WINAPI connection_handler(LPVOID arg)
{
    CONNECTION_CONFIG *config = (CONNECTION_CONFIG *)arg;
    SOCKET client_sock = config->client_socket;
    UINT32 dest_ip = config->orig_dest_ip;
    UINT16 dest_port = config->orig_dest_port;
    UINT32 proxy_config_id = config->proxy_config_id;
    BOOL is_ipv6 = config->is_ipv6;
    UINT8 dest_ip6[16];
    if (is_ipv6) memcpy(dest_ip6, config->orig_dest_ip6, 16);
    SOCKET socks_sock;
    struct sockaddr_in socks_addr;

    free(config);

    // Look up the proxy config for this connection
    PROXY_CONFIG *proxy = find_proxy_config(proxy_config_id);
    if (proxy == NULL || proxy->host[0] == '\0' || proxy->port == 0)
    {
        log_message("[RELAY] No proxy config (id=%u) - dropping connection", proxy_config_id);
        closesocket(client_sock);
        return 1;
    }

    // Connect to proxy, use cached resolved IP to avoid DNS per connection
    UINT32 proxy_ip = proxy->resolved_ip ? proxy->resolved_ip : resolve_hostname(proxy->host);
    if (proxy_ip == 0)
    {
        closesocket(client_sock);
        return 1;
    }

    socks_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (socks_sock == INVALID_SOCKET)
    {
        log_message("Socket creation failed (%d)", WSAGetLastError());
        closesocket(client_sock);
        return 0;
    }

    // 4 MB kernel socket buffers for the relay sockets.
    // The upload path writes from client→proxy over a real network with non-zero
    // RTT; a small (512 KB) send buffer causes send_all() to block the moment
    // the proxy's receive window fills up, which stalls the relay loop and
    // triggers TCP flow-control on the client side → massive upload throughput
    // loss.  4 MB gives plenty of headroom even at high bitrates / high RTT.
    configure_tcp_socket(socks_sock, 4194304, 30000);  // 4 MB – proxy connection
    configure_tcp_socket(client_sock, 4194304, 30000); // 4 MB – app connection

    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = proxy_ip;
    socks_addr.sin_port = htons(proxy->port);

    if (connect(socks_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == SOCKET_ERROR)
    {
        log_message("[RELAY] Failed to connect to proxy %s:%d (%d)", proxy->host, proxy->port, WSAGetLastError());
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    if (proxy->type == PROXY_TYPE_SOCKS5)
    {
        int rc;
        char cached_domain[256];
        // Per-config: only hand the hostname to the proxy (socks5h) when this config
        // opts in; otherwise send the locally-resolved IP (socks5).
        if (is_ipv6)
        {
            if (proxy->send_domain_to_proxy && dns_cache_lookup_v6(dest_ip6, cached_domain, sizeof(cached_domain)))
                rc = socks5_connect_domain(socks_sock, cached_domain, dest_port, proxy);
            else
                rc = socks5_connect_v6(socks_sock, dest_ip6, dest_port, proxy);
        }
        else
        {
            if (proxy->send_domain_to_proxy && dns_cache_lookup(dest_ip, cached_domain, sizeof(cached_domain)))
                rc = socks5_connect_domain(socks_sock, cached_domain, dest_port, proxy);
            else
                rc = socks5_connect(socks_sock, dest_ip, dest_port, proxy);
        }
        if (rc != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }
    else if (proxy->type == PROXY_TYPE_HTTP)
    {
        int rc = is_ipv6
            ? http_connect_v6(socks_sock, dest_ip6, dest_port, proxy)
            : http_connect(socks_sock, dest_ip, dest_port, proxy);
        if (rc != 0)
        {
            closesocket(client_sock);
            closesocket(socks_sock);
            return 0;
        }
    }

    // Disable timeout for data transfer phase
    DWORD zero_timeout = 0;
    setsockopt(socks_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));
    setsockopt(socks_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&zero_timeout, sizeof(zero_timeout));

    // Enable and configure customized TCP keep-alives
    struct tcp_keepalive keepalive_settings;
    keepalive_settings.onoff = 1;
    keepalive_settings.keepalivetime = 300000;      // 5 minutes in milliseconds
    keepalive_settings.keepaliveinterval = 1000;    // 1 second interval
    DWORD bytes_returned = 0;
    WSAIoctl(socks_sock, SIO_KEEPALIVE_VALS, &keepalive_settings, sizeof(keepalive_settings), NULL, 0, &bytes_returned, NULL, NULL);
    WSAIoctl(client_sock, SIO_KEEPALIVE_VALS, &keepalive_settings, sizeof(keepalive_settings), NULL, 0, &bytes_returned, NULL, NULL);

    TRANSFER_CONFIG *transfer_config = (TRANSFER_CONFIG *)malloc(sizeof(TRANSFER_CONFIG));

    if (transfer_config == NULL)
    {
        log_message("Memory allocation failed for transfer_config");
        closesocket(client_sock);
        closesocket(socks_sock);
        return 0;
    }

    transfer_config->from_socket = client_sock;
    transfer_config->to_socket = socks_sock;

    // both transfer in current thread
    transfer_handler((LPVOID)transfer_config);

    // Sockets already closed in transfer_handler!

    return 0;
}

// One-directional relay: reads from `from` and writes to `to`.
// Runs as a dedicated thread so upload and download never block each other.
// Uses a shared RELAY_PAIR reference count for safe socket cleanup:
//   - whichever direction finishes first calls shutdown() on both sockets,
//     which causes the sibling thread's recv() to return 0 and exit cleanly.
//   - the last thread to exit (refs drops to 0) closes both sockets and
//     frees the shared RELAY_PAIR.
DWORD WINAPI one_way_relay(LPVOID arg)
{
    ONE_WAY_CONFIG *cfg = (ONE_WAY_CONFIG *)arg;
    RELAY_PAIR *pair = cfg->pair;
    SOCKET from = cfg->from;
    SOCKET to   = cfg->to;
    free(cfg);

    char *buf = (char *)malloc(131072);  // 128 KB per-direction buffer
    if (buf)
    {
        int len;
        while ((len = recv(from, buf, 131072, 0)) > 0)
        {
            if (send_all(to, buf, len) == SOCKET_ERROR)
                break;
        }
        free(buf);
    }

    // Signal the sibling relay to stop by shutting down both sockets.
    // shutdown() is safe to call from any thread; it just drains/resets the
    // socket without closing the handle, so the other thread's recv() returns 0.
    shutdown(pair->sock_client, SD_BOTH);
    shutdown(pair->sock_proxy,  SD_BOTH);

    // Last thread out closes and frees everything.
    if (InterlockedDecrement(&pair->refs) == 0)
    {
        closesocket(pair->sock_client);
        closesocket(pair->sock_proxy);
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
        closesocket(sock_client);
        closesocket(sock_proxy);
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
        closesocket(sock_client);
        closesocket(sock_proxy);
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
        closesocket(sock_client);
        closesocket(sock_proxy);
        return 1;
    }

    // Run the download relay in this thread (blocks until done).
    one_way_relay(dn);

    // Wait for the upload relay thread to finish, then clean up its handle.
    WaitForSingleObject(upload_thread, INFINITE);
    CloseHandle(upload_thread);

    return 0;
}

