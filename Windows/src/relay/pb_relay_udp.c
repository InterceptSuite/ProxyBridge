#include "pb_internal.h"

// UDP relay server: forwards app datagrams through the SOCKS5 proxy (UDP ASSOCIATE)
// and routes replies back to the originating app.

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
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // ANY covers loopback: the WFP driver
    local_addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);// redirects watched datagrams to 127.0.0.1

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
                UINT32 dest_ip = 0;
                UINT16 dest_port = 0;
                UINT32 proxy_config_id = 0;
                BOOL have_udp;

                if (g_use_wfp_driver)
                {
                    // Original dest from the driver's UDP map; feed the reverse index so the
                    // proxy-reply path below routes replies back to this client unchanged.
                    DWORD pid = 0;
                    have_udp = pb_driver_udp_orig(from_addr.sin_addr.s_addr, from_port, &dest_ip, &dest_port, &pid);
                    if (have_udp)
                    {
                        char pname[MAX_PROCESS_NAME];
                        RuleAction act = RULE_ACTION_PROXY;
                        if (get_process_name_from_pid(pid, pname, sizeof(pname)))
                            act = match_rule(pname, dest_ip, dest_port, TRUE, &proxy_config_id);
                        pb_report_connection(pid, NULL, FALSE, dest_ip, NULL, dest_port, act, proxy_config_id, TRUE);
                        if (act == RULE_ACTION_PROXY)
                            add_connection(from_port, TRUE, from_addr.sin_addr.s_addr, dest_ip, dest_port, proxy_config_id);
                        else
                            have_udp = FALSE;
                    }
                }
                else
                {
                    have_udp = get_connection(from_port, TRUE, &dest_ip, &dest_port);
                    if (have_udp) proxy_config_id = get_connection_proxy_id(from_port, TRUE);
                }

                if (have_udp)
                {
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

                    // Driver mode: watched apps' DNS is redirected here, so snoop the answer
                    // to build the IP->domain map that domain rules match against.
                    if (g_use_wfp_driver && src_port == 53 && recv_len > 10)
                        snoop_dns_response(&recv_buf[10], recv_len - 10);

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
