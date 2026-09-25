#include "pb_internal.h"
#include "pb_tcp_iocp.inc"
#include "pb_tcp_setup.inc"

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
    addr.sin_addr.s_addr = htonl(INADDR_ANY);  // ANY covers loopback: the WFP driver redirects
    addr.sin_port = htons(g_local_relay_port); // watched connections to 127.0.0.1:relay_port

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

    if (arg != NULL) {
        PB_RELAY_STARTUP *startup = (PB_RELAY_STARTUP *)arg;
        startup->ipv6Ready = (listen_sock6 != INVALID_SOCKET);
        SetEvent(startup->readyEvent);
        // Do not access startup again: the caller owns its lifetime.
    }

    ULONGLONG nextReap = 0;
    while (running)
    {
        ULONGLONG now = GetTickCount64();
        if (now >= nextReap) {
            reap_tcp_workers();
            nextReap = now + 1000;
        }
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        if (listen_sock6 != INVALID_SOCKET)
            FD_SET(listen_sock6, &read_fds);
        struct timeval timeout = {1, 0};

        int selected = select(0, &read_fds, NULL, NULL, &timeout);
        if (selected == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAEINTR) continue;
            log_message("TCP listener select failed (%d); stopping relay", error);
            break;
        }
        if (selected == 0 || !running) continue;

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

                    BOOL have_dest;
                    if (g_use_wfp_driver)
                    {
                        // Original dest + PID come from the driver's redirect context; the
                        // rule engine here picks the proxy config (and could direct/block).
                        DWORD pid = 0;
                        have_dest = pb_driver_orig_dest(client_sock, &conn_config->orig_dest_ip,
                                                        &conn_config->orig_dest_port, &pid);
                        if (have_dest)
                        {
                            char pname[MAX_PROCESS_NAME];
                            UINT32 cfg = 0;
                            BOOL known = get_process_name_from_pid(pid, pname, sizeof(pname));
                            BOOL available;
                            RuleAction act = pb_select_proxy(known ? pname : NULL, FALSE,
                                conn_config->orig_dest_ip, NULL, conn_config->orig_dest_port,
                                FALSE, &cfg, &conn_config->proxy_snapshot, &available);
                            conn_config->proxy_config_id = cfg;
                            struct in_addr da; da.S_un.S_addr = conn_config->orig_dest_ip;
                            log_message("[RELAY] accepted redirect: pid=%lu dest=%s:%u action=%d cfg=%u",
                                        pid, inet_ntoa(da), conn_config->orig_dest_port, act, cfg);
                            pb_report_connection(pid, known ? pname : NULL, FALSE, conn_config->orig_dest_ip, NULL,
                                                 conn_config->orig_dest_port, act, cfg, FALSE,
                                                 available ? &conn_config->proxy_snapshot : NULL);
                            if (act == RULE_ACTION_BLOCK || !available) have_dest = FALSE;
                        }
                        else
                        {
                            log_message("[RELAY] redirect-context query FAILED (WSA %d) - dropping", WSAGetLastError());
                        }
                    }
                    else
                    {
                        UINT16 client_port = ntohs(client_addr.sin_port);
                        have_dest = get_connection_full(client_port, FALSE, &conn_config->orig_dest_ip,
                                                        &conn_config->orig_dest_port, &conn_config->proxy_config_id);
                        if (have_dest) have_dest = find_proxy_config_copy(conn_config->proxy_config_id,
                                                                         &conn_config->proxy_snapshot);
                    }
                    if (have_dest)
                    {
                        if (!start_tcp_worker(conn_config)) {
                            closesocket(client_sock);
                            free(conn_config);
                        }
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

                    BOOL have_dest6;
                    if (g_use_wfp_driver)
                    {
                        DWORD pid = 0;
                        have_dest6 = pb_driver_orig_dest6(client_sock6, conn_config->orig_dest_ip6,
                                                          &conn_config->orig_dest_port, &pid);
                        if (have_dest6)
                        {
                            char pname[MAX_PROCESS_NAME];
                            UINT32 cfg = 0;
                            BOOL known = get_process_name_from_pid(pid, pname, sizeof(pname));
                            BOOL available;
                            RuleAction act = pb_select_proxy(known ? pname : NULL, TRUE,
                                0, conn_config->orig_dest_ip6, conn_config->orig_dest_port,
                                FALSE, &cfg, &conn_config->proxy_snapshot, &available);
                            conn_config->proxy_config_id = cfg;
                            pb_report_connection(pid, known ? pname : NULL, TRUE, 0, conn_config->orig_dest_ip6,
                                                 conn_config->orig_dest_port, act, cfg, FALSE,
                                                 available ? &conn_config->proxy_snapshot : NULL);
                            if (act == RULE_ACTION_BLOCK || !available) have_dest6 = FALSE;
                        }
                    }
                    else
                    {
                        UINT16 client_port = ntohs(client_addr6.sin6_port);
                        have_dest6 = get_connection_full_v6(client_port, FALSE, conn_config->orig_dest_ip6,
                                                            &conn_config->orig_dest_port, &conn_config->proxy_config_id);
                        if (have_dest6) have_dest6 = find_proxy_config_copy(conn_config->proxy_config_id,
                                                                           &conn_config->proxy_snapshot);
                    }
                    if (have_dest6)
                    {
                        if (!start_tcp_worker(conn_config)) {
                            closesocket(client_sock6);
                            free(conn_config);
                        }
                    }
                    else { closesocket(client_sock6); free(conn_config); }
                }
                else { closesocket(client_sock6); }
            }
        }
    }

    closesocket(listen_sock);
    if (listen_sock6 != INVALID_SOCKET) closesocket(listen_sock6);
    WSACleanup();
    return 0;
}
