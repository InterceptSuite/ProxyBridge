#include "pb_internal.h"

#include "pb_udp_clients.inc"

#include "pb_udp_send.inc"

#include "pb_udp_receive.inc"
#include "pb_udp_drain.inc"

DWORD WINAPI udp_relay_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in local_addr = {0};

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

    PB_UDP_CONTEXT *ctx = (PB_UDP_CONTEXT *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) goto cleanup;
    if (!udp_grow_clients(ctx)) goto cleanup;
    ctx->definition_revision = -1;
    u_long nonblock = 1;
    if (ioctlsocket(udp_relay_socket, FIONBIO, &nonblock) == SOCKET_ERROR ||
        (udp_relay_socket6 != INVALID_SOCKET && ioctlsocket(udp_relay_socket6, FIONBIO, &nonblock) == SOCKET_ERROR))
        goto cleanup;
    if (arg != NULL) {
        PB_RELAY_STARTUP *startup = (PB_RELAY_STARTUP *)arg;
        startup->ipv6Ready = udp_relay_socket6 != INVALID_SOCKET;
        SetEvent(startup->readyEvent);
    }
    while (running) {
        udp_refresh_definitions(ctx);
        int pending = 0;
        ULONGLONG now = GetTickCount64();
        if (now >= ctx->queue_report_at) {
            ctx->queue_report_at = now + 5000;
            const PB_UDP_QUEUE_BUDGET *q = &ctx->queue_budget;
            const PB_UDP_QUEUE_BUDGET *reported = &ctx->queue_reported;
            if (q->dropped_limit != reported->dropped_limit ||
                q->dropped_allocation != reported->dropped_allocation ||
                q->dropped_expired != reported->dropped_expired) {
                log_message("UDP queue drops: limit=%llu allocation=%llu expired=%llu; queued bytes=%llu",
                    (unsigned long long)q->dropped_limit, (unsigned long long)q->dropped_allocation,
                    (unsigned long long)q->dropped_expired, (unsigned long long)q->bytes);
                ctx->queue_reported = *q;
            }
        }
        for (int i = 0; i < ctx->client_count;) {
            PB_UDP_CLIENT *c = udp_slot(ctx, ctx->active_indices[i]);
            if (now - c->activity >= PB_UDP_IDLE_MS) { udp_retire_client(c); continue; }
            if (!c->association.udp_connected && c->association.setup_phase != 0) ++pending;
            ++i;
        }
        // Start after the last admitted client, so failed early slots cannot
        // monopolize all setup capacity while later clients wait indefinitely.
        int cursor = ctx->setup_cursor;
        for (int offset = 0; offset < ctx->client_count; ++offset) {
            int i = (cursor + offset) % ctx->client_count;
            PB_UDP_CLIENT *c = udp_slot(ctx, ctx->active_indices[i]);
            if (!c->association.udp_connected) {
                BOOL starting = c->association.setup_phase == 0;
                BOOL advance = starting || c->association.setup_ready ||
                               now >= c->association.setup_deadline;
                if (advance && (!starting || pending < PB_UDP_SETUP_CAP)) {
                    c->association.setup_ready = FALSE;
                    BOOL was_pending = !starting;
                    ULONGLONG previous_attempt = c->association.last_udp_attempt;
                    establish_udp_associate(&c->association);
                    BOOL is_pending = !c->association.udp_connected && c->association.setup_phase != 0;
                    if (was_pending && !is_pending) --pending;
                    if (!was_pending && is_pending) ++pending;
                    if (starting && previous_attempt != c->association.last_udp_attempt)
                        ctx->setup_cursor = (i + 1) % ctx->client_count;
                }
            }
            udp_flush_pending(&c->association);
        }
        int count = 2;
        int poll_timeout = 250;
        ctx->polls[0].fd = udp_relay_socket;
        ctx->polls[1].fd = udp_relay_socket6;
        for (int i = 0; i < 2; ++i) { ctx->polls[i].events = POLLRDNORM; ctx->polls[i].revents = 0; }
        for (int i = 0; i < ctx->client_count; ++i) {
            PB_UDP_CLIENT *c = udp_slot(ctx, ctx->active_indices[i]);
            BOOL connected = c->association.udp_connected;
            short setup_events = pb_udp_setup_events(&c->association);
            if (!connected && !setup_events) continue;
            if (!connected) {
                ULONGLONG tick = GetTickCount64();
                ULONGLONG left = c->association.setup_deadline > tick ? c->association.setup_deadline - tick : 0;
                if (left < (ULONGLONG)poll_timeout) poll_timeout = (int)left;
            }
            for (int kind = 0; kind < (connected ? 2 : 1); ++kind) {
                ctx->polls[count].fd = kind == 0 ? c->association.udp_tcp_ctrl : c->association.udp_send_sock;
                ctx->polls[count].events = connected ? POLLRDNORM : setup_events;
                if (kind == 1 && c->association.pending.head != NULL)
                    ctx->polls[count].events |= POLLWRNORM;
                ctx->polls[count].revents = 0;
                ctx->owners[count] = c;
                ctx->controls[count] = kind == 0;
                ++count;
            }
        }
        int selected = WSAPoll(ctx->polls, count, poll_timeout);
        if (selected == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR) continue;
            log_message("UDP readiness polling failed; stopping relay");
            break;
        }
        if (!running) break;
        if (udp_refresh_definitions(ctx)) continue; // discard readiness for retired sockets
        if ((ctx->polls[0].revents | ctx->polls[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
            log_message("UDP listener failed; stopping relay");
            break;
        }
        udp_drain_ready(ctx,count);
        // Snapshot listener events before admission can resize poll storage.
        BOOL ready4 = (ctx->polls[0].revents & POLLRDNORM) != 0;
        BOOL ready6 = (ctx->polls[1].revents & POLLRDNORM) != 0;
        udp_drain_listeners(ctx,ready4,ready6);
    }
cleanup:
    if (ctx != NULL) {
        udp_destroy_clients(ctx);
        free(ctx);
    }
    closesocket(udp_relay_socket);
    udp_relay_socket = INVALID_SOCKET;
    if (udp_relay_socket6 != INVALID_SOCKET) closesocket(udp_relay_socket6);
    udp_relay_socket6 = INVALID_SOCKET;
    WSACleanup();
    return 0;
}
