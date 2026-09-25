static BOOL udp_receive_client(PB_UDP_CONTEXT *ctx, SOCKET listener, BOOL v6)
{
    struct sockaddr_storage source = {0};
    int source_length = sizeof(source);
    int length = recvfrom(listener, (char *)ctx->input, MAXBUF, 0,
                          (struct sockaddr *)&source, &source_length);
    int address_length = v6 ? 16 : 4;
    int header_length = 6 + address_length;
    if (length < 0) return FALSE;
    if (length > MAXBUF - header_length) return TRUE;
    if (source.ss_family != (v6 ? AF_INET6 : AF_INET) ||
        source_length != (v6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) return TRUE;
    UINT8 destination[16] = {0};
    UINT16 port = 0;
    DWORD pid = 0;
    UINT64 generation = 0;
    LONG64 query_epoch = pb_driver_session_epoch();
    BOOL found;
    if (v6) {
        const struct sockaddr_in6 *src = (const struct sockaddr_in6 *)&source;
        found = pb_driver_udp_orig6((const UINT8 *)&src->sin6_addr, ntohs(src->sin6_port), destination, &port, &pid, &generation);
    } else {
        const struct sockaddr_in *src = (const struct sockaddr_in *)&source;
        UINT32 ip;
        found = pb_driver_udp_orig(src->sin_addr.s_addr, ntohs(src->sin_port), &ip, &port, &pid, &generation);
        if (found) memcpy(destination, &ip, 4);
    }
    if (query_epoch != pb_driver_session_epoch()) found = FALSE;
    UINT32 proxy_id = 0, ip = 0;
    memcpy(&ip, destination, 4);
    RuleAction action = RULE_ACTION_PROXY;
    PROXY_CONFIG selected;
    BOOL available = FALSE;
    char name[MAX_PROCESS_NAME];
    BOOL name_known = found && get_process_name_from_pid(pid, name, sizeof(name));
    if (found)
        action = pb_select_proxy(name_known ? name : NULL, v6, ip, destination,
                                 port, TRUE, &proxy_id, &selected, &available);
    if (found) pb_report_connection(pid, name_known ? name : NULL, v6, ip, v6 ? destination : NULL,
        port, action, proxy_id, TRUE, available ? &selected : NULL);
    udp_refresh_definitions(ctx);
    if (query_epoch != ctx->driver_epoch) found = FALSE;
    // A callback/profile update may have refreshed the store after selection.
    // Never substitute another default proxy or a newer definition for this packet.
    const PROXY_CONFIG *def = found && available && action == RULE_ACTION_PROXY
        ? udp_selected_definition(ctx, &selected) : NULL;
    PB_UDP_CLIENT *client = udp_client(ctx, &source, source_length, pid, generation, destination, port, def);
    if (client == NULL) return TRUE;
    client->activity = GetTickCount64();
    ctx->output[0] = ctx->output[1] = ctx->output[2] = 0;
    ctx->output[3] = v6 ? SOCKS5_ATYP_IPV6 : SOCKS5_ATYP_IPV4;
    memcpy(ctx->output + 4, destination, address_length);
    ctx->output[4 + address_length] = (unsigned char)(port >> 8);
    ctx->output[5 + address_length] = (unsigned char)port;
    memcpy(ctx->output + header_length, ctx->input, length);
    udp_flush_pending(&client->association);
    udp_send_payload(&client->association, ctx->output, header_length + length);
    return TRUE;
}

static BOOL udp_receive_reply(PB_UDP_CONTEXT *ctx, PB_UDP_CLIENT *client)
{
    if (!client->used || ctx->driver_epoch != pb_driver_session_epoch() ||
        ctx->definition_revision != InterlockedCompareExchange64(&g_proxy_revision,0,0)) return FALSE;
    PB_UDP_ASSOCIATION *a = &client->association;
    struct sockaddr_in sender = {0};
    int sender_length = sizeof(sender);
    int length = recvfrom(a->udp_send_sock, (char *)ctx->input, MAXBUF, 0,
                          (struct sockaddr *)&sender, &sender_length);
    if (length == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK && error != WSAEMSGSIZE) pb_udp_association_close(a);
        return FALSE;
    }
    if (sender_length != sizeof(sender) || sender.sin_family != AF_INET ||
        sender.sin_addr.s_addr != a->udp_relay_addr.sin_addr.s_addr ||
        sender.sin_port != a->udp_relay_addr.sin_port || length < 4 ||
        ctx->input[0] != 0 || ctx->input[1] != 0 || ctx->input[2] != 0) return TRUE;
    BOOL v6 = client->source.ss_family == AF_INET6;
    int address_length = v6 ? 16 : 4;
    int header_length = 6 + address_length;
    if (ctx->input[3] != (v6 ? SOCKS5_ATYP_IPV6 : SOCKS5_ATYP_IPV4) || length < header_length ||
        memcmp(ctx->input + 4, client->destination, address_length) != 0) return TRUE;
    UINT16 port = (UINT16)((ctx->input[4 + address_length] << 8) | ctx->input[5 + address_length]);
    if (port != client->destination_port) return TRUE;
    // Revalidate delayed replies against the kernel endpoint generation before
    // delivering to an address/port that another socket may now own.
    UINT64 generation = 0;
    DWORD pid = 0;
    UINT16 current_port = 0;
    UINT8 current_destination[16] = {0};
    BOOL current;
    if (v6) {
        const struct sockaddr_in6 *src = (const struct sockaddr_in6 *)&client->source;
        current = pb_driver_udp_orig6((const UINT8 *)&src->sin6_addr, ntohs(src->sin6_port),
                                     current_destination, &current_port, &pid, &generation);
    } else {
        const struct sockaddr_in *src = (const struct sockaddr_in *)&client->source;
        UINT32 ip = 0;
        current = pb_driver_udp_orig(src->sin_addr.s_addr, ntohs(src->sin_port),
                                    &ip, &current_port, &pid, &generation);
        memcpy(current_destination, &ip, 4);
    }
    if (!current || generation != client->mapping_generation || pid != client->pid ||
        current_port != client->destination_port ||
        memcmp(current_destination, client->destination, address_length) != 0) {
        udp_retire_client(client);
        return FALSE;
    }
    if (!v6 && port == 53 && length > header_length)
        snoop_dns_response(ctx->input + header_length, length - header_length);
    SOCKET listener = v6 ? udp_relay_socket6 : udp_relay_socket;
    if (sendto(listener, (char *)ctx->input + header_length, length - header_length, 0,
               (struct sockaddr *)&client->source, client->source_length) != SOCKET_ERROR)
        client->activity = GetTickCount64();
    return TRUE;
}


