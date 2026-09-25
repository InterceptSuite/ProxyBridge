static void udp_send_payload(PB_UDP_ASSOCIATION *a, const unsigned char *data, int length)
{
    ULONGLONG now = GetTickCount64();
    pb_udp_queue_expire(&a->pending, now);
    if (a->udp_connected && !a->pending.head) {
        int sent = sendto(a->udp_send_sock, (const char *)data, length, 0,
                          (struct sockaddr *)&a->udp_relay_addr, sizeof(a->udp_relay_addr));
        if (sent == length) return;
        if (sent != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) {
            pb_udp_association_close(a);
            return;
        }
    }
    if (length > 0) pb_udp_queue_push(&a->pending, data, (unsigned)length, now);
}

static void udp_flush_pending(PB_UDP_ASSOCIATION *a)
{
    pb_udp_queue_expire(&a->pending, GetTickCount64());
    if (!a->udp_connected) return;
    // The queue itself is capped at eight packets; never spin on WOULD_BLOCK.
    for (unsigned i = 0; i < PB_UDP_QUEUE_PACKETS && a->pending.head; ++i) {
        PB_UDP_PACKET *packet = a->pending.head;
        int sent = sendto(a->udp_send_sock, (const char *)packet->data, (int)packet->length, 0,
                          (struct sockaddr *)&a->udp_relay_addr, sizeof(a->udp_relay_addr));
        if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) return;
        if (sent != (int)packet->length) { pb_udp_association_close(a); return; }
        pb_udp_queue_pop(&a->pending);
    }
}
