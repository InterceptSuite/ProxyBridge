#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static BOOL fail_allocation;
static unsigned allocation_calls;
static void *queue_allocate(size_t size)
{
    ++allocation_calls;
    return fail_allocation ? NULL : malloc(size);
}
#define malloc queue_allocate
#include "pb_internal.h"
#undef malloc

static int send_mode, sends, order;
static int fake_sendto(SOCKET socket, const char *data, int length, int flags,
                       const struct sockaddr *destination, int destination_length)
{
    (void)socket; (void)flags; (void)destination; (void)destination_length;
    ++sends;
    if (send_mode == 1) { WSASetLastError(WSAEWOULDBLOCK); return SOCKET_ERROR; }
    if (send_mode == 2) { WSASetLastError(WSAECONNRESET); return SOCKET_ERROR; }
    if ((unsigned char)data[0] != order++) return SOCKET_ERROR;
    return length;
}
void pb_udp_association_close(PB_UDP_ASSOCIATION *a)
{
    a->udp_connected = FALSE;
    pb_udp_queue_clear(&a->pending);
}
#define sendto fake_sendto
#include "../src/relay/pb_udp_send.inc"
#undef sendto

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); return 1; } } while (0)
int main(void)
{
    PB_UDP_QUEUE_BUDGET budget = {0};
    PB_UDP_QUEUE queue = {0}; queue.budget = &budget;
    unsigned char data[65535] = {0};
    for (unsigned i = 0; i < 8; ++i) { data[0] = (unsigned char)i; CHECK(pb_udp_queue_push(&queue, data, 1, 100)); }
    CHECK(!pb_udp_queue_push(&queue, data, 1, 100));
    for (unsigned i = 0; i < 8; ++i) {
        CHECK(queue.head && queue.head->data[0] == i);
        pb_udp_queue_pop(&queue);
    }
    CHECK(!queue.head && !queue.tail && budget.bytes == 0);
    CHECK(pb_udp_queue_push(&queue, data, sizeof(data), 100));
    CHECK(pb_udp_queue_push(&queue, data, sizeof(data), 100));
    CHECK(!pb_udp_queue_push(&queue, data, 3, 100));
    pb_udp_queue_expire(&queue, 5099); CHECK(queue.packets == 2);
    pb_udp_queue_expire(&queue, 5100); CHECK(queue.packets == 0 && budget.bytes == 0 && budget.dropped_expired == 2);
    fail_allocation = TRUE;
    CHECK(!pb_udp_queue_push(&queue, data, 1, 100));
    CHECK(budget.dropped_allocation == 1 && budget.bytes == 0);
    fail_allocation = FALSE;
    PB_UDP_QUEUE queues[32] = {0};
    unsigned accepted = 0;
    for (unsigned i = 0; i < 32; ++i) {
        queues[i].budget = &budget;
        if (pb_udp_queue_push(&queues[i], data, sizeof(data), 100)) ++accepted;
        CHECK(budget.bytes <= PB_UDP_QUEUE_GLOBAL_BYTES);
    }
    CHECK(accepted > 0 && accepted < 32);
    for (unsigned i = 0; i < 32; ++i) pb_udp_queue_clear(&queues[i]);
    CHECK(budget.bytes == 0);

    PB_UDP_ASSOCIATION a = {0}; a.pending.budget = &budget;
    for (unsigned i = 0; i < 4; ++i) { data[0] = (unsigned char)i; udp_send_payload(&a, data, 1); }
    CHECK(a.pending.packets == 4 && sends == 0);
    a.udp_connected = TRUE; send_mode = 1;
    udp_flush_pending(&a); CHECK(a.pending.packets == 4 && sends == 1);
    send_mode = 0; udp_flush_pending(&a);
    CHECK(!a.pending.head && order == 4 && budget.bytes == 0);
    unsigned before = allocation_calls;
    fail_allocation = TRUE; data[0] = 4; udp_send_payload(&a, data, 1);
    CHECK(order == 5 && allocation_calls == before && budget.bytes == 0);
    fail_allocation = FALSE;
    send_mode = 1; data[0] = 5; udp_send_payload(&a, data, 1);
    CHECK(a.pending.packets == 1);
    send_mode = 2; udp_flush_pending(&a);
    CHECK(!a.udp_connected && !a.pending.head && budget.bytes == 0);
    puts("PASS: FIFO/copy, packet-byte-global limits, TTL, allocation failure, WOULD_BLOCK, fast path, fatal-send cleanup");
    return 0;
}
