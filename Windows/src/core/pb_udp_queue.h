#pragma once
#include <stddef.h>

#define PB_UDP_QUEUE_PACKETS 8u
#define PB_UDP_QUEUE_BYTES (128u * 1024u)
#define PB_UDP_QUEUE_GLOBAL_BYTES (1024u * 1024u)
#define PB_UDP_QUEUE_TTL_MS 5000u

typedef struct {
    size_t bytes; // actual requested allocations, including packet headers
    UINT64 dropped_limit;
    UINT64 dropped_allocation;
    UINT64 dropped_expired;
} PB_UDP_QUEUE_BUDGET;

typedef struct PB_UDP_PACKET {
    struct PB_UDP_PACKET *next;
    ULONGLONG deadline;
    unsigned length;
    unsigned char data[1];
} PB_UDP_PACKET;

typedef struct {
    PB_UDP_PACKET *head, *tail;
    unsigned packets, bytes;
    PB_UDP_QUEUE_BUDGET *budget;
} PB_UDP_QUEUE;

static __inline void pb_udp_queue_pop(PB_UDP_QUEUE *queue)
{
    PB_UDP_PACKET *packet = queue->head;
    if (!packet) return;
    queue->head = packet->next;
    if (!queue->head) queue->tail = NULL;
    --queue->packets;
    queue->bytes -= packet->length;
    queue->budget->bytes -= sizeof(PB_UDP_PACKET) + packet->length - 1u;
    free(packet);
}

static __inline void pb_udp_queue_clear(PB_UDP_QUEUE *queue)
{
    while (queue->head) pb_udp_queue_pop(queue);
}

static __inline void pb_udp_queue_expire(PB_UDP_QUEUE *queue, ULONGLONG now)
{
    while (queue->head && now >= queue->head->deadline) {
        ++queue->budget->dropped_expired;
        pb_udp_queue_pop(queue);
    }
}

static __inline BOOL pb_udp_queue_push(PB_UDP_QUEUE *queue, const void *data,
                                      unsigned length, ULONGLONG now)
{
    PB_UDP_QUEUE_BUDGET *budget = queue->budget;
    if (!budget) return FALSE;
    pb_udp_queue_expire(queue, now);
    size_t allocation = sizeof(PB_UDP_PACKET) + (size_t)length - 1u;
    if (!data || length == 0 || length > 65535u ||
        queue->packets >= PB_UDP_QUEUE_PACKETS ||
        length > PB_UDP_QUEUE_BYTES - queue->bytes ||
        allocation > PB_UDP_QUEUE_GLOBAL_BYTES - budget->bytes) {
        ++budget->dropped_limit;
        return FALSE;
    }
    PB_UDP_PACKET *packet = malloc(allocation);
    if (!packet) { ++budget->dropped_allocation; return FALSE; }
    packet->next = NULL;
    packet->deadline = now + PB_UDP_QUEUE_TTL_MS;
    packet->length = length;
    memcpy(packet->data, data, length);
    if (queue->tail) queue->tail->next = packet;
    else queue->head = packet;
    queue->tail = packet;
    ++queue->packets;
    queue->bytes += length;
    budget->bytes += allocation;
    return TRUE;
}
