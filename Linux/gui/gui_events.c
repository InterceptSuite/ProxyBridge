#include "gui_events.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct EventRing {
    pthread_mutex_t lock;
    char *slots;
    uint16_t *lens;
    size_t cap, slot_size, head, count;
    uint64_t pushed, delivered, dropped, dropped_pending;
};

EventRing *event_ring_new(size_t capacity, size_t slot_size) {
    if (capacity == 0 || slot_size < 2 || slot_size > UINT16_MAX) return NULL;
    EventRing *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->slots = malloc(capacity * slot_size);
    r->lens = calloc(capacity, sizeof(uint16_t));
    if (!r->slots || !r->lens) {
        free(r->slots);
        free(r->lens);
        free(r);
        return NULL;
    }
    r->cap = capacity;
    r->slot_size = slot_size;
    pthread_mutex_init(&r->lock, NULL);
    return r;
}

void event_ring_free(EventRing *r) {
    if (!r) return;
    pthread_mutex_destroy(&r->lock);
    free(r->slots);
    free(r->lens);
    free(r);
}

void event_ring_push(EventRing *r, const char *text) {
    size_t len = text ? strnlen(text, r->slot_size - 1) : 0;
    pthread_mutex_lock(&r->lock);
    if (r->count == r->cap) {
        r->head = (r->head + 1) % r->cap;
        r->count--;
        r->dropped++;
        r->dropped_pending++;
    }
    size_t idx = (r->head + r->count) % r->cap;
    memcpy(r->slots + idx * r->slot_size, text, len);
    r->lens[idx] = (uint16_t)len;
    r->count++;
    r->pushed++;
    pthread_mutex_unlock(&r->lock);
}

size_t event_ring_drain(EventRing *r, char *out, size_t out_size, size_t max_events, uint64_t *dropped) {
    size_t n = 0, used = 0;
    pthread_mutex_lock(&r->lock);
    while (n < max_events && r->count > 0) {
        size_t len = r->lens[r->head];
        if (used + len + 2 > out_size) break;
        memcpy(out + used, r->slots + r->head * r->slot_size, len);
        used += len;
        out[used++] = '\n';
        r->head = (r->head + 1) % r->cap;
        r->count--;
        r->delivered++;
        n++;
    }
    if (dropped) *dropped = r->dropped_pending;
    r->dropped_pending = 0;
    pthread_mutex_unlock(&r->lock);
    if (out_size) out[used] = '\0';
    return n;
}

void event_ring_stats(EventRing *r, uint64_t *pushed, uint64_t *delivered, uint64_t *dropped) {
    pthread_mutex_lock(&r->lock);
    if (pushed) *pushed = r->pushed;
    if (delivered) *delivered = r->delivered;
    if (dropped) *dropped = r->dropped;
    pthread_mutex_unlock(&r->lock);
}
