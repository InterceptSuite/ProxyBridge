#ifndef PROXYBRIDGE_GUI_EVENTS_H
#define PROXYBRIDGE_GUI_EVENTS_H

#include <stddef.h>
#include <stdint.h>

typedef struct EventRing EventRing;

EventRing *event_ring_new(size_t capacity, size_t slot_size);
void event_ring_free(EventRing *r);

// any thread; text is truncated to slot_size - 1, the oldest event is dropped when full
void event_ring_push(EventRing *r, const char *text);

// moves events into out as "text\n" lines (NUL terminated), stops at max_events or when out is full.
// *dropped receives the number of events dropped since the previous drain
size_t event_ring_drain(EventRing *r, char *out, size_t out_size, size_t max_events, uint64_t *dropped);

void event_ring_stats(EventRing *r, uint64_t *pushed, uint64_t *delivered, uint64_t *dropped);

#endif
