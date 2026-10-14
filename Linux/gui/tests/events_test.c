// event ring: ordering, drop accounting, multi-producer stress (run under ASan and TSan too)
#include "gui_events.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PRODUCERS 8
#define PER_PRODUCER 200000

static int failures = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static EventRing *ring;

static void *producer(void *arg) {
    int id = (int)(intptr_t)arg;
    char buf[64];
    for (int i = 0; i < PER_PRODUCER; i++) {
        snprintf(buf, sizeof(buf), "%d:%d", id, i);
        event_ring_push(ring, buf);
    }
    return NULL;
}

// "id:seq" without strto*
static int parse_event(const char *s, int *id, long *seq) {
    int i = 0;
    *id = 0;
    for (; s[i] >= '0' && s[i] <= '9'; i++) *id = *id * 10 + (s[i] - '0');
    if (s[i++] != ':') return 0;
    *seq = 0;
    for (; s[i] >= '0' && s[i] <= '9'; i++) *seq = *seq * 10 + (s[i] - '0');
    return s[i] == '\n' || s[i] == '\0';
}

int main() {
    // fifo + drop accounting on a tiny ring
    EventRing *small = event_ring_new(4, 16);
    char out[256];
    uint64_t dropped = 0;
    char buf[16];
    for (int i = 0; i < 10; i++) { snprintf(buf, sizeof(buf), "e%d", i); event_ring_push(small, buf); }
    CHECK(event_ring_drain(small, out, sizeof(out), 100, &dropped) == 4);
    CHECK(dropped == 6 && strcmp(out, "e6\ne7\ne8\ne9\n") == 0);
    CHECK(event_ring_drain(small, out, sizeof(out), 100, &dropped) == 0 && dropped == 0 && out[0] == '\0');
    event_ring_push(small, "0123456789abcdefXYZ");
    CHECK(event_ring_drain(small, out, sizeof(out), 100, &dropped) == 1 && strcmp(out, "0123456789abcde\n") == 0);
    event_ring_push(small, "a"); event_ring_push(small, "b"); event_ring_push(small, "c");
    CHECK(event_ring_drain(small, out, 6, 100, &dropped) == 2 && strcmp(out, "a\nb\n") == 0);
    CHECK(event_ring_drain(small, out, sizeof(out), 1, &dropped) == 1 && strcmp(out, "c\n") == 0);
    event_ring_free(small);
    CHECK(event_ring_new(0, 8) == NULL);

    // multi producer stress with a slow consumer
    ring = event_ring_new(4096, 512);
    pthread_t th[PRODUCERS];
    for (long i = 0; i < PRODUCERS; i++) pthread_create(&th[i], NULL, producer, (void *)(intptr_t)i);

    static char big[256 * 1024];
    long last[PRODUCERS];
    for (int i = 0; i < PRODUCERS; i++) last[i] = -1;
    uint64_t delivered = 0, reported_dropped = 0;
    int done = 0;
    for (int round = 0; ; round++) {
        uint64_t d = 0;
        size_t n = event_ring_drain(ring, big, sizeof(big), 2000, &d);
        reported_dropped += d;
        delivered += n;
        size_t seen = 0;
        for (char *p = big; *p; ) {
            char *nl = strchr(p, '\n');
            int id = 0; long seq = 0;
            CHECK(nl && parse_event(p, &id, &seq) && id >= 0 && id < PRODUCERS);
            if (!nl || id < 0 || id >= PRODUCERS) break;
            CHECK(seq > last[id]);
            last[id] = seq;
            seen++;
            p = nl + 1;
        }
        CHECK(seen == n);
        if (round % 4 == 0) usleep(1000);
        if (!done) {
            done = 1;
            uint64_t pushed;
            event_ring_stats(ring, &pushed, NULL, NULL);
            done = pushed == (uint64_t)PRODUCERS * PER_PRODUCER;
        } else if (n == 0) {
            break;
        }
    }
    for (int i = 0; i < PRODUCERS; i++) pthread_join(th[i], NULL);

    uint64_t pushed, del, drop;
    event_ring_stats(ring, &pushed, &del, &drop);
    printf("pushed=%llu delivered=%llu dropped=%llu\n", (unsigned long long)pushed, (unsigned long long)del, (unsigned long long)drop);
    CHECK(pushed == (uint64_t)PRODUCERS * PER_PRODUCER);
    CHECK(pushed == del + drop);
    CHECK(del == delivered);
    CHECK(drop == reported_dropped);
    event_ring_free(ring);

    if (!failures) printf("events_test: all passed\n");
    return failures ? 1 : 0;
}
