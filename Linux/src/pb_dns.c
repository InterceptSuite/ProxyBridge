#include <stdbool.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pb_dns.h"

#define BUCKETS 16384

struct ent {
    uint32_t ip;
    char *names[PB_DNS_MAX_NAMES]; int n;
    struct ent *hnext;                      // hash chain
    struct ent *prev, *next;                // age order: head = oldest
};

static struct {
    pthread_mutex_t lock;
    struct ent *bucket[BUCKETS];
    struct ent *head, *tail;
    size_t count;
} T = { .lock = PTHREAD_MUTEX_INITIALIZER };

static unsigned hash_ip(uint32_t ip) { ip *= 2654435761u; return (ip >> 12) & (BUCKETS - 1); }

static void ent_unlink_age(struct ent *e)
{
    if (e->prev) e->prev->next = e->next; else T.head = e->next;
    if (e->next) e->next->prev = e->prev; else T.tail = e->prev;
    e->prev = e->next = NULL;
}

static void ent_push_tail(struct ent *e)
{
    e->prev = T.tail; e->next = NULL;
    if (T.tail) T.tail->next = e; else T.head = e;
    T.tail = e;
}

static void ent_free(struct ent *e)
{
    for (int i = 0; i < e->n; i++) free(e->names[i]);
    free(e);
}

static void evict_oldest(struct pb_dns_result *res)
{
    struct ent *e = T.head;
    if (!e) return;
    ent_unlink_age(e);
    for (struct ent **pp = &T.bucket[hash_ip(e->ip)]; *pp; pp = &(*pp)->hnext)
        if (*pp == e) { *pp = e->hnext; break; }
    if (res && res->nevicted < 32) res->evicted[res->nevicted++] = e->ip;
    ent_free(e);
    T.count--;
}

static struct ent *find(uint32_t ip)
{
    for (struct ent *e = T.bucket[hash_ip(ip)]; e; e = e->hnext) if (e->ip == ip) return e;
    return NULL;
}

// Adds names to ip's entry (creating it), refreshing its age. Caller holds the lock.
static void add_mapping(uint32_t ip, char names[][256], int nn, struct pb_dns_result *res)
{
    struct ent *e = find(ip);
    if (!e) {
        while (T.count >= PB_DNS_MAX_ENTRIES) evict_oldest(res);
        e = calloc(1, sizeof *e);
        if (!e) return;
        e->ip = ip;
        unsigned h = hash_ip(ip);
        e->hnext = T.bucket[h]; T.bucket[h] = e;
        T.count++;
    } else {
        ent_unlink_age(e);
    }
    ent_push_tail(e);
    for (int i = 0; i < nn; i++) {
        bool have = false;
        for (int j = 0; j < e->n; j++) if (!strcmp(e->names[j], names[i])) { have = true; break; }
        if (have) continue;
        char *c = strdup(names[i]);
        if (!c) continue;
        if (e->n == PB_DNS_MAX_NAMES) { free(e->names[0]); memmove(&e->names[0], &e->names[1], (PB_DNS_MAX_NAMES - 1) * sizeof(char *)); e->n--; }
        e->names[e->n++] = c;
    }
    // names[0] is the name the application asked for: keep it last, where the lookup reports "most recent"
    for (int j = 0; j + 1 < e->n && nn > 0; j++) {
        if (strcmp(e->names[j], names[0]) != 0) continue;
        char *q = e->names[j];
        memmove(&e->names[j], &e->names[j + 1], (size_t)(e->n - j - 1) * sizeof(char *));
        e->names[e->n - 1] = q;
        break;
    }
    if (res) {
        bool dup = false;
        for (int i = 0; i < res->nips; i++) if (res->ips[i] == ip) dup = true;
        if (!dup && res->nips < 32) res->ips[res->nips++] = ip;
    }
}


// Reads a (possibly compressed) name at *off into out (lower-case, dotted). Advances *off past the name as stored at that
// position. Returns false on malformed data.
static bool read_name(const uint8_t *m, size_t len, size_t *off, char *out, size_t outsz)
{
    size_t pos = *off, o = 0;
    int hops = 0;
    bool jumped = false;
    for (;;) {
        if (pos >= len) return false;
        uint8_t l = m[pos];
        if (l == 0) { pos++; break; }
        if ((l & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return false;
            size_t ptr = ((size_t)(l & 0x3F) << 8) | m[pos + 1];
            if (!jumped) *off = pos + 2;
            jumped = true;
            if (++hops > 16 || ptr >= len) return false;
            pos = ptr;
            continue;
        }
        if (l & 0xC0) return false;
        if (pos + 1 + l > len) return false;
        if (o + l + 2 > outsz) return false;
        if (o) out[o++] = '.';
        for (uint8_t i = 0; i < l; i++) out[o++] = (char)tolower(m[pos + 1 + i]);
        pos += 1u + l;
    }
    out[o] = 0;
    if (!jumped) *off = pos;
    return true;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

int pb_dns_observe(const uint8_t *m, size_t len, struct pb_dns_result *res)
{
    if (res) memset(res, 0, sizeof *res);
    if (len < 12) return 0;
    uint16_t flags = rd16(m + 2), qd = rd16(m + 4), an = rd16(m + 6);
    if (!(flags & 0x8000) || (flags & 0x7800) || (flags & 0x000F)) return 0;   // response, QUERY opcode, NOERROR only
    if (qd > 4 || an == 0 || an > 128) return 0;

    char names[PB_DNS_MAX_NAMES][256];
    int nn = 0;
    size_t off = 12;
    char buf[256];
    for (int i = 0; i < qd; i++) {
        if (!read_name(m, len, &off, buf, sizeof buf) || off + 4 > len) return 0;
        off += 4;
        if (nn < PB_DNS_MAX_NAMES) { bool dup = false; for (int k = 0; k < nn; k++) if (!strcmp(names[k], buf)) dup = true; if (!dup) strcpy(names[nn++], buf); }
    }

    uint32_t ips[64]; int nips = 0;
    struct { size_t rdata; uint16_t type, rdlen; char owner[256]; } rr[128];
    int nrr = 0;
    for (int i = 0; i < an; i++) {
        char owner[256];
        if (!read_name(m, len, &off, owner, sizeof owner) || off + 10 > len) break;
        uint16_t type = rd16(m + off), rdlen = rd16(m + off + 8);
        size_t rd = off + 10;
        if (rd + rdlen > len) break;
        strcpy(rr[nrr].owner, owner); rr[nrr].type = type; rr[nrr].rdlen = rdlen; rr[nrr].rdata = rd; nrr++;
        off = rd + rdlen;
    }
    // Only records that descend from the question count: the question names, the targets of CNAMEs owned by one of
    // those names (chained), and A records owned by a name in that set. An answer section that also carries
    // "other.example A 1.2.3.4" or an unrelated CNAME must not teach the engine anything about those names.
    bool in_set[128] = { false };
    for (int round = 0; round < 8; round++) {
        bool grew = false;
        for (int i = 0; i < nrr; i++) {
            if (rr[i].type != 5 || in_set[i]) continue;
            bool owner_known = false;
            for (int k = 0; k < nn; k++) if (!strcmp(names[k], rr[i].owner)) owner_known = true;
            if (!owner_known) continue;
            in_set[i] = true;
            char target[256];
            size_t o2 = rr[i].rdata;
            if (!read_name(m, len, &o2, target, sizeof target)) continue;
            bool dup = false;
            for (int k = 0; k < nn; k++) if (!strcmp(names[k], target)) dup = true;
            if (!dup && nn < PB_DNS_MAX_NAMES) { strcpy(names[nn++], target); grew = true; }
        }
        if (!grew) break;
    }
    for (int i = 0; i < nrr; i++) {
        if (rr[i].type != 1 || rr[i].rdlen != 4 || nips >= 64) continue;
        bool owner_known = false;
        for (int k = 0; k < nn; k++) if (!strcmp(names[k], rr[i].owner)) owner_known = true;
        if (!owner_known) continue;                              // out of bailiwick
        ips[nips++] = ((uint32_t)m[rr[i].rdata] << 24) | ((uint32_t)m[rr[i].rdata + 1] << 16) | ((uint32_t)m[rr[i].rdata + 2] << 8) | m[rr[i].rdata + 3];
    }
    if (!nips || !nn) return 0;

    pthread_mutex_lock(&T.lock);
    for (int i = 0; i < nips; i++) {
        uint32_t ip = ips[i];
        if ((ip >> 24) == 127 || ip == 0) continue;              // answers pointing at loopback/unspecified are never redirected
        add_mapping(ip, names, nn, res);
    }
    pthread_mutex_unlock(&T.lock);
    return nips;
}

int pb_dns_lookup(uint32_t ip, char out[][256], int max)
{
    int n = 0;
    pthread_mutex_lock(&T.lock);
    struct ent *e = find(ip);
    if (e) for (; n < e->n && n < max; n++) snprintf(out[n], 256, "%s", e->names[n]);
    pthread_mutex_unlock(&T.lock);
    return n;
}

int pb_dns_load_hosts(const char *path, struct pb_dns_result *res)
{
    if (res) memset(res, 0, sizeof *res);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    int added = 0;
    while (fgets(line, sizeof line, f)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        char *save = NULL, *ipstr = strtok_r(line, " \t\r\n", &save);
        struct in_addr a;
        if (!ipstr || inet_pton(AF_INET, ipstr, &a) != 1) continue;
        uint32_t ip = ntohl(a.s_addr);
        if ((ip >> 24) == 127 || ip == 0) continue;
        char names[PB_DNS_MAX_NAMES][256];
        int nn = 0;
        for (char *nm; nn < PB_DNS_MAX_NAMES && (nm = strtok_r(NULL, " \t\r\n", &save)); ) {
            snprintf(names[nn], 256, "%s", nm);
            for (char *c = names[nn]; *c; c++) *c = (char)tolower((unsigned char)*c);
            nn++;
        }
        if (!nn) continue;
        pthread_mutex_lock(&T.lock);
        add_mapping(ip, names, nn, res);
        pthread_mutex_unlock(&T.lock);
        added++;
    }
    fclose(f);
    return added;
}

void pb_dns_for_each(void (*cb)(uint32_t, const char *const *, int, void *), void *ctx)
{
    pthread_mutex_lock(&T.lock);
    for (struct ent *e = T.head; e; e = e->next) cb(e->ip, (const char *const *)e->names, e->n, ctx);
    pthread_mutex_unlock(&T.lock);
}

void pb_dns_clear(void)
{
    pthread_mutex_lock(&T.lock);
    while (T.head) evict_oldest(NULL);
    pthread_mutex_unlock(&T.lock);
}

size_t pb_dns_count(void)
{
    pthread_mutex_lock(&T.lock);
    size_t n = T.count;
    pthread_mutex_unlock(&T.lock);
    return n;
}
