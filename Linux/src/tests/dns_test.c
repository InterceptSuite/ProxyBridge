#include <stdbool.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../pb_dns.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

// tiny DNS message builder -------------------------------------------------------------------------------------------
struct msg { uint8_t b[2048]; size_t n; };
static void w16(struct msg *m, unsigned v) { m->b[m->n++] = (uint8_t)(v >> 8); m->b[m->n++] = (uint8_t)v; }
static void w32(struct msg *m, unsigned v) { w16(m, v >> 16); w16(m, v & 0xffff); }
static size_t wname(struct msg *m, const char *name)
{
    size_t start = m->n;
    while (*name) {
        const char *dot = strchr(name, '.'); size_t l = dot ? (size_t)(dot - name) : strlen(name);
        m->b[m->n++] = (uint8_t)l; memcpy(m->b + m->n, name, l); m->n += l; name += l + (dot ? 1 : 0);
    }
    m->b[m->n++] = 0;
    return start;
}
static void ptr(struct msg *m, size_t at) { w16(m, 0xC000 | (unsigned)at); }
static void header(struct msg *m, unsigned flags, unsigned qd, unsigned an) { m->n = 0; w16(m, 0x1234); w16(m, flags); w16(m, qd); w16(m, an); w16(m, 0); w16(m, 0); }
static void a_rr(struct msg *m, size_t owner_off, const char *ip) { ptr(m, owner_off); w16(m, 1); w16(m, 1); w32(m, 60); w16(m, 4); struct in_addr a; inet_pton(AF_INET, ip, &a); memcpy(m->b + m->n, &a, 4); m->n += 4; }
static uint32_t H(const char *ip) { struct in_addr a; inet_pton(AF_INET, ip, &a); return ntohl(a.s_addr); }
static bool has(uint32_t ip, const char *name) { char n[8][256]; int c = pb_dns_lookup(ip, n, 8); for (int i = 0; i < c; i++) if (!strcmp(n[i], name)) return true; return false; }

int main(void)
{
    struct msg m; struct pb_dns_result r;

    // 1. plain A answer with a compressed owner name
    header(&m, 0x8180, 1, 2); size_t q = wname(&m, "www.Example.COM"); w16(&m, 1); w16(&m, 1);
    a_rr(&m, q, "93.184.216.34"); a_rr(&m, q, "93.184.216.35");
    CHECK(pb_dns_observe(m.b, m.n, &r) == 2 && r.nips == 2);
    CHECK(has(H("93.184.216.34"), "www.example.com") && has(H("93.184.216.35"), "www.example.com"));   // lower-cased

    // 2. CNAME chain: www.shop.test -> cdn.edge.net -> A
    header(&m, 0x8180, 1, 3); q = wname(&m, "www.shop.test"); w16(&m, 1); w16(&m, 1);
    ptr(&m, q); w16(&m, 5); w16(&m, 1); w32(&m, 300); size_t lenpos = m.n; w16(&m, 0); size_t t = wname(&m, "cdn.edge.net"); w16(&m, 0); /* patch below */
    m.b[lenpos] = 0; m.b[lenpos + 1] = (uint8_t)(m.n - lenpos - 2 - 2); m.n -= 2;
    a_rr(&m, t, "198.51.100.7");
    // fix an count (we wrote 3 but only 2 RRs)
    m.b[7] = 2;
    CHECK(pb_dns_observe(m.b, m.n, &r) == 1);
    CHECK(has(H("198.51.100.7"), "www.shop.test") && has(H("198.51.100.7"), "cdn.edge.net"));

    // 2b. out-of-bailiwick records are ignored: an unrelated A record and a CNAME that the question does not lead to
    header(&m, 0x8180, 1, 3); q = wname(&m, "q.example"); w16(&m, 1); w16(&m, 1);
    a_rr(&m, q, "203.0.113.1");
    { size_t o = wname(&m, "allowed.corp"); (void)o; w16(&m, 1); w16(&m, 1); w32(&m, 60); w16(&m, 4);
      struct in_addr a; inet_pton(AF_INET, "203.0.113.2", &a); memcpy(m.b + m.n, &a, 4); m.n += 4; }
    { size_t o = wname(&m, "victim.bank"); (void)o; w16(&m, 5); w16(&m, 1); w32(&m, 60); size_t lp = m.n; w16(&m, 0);
      wname(&m, "q.example"); m.b[lp + 1] = (uint8_t)(m.n - lp - 2); }
    CHECK(pb_dns_observe(m.b, m.n, &r) == 1 && r.nips == 1);                                 // only q.example's own address
    CHECK(has(H("203.0.113.1"), "q.example") && !has(H("203.0.113.1"), "allowed.corp") && !has(H("203.0.113.1"), "victim.bank"));
    CHECK(!has(H("203.0.113.2"), "allowed.corp") && !has(H("203.0.113.2"), "q.example"));

    // 3. rejects: query (QR=0), NXDOMAIN, no answers, loopback answers
    header(&m, 0x0100, 1, 0); q = wname(&m, "x.test"); w16(&m, 1); w16(&m, 1);
    CHECK(pb_dns_observe(m.b, m.n, &r) == 0);
    header(&m, 0x8183, 1, 0); q = wname(&m, "x.test"); w16(&m, 1); w16(&m, 1);
    CHECK(pb_dns_observe(m.b, m.n, &r) == 0);
    header(&m, 0x8180, 1, 1); q = wname(&m, "local.test"); w16(&m, 1); w16(&m, 1); a_rr(&m, q, "127.0.0.9");
    pb_dns_observe(m.b, m.n, &r); CHECK(!has(H("127.0.0.9"), "local.test"));

    // 4. hostile input must not crash or loop: pointer loops, truncated records, random garbage
    header(&m, 0x8180, 1, 1); m.b[m.n++] = 0xC0; m.b[m.n++] = 12;            // name pointing at itself
    w16(&m, 1); w16(&m, 1); CHECK(pb_dns_observe(m.b, m.n, &r) == 0);
    header(&m, 0x8180, 1, 1); q = wname(&m, "t.test"); w16(&m, 1); w16(&m, 1); ptr(&m, q); w16(&m, 1); w16(&m, 1); w32(&m, 1); w16(&m, 4); m.b[m.n++] = 1;   // rdata truncated
    CHECK(pb_dns_observe(m.b, m.n, &r) == 0);
    srand(7);
    for (int i = 0; i < 200000; i++) {
        size_t n = (size_t)(rand() % 200); uint8_t g[200];
        for (size_t k = 0; k < n; k++) g[k] = (uint8_t)rand();
        if (n >= 12 && (i & 1)) { g[2] = 0x81; g[3] = 0x80; g[5] = 1; g[7] = (uint8_t)(1 + rand() % 3); }
        pb_dns_observe(g, n, &r);
    }

    // 5. bounded table: oldest mappings are evicted and reported
    pb_dns_clear();
    int evicted = 0;
    for (uint32_t i = 0; i < PB_DNS_MAX_ENTRIES + 500; i++) {
        header(&m, 0x8180, 1, 1); q = wname(&m, "bulk.test"); w16(&m, 1); w16(&m, 1);
        ptr(&m, q); w16(&m, 1); w16(&m, 1); w32(&m, 60); w16(&m, 4); uint32_t ip = 0x0A000000u + 0x010000u + i; m.b[m.n++] = (uint8_t)(ip >> 24); m.b[m.n++] = (uint8_t)(ip >> 16); m.b[m.n++] = (uint8_t)(ip >> 8); m.b[m.n++] = (uint8_t)ip;
        pb_dns_observe(m.b, m.n, &r); evicted += r.nevicted;
    }
    CHECK(pb_dns_count() == PB_DNS_MAX_ENTRIES); CHECK(evicted == 500);
    CHECK(!has(0x0A010000u, "bulk.test") && has(0x0A010000u + 600, "bulk.test"));

    // 6. /etc/hosts style file
    pb_dns_clear();
    FILE *f = fopen("/tmp/pb_dns_test_hosts", "w"); fprintf(f, "# c\n127.0.0.1 localhost\n192.0.2.44 intranet.test wiki.Intranet.test # x\n::1 ip6\nbogus line\n"); fclose(f);
    CHECK(pb_dns_load_hosts("/tmp/pb_dns_test_hosts", &r) == 1);
    CHECK(has(H("192.0.2.44"), "intranet.test") && has(H("192.0.2.44"), "wiki.intranet.test"));
    remove("/tmp/pb_dns_test_hosts");

    printf(fails ? "DNS TESTS FAILED (%d)\n" : "dns tests passed\n", fails);
    return fails != 0;
}
