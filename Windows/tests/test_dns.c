// test_dns.c - the DNS reply parser that feeds domain rules (src\pb_dns.c: snoop_dns_response, dns_parse_name).
// It parses packets straight off the network, so every test here also runs the parser on a buffer that ends exactly
// at a no-access guard page: reading even one byte past the packet crashes the test (and fails it).
#include "pb_internal.h"
#include "pbtest.h"

/* guard-page buffer (pbtest.h): the data ends exactly where unreadable memory begins */
#define guarded(data, len, base) pb_guarded((data), (size_t)(len), (base))
#define release(base) pb_guard_release(base)

/* ---- packet builder ---- */
typedef struct { BYTE b[1500]; int n; } Pkt;
static void u8(Pkt* p, int v)  { p->b[p->n++] = (BYTE)v; }
static void u16(Pkt* p, int v) { u8(p, v >> 8); u8(p, v); }
static void u32(Pkt* p, UINT32 v) { u16(p, v >> 16); u16(p, v & 0xFFFF); }
static void name(Pkt* p, const char* dotted)
{
    const char* s = dotted;
    while (*s) { const char* e = strchr(s, '.'); int l = e ? (int)(e - s) : (int)strlen(s); u8(p, l); memcpy(p->b + p->n, s, l); p->n += l; if (!e) break; s = e + 1; }
    u8(p, 0);
}
static void header(Pkt* p, int flags, int qd, int an) { p->n = 0; u16(p, 0x1234); u16(p, flags); u16(p, qd); u16(p, an); u16(p, 0); u16(p, 0); }
static void question(Pkt* p, const char* n, int type) { name(p, n); u16(p, type); u16(p, 1); }
static void answer_a(Pkt* p, const BYTE* ip) { u16(p, 0xC00C); u16(p, 1); u16(p, 1); u32(p, 60); u16(p, 4); memcpy(p->b + p->n, ip, 4); p->n += 4; }
static void answer_aaaa(Pkt* p, const BYTE* ip6) { u16(p, 0xC00C); u16(p, 28); u16(p, 1); u32(p, 60); u16(p, 16); memcpy(p->b + p->n, ip6, 16); p->n += 16; }
static void answer_cname(Pkt* p, const char* target) { u16(p, 0xC00C); u16(p, 5); u16(p, 1); u32(p, 60); int lenpos = p->n; u16(p, 0); int st = p->n; name(p, target); int l = p->n - st; p->b[lenpos] = (BYTE)(l >> 8); p->b[lenpos + 1] = (BYTE)l; }

static BOOL fed(const Pkt* p)           /* feed through a guarded buffer */
{
    void* base; BYTE* g = guarded(p->b, p->n, &base);
    snoop_dns_response(g, p->n);
    release(base); return TRUE;
}
static BOOL known(const BYTE* ip, const char* want)
{
    UINT32 v; memcpy(&v, ip, 4); char d[256];
    return dns_cache_lookup(v, d, sizeof d) && !strcmp(d, want);
}
static BOOL unknown(const BYTE* ip) { UINT32 v; memcpy(&v, ip, 4); char d[256]; return !dns_cache_lookup(v, d, sizeof d); }

int main(void)
{
    dns_cache_init();
    const BYTE ipA[4] = { 93, 184, 216, 34 }, ipB[4] = { 10, 11, 12, 13 }, ipC[4] = { 1, 2, 3, 4 };
    BYTE v6[16] = { 0x26, 0x06, 0x47, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0xac, 0x42, 0x93, 0xf3 };
    Pkt p;

    /* 1. a normal A reply is learned */
    header(&p, 0x8180, 1, 1); question(&p, "example.com", 1); answer_a(&p, ipA); fed(&p);
    CHECK(known(ipA, "example.com"));

    /* 2. AAAA reply */
    header(&p, 0x8180, 1, 1); question(&p, "ipv6.example.org", 28); answer_aaaa(&p, v6); fed(&p);
    { char d[256]; CHECK(dns_cache_lookup_v6(v6, d, sizeof d) && !strcmp(d, "ipv6.example.org")); }

    /* 3. CNAME chain then two A records: every address is mapped to the NAME THE APP ASKED FOR */
    header(&p, 0x8180, 1, 3); question(&p, "www.shop.example", 1);
    answer_cname(&p, "cdn.example.net"); answer_a(&p, ipB); answer_a(&p, ipC); fed(&p);
    CHECK(known(ipB, "www.shop.example") && known(ipC, "www.shop.example"));

    /* 4. replies that must be ignored */
    { BYTE ipX[4] = { 9, 9, 9, 1 };
      header(&p, 0x0100, 1, 1); question(&p, "query.example", 1); answer_a(&p, ipX); fed(&p); CHECK(unknown(ipX));          /* a query, not a response */
      header(&p, 0x8183, 1, 1); question(&p, "nx.example", 1); answer_a(&p, ipX); fed(&p);   CHECK(unknown(ipX));          /* RCODE = NXDOMAIN */
      header(&p, 0x8180, 1, 0); question(&p, "empty.example", 1); fed(&p);                    CHECK(unknown(ipX));          /* no answers */
      header(&p, 0x8180, 1, 1); question(&p, "short.example", 1); u16(&p, 0xC00C); u16(&p, 1); u16(&p, 1); u32(&p, 60); u16(&p, 5); u32(&p, 0x09090901); u8(&p, 0); fed(&p);
      CHECK(unknown(ipX));                                                                                                 /* A record with a 5-byte rdata */
      BYTE tiny[11] = { 0 }; void* b; BYTE* g = guarded(tiny, 11, &b); snoop_dns_response(g, 11); release(b); }            /* shorter than a header */

    /* 5. hostile names: pointer loops, label overruns, over-long names */
    { BYTE ipX[4] = { 9, 9, 9, 2 };
      header(&p, 0x8180, 1, 1); u8(&p, 0xC0); u8(&p, 0x0C); u16(&p, 1); u16(&p, 1); answer_a(&p, ipX); fed(&p);              /* the question name points at itself */
      CHECK(unknown(ipX));
      header(&p, 0x8180, 1, 1); u8(&p, 63); memset(p.b + p.n, 'a', 20); p.n += 20; fed(&p);                                /* label longer than the packet */
      header(&p, 0x8180, 1, 1); for (int i = 0; i < 6; i++) { u8(&p, 63); memset(p.b + p.n, 'b', 63); p.n += 63; } u8(&p, 0);
      u16(&p, 1); u16(&p, 1); answer_a(&p, ipX); fed(&p);                                                                  /* name of 380+ characters */
      CHECK(unknown(ipX)); }

    /* 6. counts that lie: more answers or questions than the packet holds */
    header(&p, 0x8180, 9, 9); question(&p, "liar.example", 1); fed(&p);
    header(&p, 0x8180, 1, 500); question(&p, "liar2.example", 1); { BYTE ipL[4] = { 7, 7, 7, 7 }; answer_a(&p, ipL); fed(&p); CHECK(known(ipL, "liar2.example")); }

    /* 7. every prefix of a valid reply, parsed from a buffer that ends exactly there (guard page after the last byte) */
    header(&p, 0x8180, 1, 3); question(&p, "prefix.example.com", 1); answer_cname(&p, "t.example.net"); answer_a(&p, ipA); answer_aaaa(&p, v6);
    for (int cut = 0; cut <= p.n; cut++) { void* b; BYTE* g = guarded(p.b, cut, &b); snoop_dns_response(g, cut); release(b); }
    CHECK(TRUE);

    /* 8. random packets, mutated valid packets, and random pointer soup: nothing may read outside the packet */
    srand(2026);
    int packets = 0;
    for (int it = 0; it < 60000; it++)
    {
        Pkt r;
        if (it % 3 == 0) { r.n = rand() % 200; for (int i = 0; i < r.n; i++) r.b[i] = (BYTE)rand(); if (r.n > 3 && rand() % 2) { r.b[2] |= 0x80; r.b[3] &= 0xF0; } }
        else { r = p; int flips = 1 + rand() % 4; for (int f = 0; f < flips; f++) r.b[rand() % r.n] = (BYTE)(rand() % 4 ? 0xC0 + rand() % 3 : rand()); if (it % 3 == 2) r.n = rand() % (r.n + 1); }
        void* b; BYTE* g = guarded(r.b, r.n, &b); snoop_dns_response(g, r.n); release(b); packets++;
    }
    CHECK(packets == 60000);

    return pbtest_done("test_dns");
}
