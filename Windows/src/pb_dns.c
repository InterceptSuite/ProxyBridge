#include "pb_internal.h"

// DNS snoop cache: maps intercepted A/AAAA answers back to hostnames.

// dns cache
void dns_cache_init(void)
{
    InitializeSRWLock(&g_dns_cache_lock);
    memset(g_dns_cache,    0, sizeof(g_dns_cache));
    memset(g_dns_cache_v6, 0, sizeof(g_dns_cache_v6));
}

UINT32 dns_bucket(UINT32 ip)
{
    return (ip * 2654435761u) >> (32 - 10);  // Knuth multiplicative hash 1024 buckets
}

void dns_cache_store(UINT32 ip, const char *domain)
{
    if (!domain || domain[0] == '\0') return;
    UINT32 bucket = dns_bucket(ip);
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_dns_cache_lock);
    DNS_CACHE_ENTRY *e = g_dns_cache[bucket];
    while (e)
    {
        if (e->ip == ip)
        {
            strncpy_s(e->domain, sizeof(e->domain), domain, _TRUNCATE);
            e->expire_tick = now + DNS_CACHE_TTL_MS;
            ReleaseSRWLockExclusive(&g_dns_cache_lock);
            return;
        }
        e = e->next;
    }
    DNS_CACHE_ENTRY *ne = (DNS_CACHE_ENTRY *)malloc(sizeof(DNS_CACHE_ENTRY));
    if (ne)
    {
        ne->ip         = ip;
        ne->expire_tick = now + DNS_CACHE_TTL_MS;
        strncpy_s(ne->domain, sizeof(ne->domain), domain, _TRUNCATE);
        ne->next           = g_dns_cache[bucket];
        g_dns_cache[bucket] = ne;
    }
    ReleaseSRWLockExclusive(&g_dns_cache_lock);
}

BOOL dns_cache_lookup(UINT32 ip, char *out_domain, size_t out_size)
{
    UINT32 bucket = dns_bucket(ip);
    ULONGLONG now = GetTickCount64();
    BOOL found = FALSE;

    AcquireSRWLockShared(&g_dns_cache_lock);
    DNS_CACHE_ENTRY *e = g_dns_cache[bucket];
    while (e)
    {
        if (e->ip == ip && e->expire_tick > now)
        {
            strncpy_s(out_domain, out_size, e->domain, _TRUNCATE);
            found = TRUE;
            break;
        }
        e = e->next;
    }
    ReleaseSRWLockShared(&g_dns_cache_lock);
    return found;
}

UINT32 dns_bucket_v6(const UINT8 ip6[16])
{
    // FNV-1a over 16 bytes, folded to DNS_CACHE_BUCKETS
    UINT32 h = 2166136261u;
    for (int i = 0; i < 16; i++)
        h = (h ^ ip6[i]) * 16777619u;
    return h & (DNS_CACHE_BUCKETS - 1);
}

void dns_cache_store_v6(const UINT8 ip6[16], const char *domain)
{
    if (!domain || domain[0] == '\0') return;
    UINT32 bucket = dns_bucket_v6(ip6);
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_dns_cache_lock);
    DNS_CACHE_ENTRY_V6 *e = g_dns_cache_v6[bucket];
    while (e)
    {
        if (memcmp(e->ip6, ip6, 16) == 0)
        {
            strncpy_s(e->domain, sizeof(e->domain), domain, _TRUNCATE);
            e->expire_tick = now + DNS_CACHE_TTL_MS;
            ReleaseSRWLockExclusive(&g_dns_cache_lock);
            return;
        }
        e = e->next;
    }
    DNS_CACHE_ENTRY_V6 *ne = (DNS_CACHE_ENTRY_V6 *)malloc(sizeof(DNS_CACHE_ENTRY_V6));
    if (ne)
    {
        memcpy(ne->ip6, ip6, 16);
        ne->expire_tick = now + DNS_CACHE_TTL_MS;
        strncpy_s(ne->domain, sizeof(ne->domain), domain, _TRUNCATE);
        ne->next = g_dns_cache_v6[bucket];
        g_dns_cache_v6[bucket] = ne;
    }
    ReleaseSRWLockExclusive(&g_dns_cache_lock);
}

BOOL dns_cache_lookup_v6(const UINT8 ip6[16], char *out_domain, size_t out_size)
{
    UINT32 bucket = dns_bucket_v6(ip6);
    ULONGLONG now = GetTickCount64();
    BOOL found = FALSE;

    AcquireSRWLockShared(&g_dns_cache_lock);
    DNS_CACHE_ENTRY_V6 *e = g_dns_cache_v6[bucket];
    while (e)
    {
        if (memcmp(e->ip6, ip6, 16) == 0 && e->expire_tick > now)
        {
            strncpy_s(out_domain, out_size, e->domain, _TRUNCATE);
            found = TRUE;
            break;
        }
        e = e->next;
    }
    ReleaseSRWLockShared(&g_dns_cache_lock);
    return found;
}

// Parse a DNS name (with pointer compression) at msg[*offset] into dst.
// Advances *offset past the name on success.
BOOL dns_parse_name(const UINT8 *msg, int msg_len, int *offset, char *dst, int dst_len)
{
    int pos    = *offset;
    int out    = 0;
    int jumps  = 0;
    BOOL jumped      = FALSE;
    int  jumped_end  = -1;

    while (pos < msg_len)
    {
        UINT8 b = msg[pos];
        if (b == 0x00)
        {
            dst[out] = '\0';
            if (!jumped) *offset = pos + 1;
            else         *offset = jumped_end;
            return TRUE;
        }
        if ((b & 0xC0) == 0xC0)
        {
            if (pos + 1 >= msg_len) return FALSE;
            if (!jumped) jumped_end = pos + 2;
            jumped = TRUE;
            pos = ((b & 0x3F) << 8) | msg[pos + 1];
            if (++jumps > 10) return FALSE;
            continue;
        }
        int label_len = (int)b;
        pos++;
        if (pos + label_len > msg_len)       return FALSE;
        if (out + label_len + 2 >= dst_len)  return FALSE;
        if (out > 0) dst[out++] = '.';
        memcpy(&dst[out], &msg[pos], label_len);
        out  += label_len;
        pos  += label_len;
    }
    return FALSE;
}

// Snoop an inbound DNS response (UDP payload starting at the DNS header).
// For every A-record answer, store ip → qname in the DNS cache.
void snoop_dns_response(const UINT8 *payload, int payload_len)
{
    if (payload_len < 12) return;

    UINT16 flags   = ((UINT16)payload[2] << 8) | payload[3];
    if (!(flags & 0x8000)) return;   // not a response
    if  (flags & 0x000F)   return;   // RCODE != NOERROR

    UINT16 qdcount = ((UINT16)payload[4] << 8) | payload[5];
    UINT16 ancount = ((UINT16)payload[6] << 8) | payload[7];
    if (ancount == 0) return;

    int offset = 12;

    // Extract the first question's name as the canonical hostname for this answer.
    char qname[256];
    if (!dns_parse_name(payload, payload_len, &offset, qname, sizeof(qname))) return;
    offset += 4;  // QTYPE + QCLASS

    // Skip any remaining questions
    for (int q = 1; q < qdcount && offset < payload_len; q++)
    {
        char tmp[256];
        if (!dns_parse_name(payload, payload_len, &offset, tmp, sizeof(tmp))) return;
        offset += 4;
    }

    // Parse answer RRs
    for (int i = 0; i < ancount && offset < payload_len; i++)
    {
        char rname[256];
        if (!dns_parse_name(payload, payload_len, &offset, rname, sizeof(rname))) return;
        if (offset + 10 > payload_len) return;

        UINT16 rtype  = ((UINT16)payload[offset + 0] << 8) | payload[offset + 1];
        UINT16 rclass = ((UINT16)payload[offset + 2] << 8) | payload[offset + 3];
        UINT16 rdlen  = ((UINT16)payload[offset + 8] << 8) | payload[offset + 9];
        offset += 10;
        if (offset + rdlen > payload_len) return;

        if (rtype == 1 /* A */ && rclass == 1 /* IN */ && rdlen == 4)
        {
            UINT32 ip;
            memcpy(&ip, &payload[offset], 4);  // network-byte-order, matches ip_header->DstAddr
            dns_cache_store(ip, qname);
        }
        else if (rtype == 28 /* AAAA */ && rclass == 1 /* IN */ && rdlen == 16)
        {
            dns_cache_store_v6(&payload[offset], qname);
        }
        offset += rdlen;
    }
}

// Prune expired DNS-snoop entries (IPv4 + IPv6) so the caches don't grow without bound.
void cleanup_stale_dns_cache(void)
{
    ULONGLONG now = GetTickCount64();

    AcquireSRWLockExclusive(&g_dns_cache_lock);
    for (int i = 0; i < DNS_CACHE_BUCKETS; i++)
    {
        DNS_CACHE_ENTRY **pp = &g_dns_cache[i];
        while (*pp != NULL)
        {
            if ((*pp)->expire_tick <= now)
            {
                DNS_CACHE_ENTRY *to_free = *pp;
                *pp = (*pp)->next;
                free(to_free);
            }
            else
            {
                pp = &(*pp)->next;
            }
        }

        DNS_CACHE_ENTRY_V6 **pp6 = &g_dns_cache_v6[i];
        while (*pp6 != NULL)
        {
            if ((*pp6)->expire_tick <= now)
            {
                DNS_CACHE_ENTRY_V6 *to_free = *pp6;
                *pp6 = (*pp6)->next;
                free(to_free);
            }
            else
            {
                pp6 = &(*pp6)->next;
            }
        }
    }
    ReleaseSRWLockExclusive(&g_dns_cache_lock);
}

// Flush the Windows DNS resolver cache so applications re-resolve hostnames on the
// wire, where our port-53 snoop can capture the IP->hostname mapping. Without this a
// domain that was resolved before a domain rule existed would have no cached mapping
// and the rule could not match. DnsFlushResolverCache is loaded dynamically so we
// avoid a hard dnsapi.lib dependency (keeps the MinGW/GCC build path unchanged).
void flush_dns_resolver_cache(void)
{
    HMODULE dnsapi = LoadLibraryA("dnsapi.dll");
    if (dnsapi == NULL)
        return;
    typedef BOOL (WINAPI *DnsFlushFn)(void);
    DnsFlushFn fn = (DnsFlushFn)GetProcAddress(dnsapi, "DnsFlushResolverCache");
    if (fn != NULL)
        fn();
    FreeLibrary(dnsapi);
}

