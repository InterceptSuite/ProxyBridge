#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pb_rules.h"

static void set_err(char *err, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_err(char *err, size_t n, const char *fmt, ...)
{
    if (!err || !n) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, n, fmt, ap);
    va_end(ap);
}

// Splits on ';' or ',' and trims whitespace. Returns the number of tokens (<= max) or -1 if there are more than max.
static int split_list(const char *s, char tokens[][256], int max)
{
    int n = 0;
    while (*s) {
        while (*s == ';' || *s == ',' || isspace((unsigned char)*s)) s++;
        if (!*s) break;
        const char *e = s;
        while (*e && *e != ';' && *e != ',') e++;
        const char *t = e;
        while (t > s && isspace((unsigned char)t[-1])) t--;
        if (n >= max) return -1;
        size_t len = (size_t)(t - s);
        if (len >= 256) len = 255;
        memcpy(tokens[n], s, len);
        tokens[n][len] = 0;
        n++;
        s = e;
    }
    return n;
}

bool pb_glob_match(const char *p, const char *s)
{
    const char *star = NULL, *ss = s;
    while (*s) {
        if (*p == '*') { star = p++; ss = s; }
        else if (*p == '?' || *p == *s) { p++; s++; }
        else if (star) { p = star + 1; s = ++ss; }
        else return false;
    }
    while (*p == '*') p++;
    return *p == 0;
}

static bool parse_uint(const char *s, size_t len, unsigned max, unsigned *out)
{
    if (!len || len > 5) return false;
    unsigned v = 0;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)s[i])) return false;
        v = v * 10 + (unsigned)(s[i] - '0');
    }
    if (v > max) return false;
    *out = v;
    return true;
}

static bool parse_ipv4(const char *s, uint32_t *out)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return false;
    *out = ntohl(a.s_addr);
    return true;
}

// "10", "*", "1-5" -> inclusive octet range
static bool parse_octet(const char *s, size_t len, uint8_t *lo, uint8_t *hi)
{
    unsigned a, b;
    if (len == 1 && s[0] == '*') { *lo = 0; *hi = 255; return true; }
    const char *dash = memchr(s, '-', len);
    if (dash) {
        if (!parse_uint(s, (size_t)(dash - s), 255, &a) || !parse_uint(dash + 1, len - (size_t)(dash - s) - 1, 255, &b) || a > b) return false;
        *lo = (uint8_t)a; *hi = (uint8_t)b;
        return true;
    }
    if (!parse_uint(s, len, 255, &a)) return false;
    *lo = *hi = (uint8_t)a;
    return true;
}

static bool v6_prefix_range(const uint8_t *base, unsigned prefix, uint8_t *lo, uint8_t *hi)
{
    if (prefix > 128) return false;
    for (int i = 0; i < 16; i++) {
        int bits = (int)prefix - i * 8;
        uint8_t mask = bits >= 8 ? 0xff : bits <= 0 ? 0 : (uint8_t)(0xff << (8 - bits));
        lo[i] = base[i] & mask;
        hi[i] = base[i] | (uint8_t)~mask;
    }
    return true;
}

static bool looks_like_domain(const char *tok)
{
    for (const char *c = tok; *c; c++)
        if (isalpha((unsigned char)*c) || *c == '_' || *c == '?') return true;
    return false;
}

static bool parse_domain_token(const char *tok, char *out, char *err, size_t errlen)
{
    size_t n = strlen(tok);
    if (n == 0 || n > 253) { set_err(err, errlen, "invalid domain pattern '%s'", tok); return false; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)tok[i];
        if (!(isalnum(c) || c == '-' || c == '.' || c == '_' || c == '*' || c == '?')) {
            set_err(err, errlen, "invalid character '%c' in domain pattern '%s'", c, tok);
            return false;
        }
        out[i] = (char)tolower(c);
    }
    out[n] = 0;
    if (out[0] == '.' || out[n - 1] == '.' || strstr(out, "..")) { set_err(err, errlen, "invalid domain pattern '%s'", tok); return false; }
    return true;
}

bool pb_domain_match(const char *pattern, const char *name)
{
    char lower[256];
    size_t n = strlen(name);
    if (n >= sizeof lower) return false;
    for (size_t i = 0; i <= n; i++) lower[i] = (char)tolower((unsigned char)name[i]);
    while (n && lower[n - 1] == '.') lower[--n] = 0;          // tolerate a trailing root dot
    return pb_glob_match(pattern, lower);
}

static bool parse_host_token(const char *tok, struct pb_host_pat *p, char *err, size_t errlen)
{
    memset(p, 0, sizeof *p);
    if (strchr(tok, ':')) {
        char buf[256];
        snprintf(buf, sizeof buf, "%s", tok);
        char *slash = strchr(buf, '/'), *dash = strchr(buf, '-');
        struct in6_addr a, b;
        p->kind = PB_HOST_V6_RANGE;
        if (slash) {
            *slash = 0;
            unsigned pre;
            if (inet_pton(AF_INET6, buf, &a) != 1 || !parse_uint(slash + 1, strlen(slash + 1), 128, &pre)) goto bad6;
            v6_prefix_range(a.s6_addr, pre, p->lo6, p->hi6);
        } else if (dash) {
            *dash = 0;
            if (inet_pton(AF_INET6, buf, &a) != 1 || inet_pton(AF_INET6, dash + 1, &b) != 1) goto bad6;
            if (memcmp(a.s6_addr, b.s6_addr, 16) > 0) { set_err(err, errlen, "IPv6 range '%s' has start > end", tok); return false; }
            memcpy(p->lo6, a.s6_addr, 16); memcpy(p->hi6, b.s6_addr, 16);
        } else {
            if (inet_pton(AF_INET6, buf, &a) != 1) goto bad6;
            memcpy(p->lo6, a.s6_addr, 16); memcpy(p->hi6, a.s6_addr, 16);
        }
        return true;
bad6:
        set_err(err, errlen, "invalid IPv6 address or range '%s'", tok);
        return false;
    }

    const char *slash = strchr(tok, '/'), *dash = strchr(tok, '-');
    uint32_t a, b;
    char buf[256];
    if (slash) {
        snprintf(buf, sizeof buf, "%.*s", (int)(slash - tok), tok);
        unsigned pre;
        if (!parse_ipv4(buf, &a) || !parse_uint(slash + 1, strlen(slash + 1), 32, &pre)) goto bad4;
        uint32_t mask = pre ? 0xffffffffu << (32 - pre) : 0;
        p->kind = PB_HOST_V4_RANGE; p->lo4 = a & mask; p->hi4 = a | ~mask;
        return true;
    }
    int dots_before = 0;
    for (const char *c = tok; dash && c < dash; c++) dots_before += *c == '.';
    if (dash && dots_before == 3) {
        snprintf(buf, sizeof buf, "%.*s", (int)(dash - tok), tok);
        if (!parse_ipv4(buf, &a) || !parse_ipv4(dash + 1, &b)) goto bad4;
        if (a > b) { set_err(err, errlen, "IPv4 range '%s' has start > end", tok); return false; }
        p->kind = PB_HOST_V4_RANGE; p->lo4 = a; p->hi4 = b;
        return true;
    }
    const char *s = tok;
    for (int i = 0; i < 4; i++) {
        const char *e = strchr(s, '.');
        size_t len = e ? (size_t)(e - s) : strlen(s);
        if ((i < 3) != (e != NULL)) goto bad4;
        if (!parse_octet(s, len, &p->box_lo[i], &p->box_hi[i])) goto bad4;
        s = e ? e + 1 : s + len;
    }
    // a box whose wildcard octets form a suffix collapses to a numeric range
    {
        int i = 0;
        while (i < 4 && p->box_lo[i] == p->box_hi[i]) i++; 
        bool contiguous = true;
        if (i < 4) {
            for (int j = i + 1; j < 4; j++)
                if (p->box_lo[j] != 0 || p->box_hi[j] != 255) contiguous = false;
        }
        if (contiguous) {
            p->kind = PB_HOST_V4_RANGE;
            p->lo4 = p->hi4 = 0;
            for (int j = 0; j < 4; j++) {
                p->lo4 = (p->lo4 << 8) | p->box_lo[j];
                p->hi4 = (p->hi4 << 8) | p->box_hi[j];
            }
        } else {
            p->kind = PB_HOST_V4_BOX;
        }
    }
    return true;
bad4:
    set_err(err, errlen, "invalid IPv4 address, range or pattern '%s'", tok);
    return false;
}

static bool parse_port_token(const char *tok, struct pb_port_range *r, char *err, size_t errlen)
{
    unsigned a, b;
    const char *dash = strchr(tok, '-');
    if (dash) {
        if (!parse_uint(tok, (size_t)(dash - tok), 65535, &a) || !parse_uint(dash + 1, strlen(dash + 1), 65535, &b) || a > b || a == 0) {
            set_err(err, errlen, "invalid port range '%s'", tok);
            return false;
        }
    } else {
        if (!parse_uint(tok, strlen(tok), 65535, &a) || a == 0) {
            set_err(err, errlen, "invalid port '%s' (1-65535)", tok);
            return false;
        }
        b = a;
    }
    r->lo = (uint16_t)a; r->hi = (uint16_t)b;
    return true;
}

void pb_rule_free(struct pb_rule *r)
{
    free(r->procs); free(r->hosts); free(r->ports); free(r->domains);
    r->procs = NULL; r->hosts = NULL; r->ports = NULL; r->domains = NULL;
    r->nprocs = r->nhosts = r->nports = r->ndomains = 0;
}

static bool is_any(const char *s)
{
    while (isspace((unsigned char)*s)) s++;
    if (!*s) return true;
    return s[0] == '*' && (s[1] == 0 || isspace((unsigned char)s[1]));
}

bool pb_rule_parse(struct pb_rule *out, const char *process, const char *hosts, const char *ports, char *err, size_t errlen)
{
    memset(out, 0, sizeof *out);
    if (!process) process = "";
    if (!hosts) hosts = "";
    if (!ports) ports = "";
    if (strlen(process) >= sizeof out->process_src || strlen(ports) >= sizeof out->ports_src) {
        set_err(err, errlen, "pattern too long (max 511 characters)");
        return false;
    }
    if (strlen(hosts) >= sizeof out->hosts_src) {
        set_err(err, errlen, "host list too long (max %d characters)", PB_HOSTS_MAX - 1);
        return false;
    }
    snprintf(out->process_src, sizeof out->process_src, "%s", process);
    snprintf(out->hosts_src, sizeof out->hosts_src, "%s", hosts);
    snprintf(out->ports_src, sizeof out->ports_src, "%s", ports);

    char (*tok)[256] = malloc(sizeof(char[256]) * PB_MAX_HOST_PATTERNS);   // sized for the longest list (hosts)
    if (!tok) { set_err(err, errlen, "out of memory"); return false; }

    if (is_any(process)) out->any_proc = true;
    else {
        int n = split_list(process, tok, PB_MAX_PATTERNS);
        if (n < 0) { set_err(err, errlen, "too many process patterns (max %d)", PB_MAX_PATTERNS); goto fail; }
        out->procs = malloc(sizeof(char[256]) * (size_t)(n ? n : 1));
        if (!out->procs) goto oom;
        for (int i = 0; i < n; i++) {
            if (!strcmp(tok[i], "*")) { out->any_proc = true; continue; }
            memcpy(out->procs[out->nprocs++], tok[i], 256);
        }
        if (out->any_proc) { free(out->procs); out->procs = NULL; out->nprocs = 0; }
    }

    if (is_any(hosts)) out->any_host = true;
    else {
        int n = split_list(hosts, tok, PB_MAX_HOST_PATTERNS);
        if (n < 0) { set_err(err, errlen, "too many host patterns (max %d)", PB_MAX_HOST_PATTERNS); goto fail; }
        out->hosts = calloc((size_t)(n ? n : 1), sizeof *out->hosts);
        out->domains = malloc(sizeof(char[256]) * (size_t)(n ? n : 1));
        if (!out->hosts || !out->domains) goto oom;
        for (int i = 0; i < n; i++) {
            if (!strcmp(tok[i], "*")) { out->any_host = true; break; }
            if (looks_like_domain(tok[i]) && !strchr(tok[i], ':')) {
                if (!parse_domain_token(tok[i], out->domains[out->ndomains], err, errlen)) goto fail;
                out->ndomains++;
                continue;
            }
            if (!parse_host_token(tok[i], &out->hosts[out->nhosts], err, errlen)) goto fail;
            out->nhosts++;
        }
        if (out->any_host) { free(out->hosts); free(out->domains); out->hosts = NULL; out->domains = NULL; out->nhosts = out->ndomains = 0; }
    }

    if (is_any(ports)) out->any_port = true;
    else {
        int n = split_list(ports, tok, PB_MAX_PATTERNS);
        if (n < 0) { set_err(err, errlen, "too many port patterns (max %d)", PB_MAX_PATTERNS); goto fail; }
        out->ports = calloc((size_t)(n ? n : 1), sizeof *out->ports);
        if (!out->ports) goto oom;
        for (int i = 0; i < n; i++) {
            if (!strcmp(tok[i], "*")) { out->any_port = true; break; }
            if (!parse_port_token(tok[i], &out->ports[out->nports], err, errlen)) goto fail;
            out->nports++;
        }
        if (out->any_port) { free(out->ports); out->ports = NULL; out->nports = 0; }
    }
    free(tok);
    return true;
oom:
    set_err(err, errlen, "out of memory");
fail:
    free(tok);
    pb_rule_free(out);
    return false;
}

bool pb_rule_match_process(const struct pb_rule *r, const char *exe_path)
{
    if (r->any_proc) return true;
    if (!exe_path || !*exe_path) return false;
    const char *base = strrchr(exe_path, '/');
    base = base ? base + 1 : exe_path;
    for (int i = 0; i < r->nprocs; i++)
        if (pb_glob_match(r->procs[i], base) || pb_glob_match(r->procs[i], exe_path)) return true;
    return false;
}

bool pb_rule_match_proto(const struct pb_rule *r, int ipproto)
{
    switch (r->protocol) {
    case RULE_PROTOCOL_TCP: return ipproto == IPPROTO_TCP;
    case RULE_PROTOCOL_UDP: return ipproto == IPPROTO_UDP;
    default: return true;
    }
}

bool pb_rule_has_domains(const struct pb_rule *r) { return r->ndomains > 0; }

bool pb_rule_match_dest(const struct pb_rule *r, int family, const uint8_t addr16[16], uint16_t port,
                        const char *const *names, int nnames)
{
    if (!r->any_port) {
        bool ok = false;
        for (int i = 0; i < r->nports && !ok; i++) ok = port >= r->ports[i].lo && port <= r->ports[i].hi;
        if (!ok) return false;
    }
    if (r->any_host) return true;
    for (int i = 0; i < r->nhosts; i++) {
        const struct pb_host_pat *h = &r->hosts[i];
        if (family == AF_INET) {
            uint32_t a = ((uint32_t)addr16[12] << 24) | ((uint32_t)addr16[13] << 16) | ((uint32_t)addr16[14] << 8) | addr16[15];
            if (h->kind == PB_HOST_V4_RANGE && a >= h->lo4 && a <= h->hi4) return true;
            if (h->kind == PB_HOST_V4_BOX) {
                bool ok = true;
                for (int j = 0; j < 4 && ok; j++) {
                    uint8_t o = addr16[12 + j];
                    ok = o >= h->box_lo[j] && o <= h->box_hi[j];
                }
                if (ok) return true;
            }
        } else if (h->kind == PB_HOST_V6_RANGE) {
            if (memcmp(addr16, h->lo6, 16) >= 0 && memcmp(addr16, h->hi6, 16) <= 0) return true;
        }
    }
    for (int d = 0; d < r->ndomains; d++)
        for (int k = 0; k < nnames; k++)
            if (pb_domain_match(r->domains[d], names[k])) return true;
    return false;
}

bool pb_implicit_direct(int family, const uint8_t a[16], uint16_t port, int ipproto, bool dns_via_proxy)
{
    if (family == AF_INET) {
        if (a[12] == 127) return true;                                  // loopback
        if (a[12] >= 224) return true;                                  // multicast + reserved + broadcast
        if (a[12] == 0) return true;                                    // 0.0.0.0/8
    } else {
        static const uint8_t lo[16] = { [15] = 1 };
        if (!memcmp(a, lo, 16)) return true;                            // ::1
        if (a[0] == 0xff) return true;                                  // multicast
        if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return true;         // link-local (needs scope id anyway)
    }
    if (ipproto == IPPROTO_UDP && (port == 67 || port == 68)) return true;   // DHCP
    if (port == 53 && !dns_via_proxy) return true;
    return false;
}

int pb_rules_eval(const struct pb_rule *rules, size_t n, const char *exe_path, int family, const uint8_t addr16[16],
                  uint16_t port, int ipproto, const char *const *names, int nnames)
{
    for (size_t i = 0; i < n; i++) {
        const struct pb_rule *r = &rules[i];
        if (!r->enabled) continue;
        if (!pb_rule_match_proto(r, ipproto)) continue;
        if (!pb_rule_match_process(r, exe_path)) continue;
        if (!pb_rule_match_dest(r, family, addr16, port, names, nnames)) continue;
        return (int)i;
    }
    return -1;
}
