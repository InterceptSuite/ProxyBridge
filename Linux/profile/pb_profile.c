#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "pb_profile.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

// ---- minimal JSON reader: bounded depth and node count, everything copied out of the input ----

enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };
#define MAX_DEPTH 12
#define MAX_NODES 200000

struct jv {
    int t;
    bool b;
    double n;
    char *s;
    struct jv *kid;
    char **key;
    size_t nk, cap;
};

struct jp {
    const char *p, *end;
    unsigned nodes;
    char *err;
    size_t errlen;
};

static void jfree(struct jv *v)
{
    free(v->s);
    for (size_t i = 0; i < v->nk; i++) {
        jfree(&v->kid[i]);
        if (v->key) free(v->key[i]);
    }
    free(v->kid);
    free(v->key);
    memset(v, 0, sizeof *v);
}

static int jfail(struct jp *j, const char *fmt, ...)
{
    if (j->err && j->errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(j->err, j->errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

static void skip_ws(struct jp *j)
{
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) j->p++;
}

static int hex4(const char *p)
{
    int v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return -1;
    }
    return v;
}

static char *put_utf8(char *o, unsigned cp)
{
    if (cp < 0x80) *o++ = (char)cp;
    else if (cp < 0x800) { *o++ = (char)(0xC0 | cp >> 6); *o++ = (char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { *o++ = (char)(0xE0 | cp >> 12); *o++ = (char)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (char)(0x80 | (cp & 0x3F)); }
    else { *o++ = (char)(0xF0 | cp >> 18); *o++ = (char)(0x80 | ((cp >> 12) & 0x3F)); *o++ = (char)(0x80 | ((cp >> 6) & 0x3F)); *o++ = (char)(0x80 | (cp & 0x3F)); }
    return o;
}

// j->p is on the opening quote. The decoded text is never longer than the raw text.
static int parse_string(struct jp *j, char **out)
{
    const char *q = j->p + 1, *s = q;
    while (q < j->end && *q != '"') q += (*q == '\\' && q + 1 < j->end) ? 2 : 1;
    if (q >= j->end) return jfail(j, "unterminated string");
    char *buf = malloc((size_t)(q - s) + 1), *o = buf;
    if (!buf) return jfail(j, "out of memory");
    for (const char *r = s; r < q; r++) {
        if ((unsigned char)*r < 0x20 || *r == 0x7F) { free(buf); return jfail(j, "control character in string"); }
        if (*r != '\\') { *o++ = *r; continue; }
        r++;
        switch (*r) {
            case 'n': case 't': case 'r': case 'b': case 'f':
                free(buf); return jfail(j, "control character in string");      // no field of a profile may hold one
            case '"': case '\\': case '/': *o++ = *r; break;
            case 'u': {
                int cp = (q - r >= 5) ? hex4(r + 1) : -1;
                if (cp < 0) { free(buf); return jfail(j, "bad \\u escape"); }
                r += 4;
                if (cp >= 0xD800 && cp < 0xDC00) {
                    int lo = (q - r >= 7 && r[1] == '\\' && r[2] == 'u') ? hex4(r + 3) : -1;
                    if (lo < 0xDC00 || lo > 0xDFFF) { free(buf); return jfail(j, "bad surrogate pair"); }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    r += 6;
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) { free(buf); return jfail(j, "bad surrogate pair"); }
                if (cp < 0x20 || cp == 0x7F) { free(buf); return jfail(j, "control character in string"); }
                o = put_utf8(o, (unsigned)cp);
                break;
            }
            default: free(buf); return jfail(j, "bad escape \\%c", *r);
        }
    }
    *o = 0;
    j->p = q + 1;
    *out = buf;
    return 0;
}

static int jadd(struct jv *c, char *key, struct jv *child)
{
    if (c->nk == c->cap) {
        size_t n = c->cap ? c->cap * 2 : 8;
        struct jv *k = realloc(c->kid, n * sizeof *k);
        if (!k) return -1;
        c->kid = k;
        char **ks = realloc(c->key, n * sizeof *ks);
        if (!ks) return -1;
        c->key = ks;
        c->cap = n;
    }
    c->kid[c->nk] = *child;
    c->key[c->nk] = key;
    c->nk++;
    return 0;
}

static int parse_value(struct jp *j, struct jv *v, int depth);

static int parse_container(struct jp *j, struct jv *v, int depth, bool obj)
{
    char close = obj ? '}' : ']';
    v->t = obj ? J_OBJ : J_ARR;
    j->p++;
    skip_ws(j);
    if (j->p < j->end && *j->p == close) { j->p++; return 0; }
    for (;;) {
        char *key = NULL;
        skip_ws(j);
        if (obj) {
            if (j->p >= j->end || *j->p != '"') return jfail(j, "expected a key");
            if (parse_string(j, &key) < 0) return -1;
            skip_ws(j);
            if (j->p >= j->end || *j->p != ':') { free(key); return jfail(j, "expected ':'"); }
            for (size_t i = 0; i < v->nk; i++)
                if (!strcasecmp(v->key[i], key)) { free(key); return jfail(j, "duplicate key"); }  // other readers take the last one
            j->p++;
        }
        struct jv child = {0};
        if (parse_value(j, &child, depth + 1) < 0 || jadd(v, key, &child) < 0) {
            jfree(&child);
            free(key);
            return j->err && j->err[0] ? -1 : jfail(j, "out of memory");
        }
        skip_ws(j);
        if (j->p < j->end && *j->p == ',') { j->p++; continue; }
        if (j->p < j->end && *j->p == close) { j->p++; return 0; }
        return jfail(j, "expected ',' or '%c'", close);
    }
}

static int parse_value(struct jp *j, struct jv *v, int depth)
{
    if (depth > MAX_DEPTH) return jfail(j, "nested too deeply");
    if (++j->nodes > MAX_NODES) return jfail(j, "too many values");
    skip_ws(j);
    if (j->p >= j->end) return jfail(j, "unexpected end of file");
    char c = *j->p;
    if (c == '{' || c == '[') return parse_container(j, v, depth, c == '{');
    if (c == '"') { v->t = J_STR; return parse_string(j, &v->s); }
    size_t left = (size_t)(j->end - j->p);
    if (left >= 4 && !strncmp(j->p, "true", 4)) { v->t = J_BOOL; v->b = true; j->p += 4; return 0; }
    if (left >= 5 && !strncmp(j->p, "false", 5)) { v->t = J_BOOL; j->p += 5; return 0; }
    if (left >= 4 && !strncmp(j->p, "null", 4)) { v->t = J_NULL; j->p += 4; return 0; }
    if (c == '-' || (c >= '0' && c <= '9')) {
        bool neg = c == '-';
        double n = 0;
        j->p += neg;
        if (j->p >= j->end || *j->p < '0' || *j->p > '9') return jfail(j, "bad number");
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9') n = n * 10 + (*j->p++ - '0');
        if (j->p < j->end && (*j->p == '.' || *j->p == 'e' || *j->p == 'E'))
            return jfail(j, "numbers must be whole");                        // 1080e1 or 8.9 would be read differently elsewhere
        v->t = J_NUM;
        v->n = neg ? -n : n;
        return 0;
    }
    return jfail(j, "unexpected character '%c'", c);
}

static const struct jv *jget(const struct jv *o, const char *key)
{
    if (o->t != J_OBJ) return NULL;
    for (size_t i = 0; i < o->nk; i++)
        if (!strcasecmp(o->key[i], key)) return &o->kid[i];
    return NULL;
}

// Text of a string value, or of a whole number (older files store ports and ids either way).
static char *jtext(const struct jv *o, const char *key)
{
    const struct jv *v = jget(o, key);
    if (!v) return NULL;
    if (v->t == J_STR) return strdup(v->s);
    if (v->t == J_NUM && v->n >= 0 && v->n < 4294967296.0) {
        char b[24];
        snprintf(b, sizeof b, "%.0f", v->n);
        return strdup(b);
    }
    return NULL;
}

static bool jbool(const struct jv *o, const char *key, bool def)
{
    const struct jv *v = jget(o, key);
    if (!v) return def;
    if (v->t == J_BOOL) return v->b;
    if (v->t == J_STR) return !strcasecmp(v->s, "true") ? true : !strcasecmp(v->s, "false") ? false : def;
    return def;
}

static long jnum(const struct jv *o, const char *key, long def)
{
    const struct jv *v = jget(o, key);
    if (!v) return def;
    if (v->t == J_NUM) return (v->n >= 0 && v->n < 4294967296.0) ? (long)v->n : -1;
    if (v->t == J_STR) {
        const char *s = v->s;
        long n = 0;
        if (!*s) return def;
        for (; *s; s++) {
            if (*s < '0' || *s > '9' || n > 99999999) return -1;
            n = n * 10 + (*s - '0');
        }
        return n;
    }
    return -1;
}

// ---- host list helpers ----

static bool is_sep(char c) { return c == ';' || c == ','; }

// Anything made only of digits and the IP pattern characters is an address pattern; IPv6 has a ':'.
static bool token_is_domain(const char *t, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (t[i] == ':') return false;
    for (size_t i = 0; i < n; i++)
        if (!((t[i] >= '0' && t[i] <= '9') || t[i] == '.' || t[i] == '*' || t[i] == '-' || t[i] == '/' || t[i] == '?')) return true;
    return false;
}

static void append_token(char **dst, size_t *len, const char *t, size_t n)
{
    char *b = realloc(*dst, *len + n + 2);
    if (!b) return;
    if (*len) b[(*len)++] = ';';
    memcpy(b + *len, t, n);
    *len += n;
    b[*len] = 0;
    *dst = b;
}

void pbp_split_hosts(const char *hosts, char **ips, char **domains)
{
    char *a = NULL, *d = NULL;
    size_t la = 0, ld = 0;
    for (const char *p = hosts ? hosts : ""; *p;) {
        while (*p && (is_sep(*p) || *p == ' ' || *p == '\t')) p++;
        const char *s = p;
        while (*p && !is_sep(*p)) p++;
        const char *e = p;
        while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
        if (e == s) continue;
        if (token_is_domain(s, (size_t)(e - s))) append_token(&d, &ld, s, (size_t)(e - s));
        else append_token(&a, &la, s, (size_t)(e - s));
    }
    *ips = a ? a : strdup("");
    *domains = d ? d : strdup("");
}

char *pbp_merge_hosts(const char *ips, const char *domains)
{
    char *a = NULL, *d = NULL;
    size_t la = 0, ld = 0;
    // normalise both lists to ';' separated, trimmed tokens
    for (int pass = 0; pass < 2; pass++) {
        for (const char *p = pass ? (domains ? domains : "") : (ips ? ips : ""); *p;) {
            while (*p && (is_sep(*p) || *p == ' ' || *p == '\t')) p++;
            const char *s = p;
            while (*p && !is_sep(*p)) p++;
            const char *e = p;
            while (e > s && (e[-1] == ' ' || e[-1] == '\t')) e--;
            if (e > s) append_token(pass ? &d : &a, pass ? &ld : &la, s, (size_t)(e - s));
        }
    }
    bool any = !a || !strcmp(a, "*");
    char *out;
    if (!d) out = strdup(any ? "*" : a);
    else if (any) out = strdup(d);
    else if (asprintf(&out, "%s;%s", a, d) < 0) out = NULL;
    free(a);
    free(d);
    return out;
}

// ---- profile <-> JSON ----

void pbp_free(struct pbp_profile *p)
{
    if (!p) return;
    for (size_t i = 0; i < p->nproxies; i++) {
        free(p->proxies[i].name); free(p->proxies[i].host); free(p->proxies[i].user); free(p->proxies[i].pass);
    }
    for (size_t i = 0; i < p->nrules; i++) {
        free(p->rules[i].name); free(p->rules[i].process); free(p->rules[i].hosts); free(p->rules[i].ports);
    }
    for (size_t i = 0; i < p->nfilters; i++) {
        free(p->filters[i].process); free(p->filters[i].ip); free(p->filters[i].port);
        free(p->filters[i].protocol); free(p->filters[i].action);
    }
    free(p->filters);
    free(p->proxies);
    free(p->rules);
    free(p->name);
    memset(p, 0, sizeof *p);
}

struct pbp_proxy *pbp_find_proxy(const struct pbp_profile *p, uint32_t id)
{
    for (size_t i = 0; i < p->nproxies; i++)
        if (p->proxies[i].id == id) return &p->proxies[i];
    return NULL;
}

static char *dup_or(char *s, const char *def)
{
    if (s && *s) return s;
    free(s);
    return strdup(def);
}

// Only the proxies before the one being read count: it is already included in nproxies.
static bool name_taken(const struct pbp_profile *p, const char *name)
{
    for (size_t i = 0; i + 1 < p->nproxies; i++)
        if (!strcmp(p->proxies[i].name, name)) return true;
    return false;
}

static int read_proxy(struct pbp_profile *p, const struct jv *o, size_t idx, char *err, size_t errlen)
{
    struct pbp_proxy *x = &p->proxies[p->nproxies];
    memset(x, 0, sizeof *x);
    p->nproxies++;           // counted first so pbp_free releases a half-built entry

    char *type = jtext(o, "Type");
    long port = jnum(o, "Port", 0);
    x->host = jtext(o, "Host");
    if (!x->host || !*x->host || port < 1 || port > 65535) {
        free(type);
        snprintf(err, errlen, "ProxyConfigs[%zu]: needs a Host and a Port between 1 and 65535", idx);
        return -1;
    }
    x->port = (uint16_t)port;
    if (type && (!strcasecmp(type, "socks5") || !strcasecmp(type, "socks"))) x->type = 1;
    else if (type && (!strcasecmp(type, "http") || !strcasecmp(type, "https"))) x->type = 0;
    else {
        snprintf(err, errlen, "ProxyConfigs[%zu]: unknown Type '%s' (use SOCKS5 or HTTP)", idx, type ? type : "");
        free(type);
        return -1;
    }
    free(type);

    long id = jnum(o, "Id", 0);
    uint32_t want = id > 0 ? (uint32_t)id : 0;
    if (id > 0x7FFFFFFF) {
        snprintf(err, errlen, "ProxyConfigs[%zu]: Id out of range", idx);
        return -1;
    }
    uint32_t max = 0;
    for (size_t i = 0; i + 1 < p->nproxies; i++) {
        if (p->proxies[i].id > max) max = p->proxies[i].id;
        if (p->proxies[i].id == want) want = 0;
    }
    x->id = want ? want : max + 1;

    x->name = jtext(o, "Name");
    if (!x->name || !*x->name || name_taken(p, x->name)) {
        char fallback[48];
        snprintf(fallback, sizeof fallback, "proxy%u", x->id);
        free(x->name);
        x->name = strdup(fallback);
    }
    x->send_domain = jbool(o, "SendDomainToProxy", true);
    x->user = dup_or(jtext(o, "Username"), "");
    x->pass = dup_or(jtext(o, "Password"), "");
    if (!x->name || !x->user || !x->pass) { snprintf(err, errlen, "out of memory"); return -1; }
    return 0;
}

static int read_rule(struct pbp_profile *p, const struct jv *o, size_t idx, bool default_localhost, char *err, size_t errlen)
{
    struct pbp_rule *r = &p->rules[p->nrules];
    memset(r, 0, sizeof *r);
    p->nrules++;

    char *hosts = jtext(o, "TargetHosts"), *domains = jtext(o, "TargetDomains");
    r->hosts = pbp_merge_hosts(hosts, domains);
    free(hosts);
    free(domains);
    r->name = dup_or(jtext(o, "Name"), "");
    r->process = dup_or(jtext(o, "ProcessName"), "*");
    r->ports = dup_or(jtext(o, "TargetPorts"), "*");
    if (!r->name || !r->hosts || !r->process || !r->ports) { snprintf(err, errlen, "out of memory"); return -1; }

    char *proto = jtext(o, "Protocol"), *act = jtext(o, "Action");
    int rc = 0;
    if (!proto || !*proto || !strcasecmp(proto, "TCP")) r->protocol = 0;
    else if (!strcasecmp(proto, "UDP")) r->protocol = 1;
    else if (!strcasecmp(proto, "BOTH")) r->protocol = 2;
    else { snprintf(err, errlen, "ProxyRules[%zu]: unknown Protocol '%s'", idx, proto); rc = -1; }
    if (!rc) {
        if (!act || !*act || !strcasecmp(act, "PROXY")) r->action = 0;
        else if (!strcasecmp(act, "DIRECT")) r->action = 1;
        else if (!strcasecmp(act, "BLOCK")) r->action = 2;
        else { snprintf(err, errlen, "ProxyRules[%zu]: unknown Action '%s'", idx, act); rc = -1; }
    }
    free(proto);
    free(act);
    if (rc) return rc;

    r->enabled = jbool(o, "IsEnabled", true);
    r->localhost = r->action == 0 && jbool(o, "LocalhostViaProxy", default_localhost);
    long pid = jnum(o, "ProxyConfigId", 0);
    if (pid < 0 || (pid > 0 && !pbp_find_proxy(p, (uint32_t)pid))) {
        snprintf(err, errlen, "ProxyRules[%zu]: ProxyConfigId %ld does not match any proxy", idx, pid);
        return -1;
    }
    r->proxy_id = (uint32_t)pid;
    return 0;
}

int pbp_parse(const char *json, size_t len, struct pbp_profile *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof *out);
    if (len > PBP_MAX_FILE) { snprintf(err, errlen, "file is larger than %u MiB", PBP_MAX_FILE >> 20); return -1; }
    char *copy = malloc(len + 1);
    if (!copy) { snprintf(err, errlen, "out of memory"); return -1; }
    memcpy(copy, json, len);
    copy[len] = 0;

    err[0] = 0;
    struct jp j = { copy, copy + len, 0, err, errlen };
    struct jv root = {0};
    if (len >= 3 && !memcmp(copy, "\xEF\xBB\xBF", 3)) j.p += 3;      // editors on Windows add a BOM
    int rc = parse_value(&j, &root, 0);
    if (rc == 0) {
        skip_ws(&j);
        if (j.p != j.end) rc = jfail(&j, "unexpected data after the profile");
        else if (root.t != J_OBJ) rc = jfail(&j, "a profile is a JSON object");
    }
    if (rc < 0) {
        char tmp[200];
        snprintf(tmp, sizeof tmp, "not a valid profile: %s", err[0] ? err : "parse error");
        snprintf(err, errlen, "%s", tmp);
        jfree(&root);
        free(copy);
        return -1;
    }

    const struct jv *cfgs = jget(&root, "ProxyConfigs"), *rules = jget(&root, "ProxyRules");
    if ((cfgs && cfgs->t != J_ARR) || (rules && rules->t != J_ARR)) {
        snprintf(err, errlen, "ProxyConfigs and ProxyRules must be arrays");
        rc = -1;
    } else if ((cfgs && cfgs->nk > PBP_MAX_PROXIES) || (rules && rules->nk > PBP_MAX_RULES)) {
        snprintf(err, errlen, "too many proxies (max %d) or rules (max %d)", PBP_MAX_PROXIES, PBP_MAX_RULES);
        rc = -1;
    }
    if (rc == 0) {
        out->name = jtext(&root, "Name");
        out->logging = jbool(&root, "IsTrafficLoggingEnabled", true);
        out->dns_via_proxy = jbool(&root, "DnsViaProxy", true);
        out->log_every = jbool(&root, "LogEveryConnection", false);
        out->auto_clear = jbool(&root, "AutoClearConnectionLogs", true);
        long zoom = jnum(&root, "FontZoom", 100);
        out->font_zoom = (zoom >= PBP_ZOOM_MIN && zoom <= PBP_ZOOM_MAX) ? (int)zoom : 100;
        long dp = jnum(&root, "DefaultProxyId", 0);
        out->default_proxy_id = dp > 0 ? (uint32_t)dp : 0;
        if (cfgs && cfgs->nk) out->proxies = calloc(cfgs->nk, sizeof *out->proxies);
        if (rules && rules->nk) out->rules = calloc(rules->nk, sizeof *out->rules);
        if ((cfgs && cfgs->nk && !out->proxies) || (rules && rules->nk && !out->rules)) {
            snprintf(err, errlen, "out of memory");
            rc = -1;
        }
    }
    bool default_localhost = jbool(&root, "LocalhostViaProxy", false);     // profiles from before the setting became per rule
    for (size_t i = 0; rc == 0 && cfgs && i < cfgs->nk; i++)
        rc = cfgs->kid[i].t == J_OBJ ? read_proxy(out, &cfgs->kid[i], i, err, errlen)
                                     : (snprintf(err, errlen, "ProxyConfigs[%zu] is not an object", i), -1);
    for (size_t i = 0; rc == 0 && rules && i < rules->nk; i++)
        rc = rules->kid[i].t == J_OBJ ? read_rule(out, &rules->kid[i], i, default_localhost, err, errlen)
                                      : (snprintf(err, errlen, "ProxyRules[%zu] is not an object", i), -1);
    const struct jv *flts = jget(&root, "LogFilters");
    if (rc == 0 && flts && flts->t != J_ARR) { snprintf(err, errlen, "LogFilters must be an array"); rc = -1; }
    if (rc == 0 && flts && flts->nk > PBP_MAX_FILTERS) { snprintf(err, errlen, "too many log filters (max %d)", PBP_MAX_FILTERS); rc = -1; }
    if (rc == 0 && flts && flts->nk) {
        out->filters = calloc(flts->nk, sizeof *out->filters);
        if (!out->filters) { snprintf(err, errlen, "out of memory"); rc = -1; }
    }
    for (size_t i = 0; rc == 0 && flts && i < flts->nk; i++) {
        const struct jv *o = &flts->kid[i];
        if (o->t != J_OBJ) { snprintf(err, errlen, "LogFilters[%zu] is not an object", i); rc = -1; break; }
        struct pbp_filter *x = &out->filters[out->nfilters++];
        char *mode = jtext(o, "Mode"), *proto = jtext(o, "Protocol"), *act = jtext(o, "Action");
        x->exclude = mode && !strcasecmp(mode, "Exclude");
        x->process = dup_or(jtext(o, "ProcessName"), "");
        x->ip = dup_or(jtext(o, "Ip"), "");
        x->port = dup_or(jtext(o, "Port"), "");
        x->protocol = strdup(proto && !strcasecmp(proto, "TCP") ? "TCP" : proto && !strcasecmp(proto, "UDP") ? "UDP" : "All");
        x->action = strdup(act && !strcasecmp(act, "Direct") ? "Direct" : act && !strcasecmp(act, "Proxy") ? "Proxy" : act && !strcasecmp(act, "Blocked") ? "Blocked" : "All");
        free(mode); free(proto); free(act);
        if (!x->process || !x->ip || !x->port || !x->protocol || !x->action) { snprintf(err, errlen, "out of memory"); rc = -1; }
    }
    if (rc == 0 && out->default_proxy_id && !pbp_find_proxy(out, out->default_proxy_id)) {
        snprintf(err, errlen, "DefaultProxyId %u does not match any proxy", out->default_proxy_id);
        rc = -1;
    }
    jfree(&root);
    free(copy);
    if (rc) pbp_free(out);
    return rc;
}

// ---- serializer ----

struct sb { char *p; size_t len, cap; bool oom; };

static void sb_add(struct sb *b, const char *s, size_t n)
{
    if (b->oom) return;
    if (b->len + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 1024;
        while (c < b->len + n + 1) c *= 2;
        char *np = realloc(b->p, c);
        if (!np) { b->oom = true; return; }
        b->p = np;
        b->cap = c;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void sb_puts(struct sb *b, const char *s) { sb_add(b, s, strlen(s)); }

static void sb_fmt(struct sb *b, const char *fmt, ...)
{
    char t[64];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(t, sizeof t, fmt, ap);
    va_end(ap);
    if (n > 0 && (size_t)n < sizeof t) sb_add(b, t, (size_t)n);
}

static void sb_str(struct sb *b, const char *s)
{
    sb_add(b, "\"", 1);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"': sb_puts(b, "\\\""); break;
            case '\\': sb_puts(b, "\\\\"); break;
            case '\n': sb_puts(b, "\\n"); break;
            case '\r': sb_puts(b, "\\r"); break;
            case '\t': sb_puts(b, "\\t"); break;
            default:
                if (c < 0x20) { char u[8]; snprintf(u, sizeof u, "\\u%04x", c); sb_puts(b, u); }
                else sb_add(b, (const char *)&c, 1);
        }
    }
    sb_add(b, "\"", 1);
}

static void sb_kv(struct sb *b, const char *indent, const char *key, const char *val, const char *tail)
{
    sb_puts(b, indent);
    sb_str(b, key);
    sb_puts(b, ": ");
    sb_str(b, val);
    sb_puts(b, tail);
}

char *pbp_serialize(const struct pbp_profile *p)
{
    struct sb b = {0};
    sb_puts(&b, "{\n  \"Version\": \"1.0\",\n");
    sb_kv(&b, "  ", "Name", p->name ? p->name : "", ",\n");
    sb_puts(&b, p->logging ? "  \"IsTrafficLoggingEnabled\": true,\n" : "  \"IsTrafficLoggingEnabled\": false,\n");
    sb_puts(&b, p->dns_via_proxy ? "  \"DnsViaProxy\": true,\n" : "  \"DnsViaProxy\": false,\n");
    sb_puts(&b, p->log_every ? "  \"LogEveryConnection\": true,\n" : "  \"LogEveryConnection\": false,\n");
    sb_puts(&b, p->auto_clear ? "  \"AutoClearConnectionLogs\": true,\n" : "  \"AutoClearConnectionLogs\": false,\n");
    sb_fmt(&b, "  \"FontZoom\": %d,\n", p->font_zoom >= PBP_ZOOM_MIN && p->font_zoom <= PBP_ZOOM_MAX ? p->font_zoom : 100);
    sb_fmt(&b, "  \"DefaultProxyId\": %u,\n", p->default_proxy_id);

    sb_puts(&b, "  \"ProxyConfigs\": [");
    for (size_t i = 0; i < p->nproxies; i++) {
        const struct pbp_proxy *x = &p->proxies[i];
        char port[8];
        snprintf(port, sizeof port, "%u", x->port);
        sb_puts(&b, i ? ",\n    {\n" : "\n    {\n");
        sb_fmt(&b, "      \"Id\": %u,\n", x->id);
        sb_kv(&b, "      ", "Name", x->name, ",\n");
        sb_kv(&b, "      ", "Type", x->type ? "SOCKS5" : "HTTP", ",\n");
        sb_kv(&b, "      ", "Host", x->host, ",\n");
        sb_kv(&b, "      ", "Port", port, ",\n");
        sb_kv(&b, "      ", "Username", x->user, ",\n");
        sb_kv(&b, "      ", "Password", x->pass, ",\n");
        sb_puts(&b, x->send_domain ? "      \"SendDomainToProxy\": true\n    }" : "      \"SendDomainToProxy\": false\n    }");
    }
    sb_puts(&b, p->nproxies ? "\n  ],\n" : "],\n");

    sb_puts(&b, "  \"ProxyRules\": [");
    for (size_t i = 0; i < p->nrules; i++) {
        const struct pbp_rule *r = &p->rules[i];
        char *ips, *doms;
        pbp_split_hosts(r->hosts, &ips, &doms);
        sb_puts(&b, i ? ",\n    {\n" : "\n    {\n");
        sb_kv(&b, "      ", "Name", r->name ? r->name : "", ",\n");
        sb_kv(&b, "      ", "ProcessName", r->process, ",\n");
        sb_kv(&b, "      ", "TargetHosts", ips && *ips ? ips : "*", ",\n");
        sb_kv(&b, "      ", "TargetPorts", r->ports, ",\n");
        sb_kv(&b, "      ", "TargetDomains", doms ? doms : "", ",\n");
        sb_kv(&b, "      ", "Protocol", r->protocol == 1 ? "UDP" : r->protocol == 2 ? "BOTH" : "TCP", ",\n");
        sb_kv(&b, "      ", "Action", r->action == 1 ? "DIRECT" : r->action == 2 ? "BLOCK" : "PROXY", ",\n");
        sb_puts(&b, r->enabled ? "      \"IsEnabled\": true,\n" : "      \"IsEnabled\": false,\n");
        sb_fmt(&b, "      \"ProxyConfigId\": %u,\n", r->proxy_id);
        sb_puts(&b, r->localhost ? "      \"LocalhostViaProxy\": true\n    }" : "      \"LocalhostViaProxy\": false\n    }");
        free(ips);
        free(doms);
    }
    sb_puts(&b, p->nrules ? "\n  ],\n" : "],\n");

    sb_puts(&b, "  \"LogFilters\": [");
    for (size_t i = 0; i < p->nfilters; i++) {
        const struct pbp_filter *x = &p->filters[i];
        sb_puts(&b, i ? ",\n    {\n" : "\n    {\n");
        sb_kv(&b, "      ", "Mode", x->exclude ? "Exclude" : "Include", ",\n");
        sb_kv(&b, "      ", "ProcessName", x->process ? x->process : "", ",\n");
        sb_kv(&b, "      ", "Ip", x->ip ? x->ip : "", ",\n");
        sb_kv(&b, "      ", "Port", x->port ? x->port : "", ",\n");
        sb_kv(&b, "      ", "Protocol", x->protocol ? x->protocol : "All", ",\n");
        sb_kv(&b, "      ", "Action", x->action ? x->action : "All", "\n    }");
    }
    sb_puts(&b, p->nfilters ? "\n  ]\n}\n" : "]\n}\n");
    if (b.oom) { free(b.p); return NULL; }
    return b.p;
}

// ---- files ----

int pbp_load_file(const char *path, struct pbp_profile *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof *out);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { snprintf(err, errlen, "cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        snprintf(err, errlen, "%s is not a regular file", path);
        return -1;
    }
    if (st.st_size <= 0 || (unsigned long)st.st_size > PBP_MAX_FILE) {
        close(fd);
        snprintf(err, errlen, st.st_size <= 0 ? "%s is empty" : "%s is too large", path);
        return -1;
    }
    size_t n = (size_t)st.st_size, got = 0;
    char *buf = malloc(n);
    while (buf && got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (!buf || got != n) {
        free(buf);
        snprintf(err, errlen, "cannot read %s", path);
        return -1;
    }
    int rc = pbp_parse(buf, n, out, err, errlen);
    free(buf);
    return rc;
}

int pbp_write_file(const char *path, const char *data, char *err, size_t errlen)
{
    char *tmp = NULL;
    if (asprintf(&tmp, "%s.tmp.XXXXXX", path) < 0) { snprintf(err, errlen, "out of memory"); return -1; }
    int fd = mkstemp(tmp);                                        // created 0600
    int rc = -1;
    if (fd < 0) {
        snprintf(err, errlen, "cannot write %s: %s", path, strerror(errno));
    } else {
        size_t n = strlen(data), off = 0;
        while (off < n) {
            ssize_t w = write(fd, data + off, n - off);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) break;
            off += (size_t)w;
        }
        bool written = off == n && fsync(fd) == 0;
        int closed = close(fd);
        if (written && closed == 0 && rename(tmp, path) == 0) rc = 0;
        else {
            snprintf(err, errlen, "cannot write %s: %s", path, strerror(errno));
            unlink(tmp);
        }
    }
    free(tmp);
    return rc;
}

int pbp_save_file(const char *path, const struct pbp_profile *p, char *err, size_t errlen)
{
    char *json = pbp_serialize(p);
    if (!json) { snprintf(err, errlen, "out of memory"); return -1; }
    int rc = pbp_write_file(path, json, err, errlen);
    free(json);
    return rc;
}

int pbp_settings_load(const char *path, char **active, bool *check_updates, bool *start_at_boot)
{
    char err[200];
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *buf = malloc(65537);
    size_t n = buf ? fread(buf, 1, 65536, f) : 0;
    fclose(f);
    if (!buf) return -1;
    buf[n] = 0;
    struct jp j = { buf, buf + n, 0, err, sizeof err };
    struct jv root = {0};
    int rc = parse_value(&j, &root, 0);
    if (rc == 0 && root.t == J_OBJ) {
        char *a = jtext(&root, "ActiveProfileName");
        if (a && *a) { free(*active); *active = a; } else free(a);
        if (check_updates) *check_updates = jbool(&root, "CheckForUpdatesOnStartup", true);
        if (start_at_boot) *start_at_boot = jbool(&root, "StartAtBoot", false);
    } else rc = -1;
    jfree(&root);
    free(buf);
    return rc;
}

int pbp_settings_save(const char *path, const char *active, bool check_updates, bool start_at_boot, char *err, size_t errlen)
{
    struct sb b = {0};
    sb_puts(&b, "{\n");
    sb_kv(&b, "  ", "ActiveProfileName", active ? active : "", ",\n");
    sb_puts(&b, check_updates ? "  \"CheckForUpdatesOnStartup\": true,\n" : "  \"CheckForUpdatesOnStartup\": false,\n");
    sb_puts(&b, start_at_boot ? "  \"StartAtBoot\": true\n}\n" : "  \"StartAtBoot\": false\n}\n");
    if (b.oom) { free(b.p); snprintf(err, errlen, "out of memory"); return -1; }
    int rc = pbp_write_file(path, b.p, err, errlen);
    free(b.p);
    return rc;
}

// ---- update feed ----

int pbp_update_parse(const char *json, size_t len, char **version, char **download, char **notes)
{
    char err[100];
    char *copy = malloc(len + 1);
    if (!copy) return -1;
    memcpy(copy, json, len);
    copy[len] = 0;
    struct jp j = { copy, copy + len, 0, err, sizeof err };
    struct jv root = {0};
    int rc = parse_value(&j, &root, 0) == 0 && root.t == J_OBJ ? 0 : -1;
    const struct jv *lin = rc == 0 ? jget(&root, "linux") : NULL;
    *version = *download = *notes = NULL;
    if (lin && lin->t == J_OBJ) {
        *version = jtext(lin, "version");
        *download = jtext(lin, "download");
        *notes = jtext(lin, "release_notes");
    }
    if (*version && (strlen(*version) > 32 || strspn(*version, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.+-") != strlen(*version)))
        **version = 0;                                              // the feed is remote input: only a plain version string is shown
    if (!*version || !**version) {
        free(*version); free(*download); free(*notes);
        *version = *download = *notes = NULL;
        rc = -1;
    }
    jfree(&root);
    free(copy);
    return rc;
}

static void version_parts(const char *s, long out[3])
{
    out[0] = out[1] = out[2] = 0;
    while (*s && (*s < '0' || *s > '9')) s++;
    for (int i = 0; i < 3 && *s; i++) {
        long n = 0;
        while (*s >= '0' && *s <= '9') { n = n * 10 + (*s - '0'); if (n > 1000000) n = 1000000; s++; }
        out[i] = n;
        if (*s == '.') s++; else break;
    }
}

bool pbp_version_newer(const char *candidate, const char *current)
{
    long a[3], b[3];
    version_parts(candidate ? candidate : "", a);
    version_parts(current ? current : "", b);
    for (int i = 0; i < 3; i++)
        if (a[i] != b[i]) return a[i] > b[i];
    return false;
}

// ---- log filters ----

// Case-insensitive glob with a single backtrack point (linear time): a pattern from an imported profile must not be able
// to stall the connection callback, which runs this for every event.
static bool ci_glob(const char *p, const char *s)
{
    const char *star = NULL, *mark = NULL;
    while (*s) {
        if (*p == '*') { star = ++p; mark = s; continue; }
        if (*p == '?' || tolower((unsigned char)*p) == tolower((unsigned char)*s)) { p++; s++; continue; }
        if (!star) return false;
        p = star; s = ++mark;
    }
    while (*p == '*') p++;
    return !*p;
}

static bool pat_ok(const char *pat, const char *actual)
{
    if (!pat || !*pat || !strcasecmp(pat, "All")) return true;
    return ci_glob(pat, actual ? actual : "");
}

static bool filter_hits(const struct pbp_filter *f, const char *proc, const char *ip, const char *port, const char *proto, const char *action)
{
    return pat_ok(f->process, proc) && pat_ok(f->ip, ip) && pat_ok(f->port, port) &&
           (!f->protocol[0] || !strcasecmp(f->protocol, "All") || !strcasecmp(f->protocol, proto ? proto : "")) &&
           (!f->action[0] || !strcasecmp(f->action, "All") || !strcasecmp(f->action, action ? action : ""));
}

bool pbp_filters_pass(const struct pbp_filter *f, size_t n, const char *proc, const char *ip, const char *port, const char *proto, const char *action)
{
    if (!n) return true;
    for (size_t i = 0; i < n; i++)
        if (f[i].exclude && filter_hits(&f[i], proc, ip, port, proto, action)) return false;
    bool has_include = false;
    for (size_t i = 0; i < n; i++)
        if (!f[i].exclude) {
            has_include = true;
            if (filter_hits(&f[i], proc, ip, port, proto, action)) return true;
        }
    return !has_include;
}

// ---- profile names and files ----

#define MAX_FILENAME 240

char *pbp_filename_for(const char *name)
{
    if (!name || !*name) return NULL;
    size_t n = strlen(name);
    char *out = malloc(n * 3 + sizeof PBP_EXT), *o = out;
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ||
                     c == ' ' || c >= 0x80 || (c == '.' && i > 0);
        if (plain) *o++ = (char)c;
        else o += sprintf(o, "%%%02X", c);
    }
    strcpy(o, PBP_EXT);
    if (strlen(out) > MAX_FILENAME) { free(out); return NULL; }
    return out;
}

char *pbp_name_from_filename(const char *filename)
{
    size_t n = strlen(filename), e = sizeof PBP_EXT - 1;
    if (n <= e || strcmp(filename + n - e, PBP_EXT) != 0) return NULL;
    char *out = malloc(n), *o = out;
    if (!out) return NULL;
    size_t m = n - e;
    for (size_t i = 0; i < m; i++) {
        if (filename[i] != '%') { *o++ = filename[i]; continue; }
        char t[4] = { '0', '0', i + 2 < m ? filename[i + 1] : 'x', i + 2 < m ? filename[i + 2] : 'x' };
        int v = hex4(t);
        if (v <= 0) { free(out); return NULL; }
        *o++ = (char)v;
        i += 2;
    }
    *o = 0;
    if (!*out) { free(out); return NULL; }
    return out;
}

const char *pbp_config_dir(void)
{
    const char *env = secure_getenv("PROXYBRIDGE_CONFIG_DIR");
    return (env && *env) ? env : "/etc/proxybridge";
}

char *pbp_resolve(const char *dir, const char *s)
{
    if (!s || !*s) return NULL;
    size_t n = strlen(s), e = sizeof PBP_EXT - 1;
    bool has_ext = n > e && !strcmp(s + n - e, PBP_EXT);
    if (strchr(s, '/')) return strdup(s);                      // a path; a file in the current directory needs "./"
    char *name = strndup(s, has_ext ? n - e : n);
    char *file = name ? pbp_filename_for(name) : NULL, *path = NULL;
    if (file && asprintf(&path, "%s/profiles/%s", dir, file) < 0) path = NULL;
    free(name);
    free(file);
    return path;
}
