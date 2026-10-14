#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ProxyBridge.h"
#include <stdatomic.h>
#include "pb_bpf.h"
#include "pb_dns.h"
#include "pb_internal.h"
#include "pb_rules.h"

#define MAX_PROXIES 255

static struct {
    pthread_rwlock_t lock;
    struct pb_rule *rules; size_t nrules, caprules;
    struct pb_proxy proxies[MAX_PROXIES]; size_t nproxies;
    uint32_t next_rule_id, next_proxy_id, default_proxy;
    bool dns_via_proxy, traffic_logging, running;
    atomic_bool has_domain_rules;
    LogCallback log_cb;
    ConnectionCallback conn_cb;
} G = { .lock = PTHREAD_RWLOCK_INITIALIZER, .next_rule_id = 1, .next_proxy_id = 1, .dns_via_proxy = true };

static pthread_mutex_t cb_lock = PTHREAD_MUTEX_INITIALIZER;     // serialises user callbacks

static void set_err(char *err, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_err(char *err, size_t n, const char *fmt, ...)
{
    if (!err || !n) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, n, fmt, ap);
    va_end(ap);
}

// ---- logging -----------------------------------------------------------------------------------------------------------
void pb_core_log(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&cb_lock);
    LogCallback cb = G.log_cb;
    if (cb) cb(buf);
    pthread_mutex_unlock(&cb_lock);
}

static const char *proxy_type_name(ProxyType t) { return t == PROXY_TYPE_SOCKS5 ? "SOCKS5" : "HTTP"; }

static void proc_name_of(uint32_t pid, const char *comm, char *out, size_t n)
{
    char lnk[64], path[512];
    snprintf(lnk, sizeof lnk, "/proc/%u/exe", pid);
    ssize_t r = readlink(lnk, path, sizeof path - 1);
    if (r > 0) {
        path[r] = 0;
        const char *b = strrchr(path, '/');
        snprintf(out, n, "%s", b ? b + 1 : path);
        size_t l = strlen(out);
        if (l > 10 && !strcmp(out + l - 10, " (deleted)")) out[l - 10] = 0;
        return;
    }
    snprintf(out, n, "%s", comm && *comm ? comm : "unknown");
}

static void emit_connection(uint32_t pid, const char *comm, int family, const uint8_t addr[16], uint16_t port, int action, uint32_t proxy_id)
{
    if (!G.traffic_logging) return;
    char name[512], ip[INET6_ADDRSTRLEN + 280], info[400];
    proc_name_of(pid, comm, name, sizeof name);
    if (family == AF_INET) {
        inet_ntop(AF_INET, addr + 12, ip, sizeof ip);
        uint32_t h = ((uint32_t)addr[12] << 24) | ((uint32_t)addr[13] << 16) | ((uint32_t)addr[14] << 8) | addr[15];
        char nm[1][256];
        if (pb_dns_lookup(h, nm, 1) == 1) {                      // show the domain the application asked for, when we know it
            size_t l = strlen(ip);
            snprintf(ip + l, sizeof ip - l, " (%.*s)", (int)(sizeof ip - l - 4), nm[0]);
        }
    } else inet_ntop(AF_INET6, addr, ip, sizeof ip);
    if (action == PB_ACT_PROXY) {
        struct pb_proxy p;
        if (pb_core_get_proxy(proxy_id, &p) == 0) snprintf(info, sizeof info, "%s %s:%u", proxy_type_name(p.type), p.host, p.port);
        else snprintf(info, sizeof info, "PROXY");
    } else snprintf(info, sizeof info, "%s", action == PB_ACT_BLOCK ? "BLOCK" : "DIRECT");
    pthread_mutex_lock(&cb_lock);
    ConnectionCallback cb = G.conn_cb;
    if (cb) cb(name, pid, ip, port, info);
    pthread_mutex_unlock(&cb_lock);
}

static void on_bpf_event(const struct pb_event *e)
{
    char comm[17];
    memcpy(comm, e->comm, 16); comm[16] = 0;
    emit_connection(e->pid, comm, e->family, e->addr, e->port, e->action, e->proxy_id);
}

void pb_core_flow_event(const struct pb_orig *o, int action, const char *proxy_desc)
{
    (void)proxy_desc;
    emit_connection(o->pid, NULL, o->family, o->addr, o->port, action, o->proxy_id);
}

bool pb_core_dns_via_proxy(void) { return G.dns_via_proxy; }

// ---- proxies -------------------------------------------------------------------------------------------------------------
static struct pb_proxy *find_proxy_locked(uint32_t id)
{
    for (size_t i = 0; i < G.nproxies; i++) if (G.proxies[i].id == id) return &G.proxies[i];
    return NULL;
}

static struct pb_proxy *default_proxy_locked(void)
{
    struct pb_proxy *p = G.default_proxy ? find_proxy_locked(G.default_proxy) : NULL;
    return p ? p : (G.nproxies ? &G.proxies[0] : NULL);
}

int pb_core_get_proxy(uint32_t id, struct pb_proxy *out)
{
    int rc = -1;
    pthread_rwlock_rdlock(&G.lock);
    struct pb_proxy *p = id ? find_proxy_locked(id) : NULL;
    if (!p) p = default_proxy_locked();
    if (p) { *out = *p; rc = 0; }
    pthread_rwlock_unlock(&G.lock);
    return rc;
}

static bool valid_proxy(const char *host, uint16_t port, char *err, size_t en)
{
    if (!host || !*host) { set_err(err, en, "proxy host is empty"); return false; }
    if (strlen(host) > 253) { set_err(err, en, "proxy host too long"); return false; }
    for (const char *c = host; *c; c++)
        if (isspace((unsigned char)*c) || *c == '/' || *c == '@') { set_err(err, en, "proxy host contains invalid characters"); return false; }
    if (!port) { set_err(err, en, "proxy port must be 1-65535"); return false; }
    return true;
}

static void fill_proxy(struct pb_proxy *p, const char *name, ProxyType type, const char *host, uint16_t port, const char *user, const char *pass)
{
    snprintf(p->name, sizeof p->name, "%s", name && *name ? name : host);
    p->type = type == PROXY_TYPE_HTTP ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
    snprintf(p->host, sizeof p->host, "%s", host);
    p->port = port;
    snprintf(p->user, sizeof p->user, "%s", user ? user : "");
    snprintf(p->pass, sizeof p->pass, "%s", pass ? pass : "");
}

// ---- DNS tap: arm kernel rules for addresses whose names match domain rules ---------------------------------------------------
// Caller holds G.lock (read or write).
static void arm_ip_locked(uint32_t ip, const char *const *names, int nnames)
{
    for (size_t i = 0; i < G.nrules; i++) {
        const struct pb_rule *r = &G.rules[i];
        if (!r->enabled || !r->ndomains) continue;
        for (int d = 0; d < r->ndomains; d++) {
            bool hit = false;
            for (int k = 0; k < nnames && !hit; k++) hit = pb_domain_match(r->domains[d], names[k]);
            if (hit) { pb_bpf_dom_set((uint32_t)i, ip); break; }
        }
    }
}

static void arm_cb(uint32_t ip, const char *const *names, int n, void *ctx)
{
    (void)ctx;
    arm_ip_locked(ip, names, n);
}

static void rearm_all_locked(void)
{
    pb_bpf_dom_clear();
    if (atomic_load(&G.has_domain_rules)) pb_dns_for_each(arm_cb, NULL);
}

void pb_core_dns_observe(const uint8_t *msg, size_t len)
{
    if (!atomic_load(&G.has_domain_rules)) return;
    struct pb_dns_result res;
    if (pb_dns_observe(msg, len, &res) <= 0) return;
    pthread_rwlock_rdlock(&G.lock);
    for (int i = 0; i < res.nips; i++) {
        char names[PB_DNS_MAX_NAMES][256];
        const char *ptrs[PB_DNS_MAX_NAMES];
        int n = pb_dns_lookup(res.ips[i], names, PB_DNS_MAX_NAMES);
        for (int k = 0; k < n; k++) ptrs[k] = names[k];
        arm_ip_locked(res.ips[i], ptrs, n);
    }
    pthread_rwlock_unlock(&G.lock);
}

// ---- rule -> BPF sync ------------------------------------------------------------------------------------------------------
static struct pb_rule_view *build_views_locked(size_t *n)
{
    struct pb_rule_view *v = calloc(G.nrules ? G.nrules : 1, sizeof *v);
    if (!v) return NULL;
    for (size_t i = 0; i < G.nrules; i++) {
        const struct pb_rule *r = &G.rules[i];
        v[i].rule = r;
        v[i].action = r->action;
        if (r->action == RULE_ACTION_PROXY) {
            struct pb_proxy *p = r->proxy_id ? find_proxy_locked(r->proxy_id) : NULL;
            if (!p) p = default_proxy_locked();
            if (!p) v[i].action = RULE_ACTION_BLOCK;           // no usable proxy: fail closed
            else { v[i].proxy_id = (uint16_t)p->id; v[i].udp_direct = p->type == PROXY_TYPE_HTTP; }
        }
    }
    *n = G.nrules;
    return v;
}

static void sync_locked(void)
{
    if (!G.running) return;
    size_t n;
    struct pb_rule_view *v = build_views_locked(&n);
    bool dom = false;
    for (size_t i = 0; i < G.nrules; i++) dom |= G.rules[i].enabled && G.rules[i].ndomains > 0;
    atomic_store(&G.has_domain_rules, dom);
    if (v && pb_bpf_sync(v, n) != 0) pb_core_log("failed to apply rules to the kernel datapath");
    free(v);
    rearm_all_locked();
    pb_bpf_set_flags(G.traffic_logging, G.dns_via_proxy);
}

// ---- slow path -------------------------------------------------------------------------------------------------------------
static bool exe_path_of_pid(uint32_t pid, char *out, size_t n)
{
    char lnk[64];
    snprintf(lnk, sizeof lnk, "/proc/%u/exe", pid);
    ssize_t r = readlink(lnk, out, n - 1);
    if (r <= 0) { out[0] = 0; return false; }
    out[r] = 0;
    size_t l = strlen(out);
    if (l > 10 && !strcmp(out + l - 10, " (deleted)")) out[l - 10] = 0;
    return true;
}

void pb_core_decide(const struct pb_orig *o, struct pb_decision *out)
{
    char path[512];
    exe_path_of_pid(o->pid, path, sizeof path);              // may be empty if the process is already gone
    out->action = PB_ACT_DIRECT; out->proxy_id = 0;

    pthread_rwlock_rdlock(&G.lock);
    if (!pb_implicit_direct(o->family, o->addr, o->port, o->proto, G.dns_via_proxy)) {
        char nbuf[PB_DNS_MAX_NAMES][256];
        const char *nptr[PB_DNS_MAX_NAMES];
        int nn = 0;
        if (o->family == AF_INET && atomic_load(&G.has_domain_rules)) {
            uint32_t h = ((uint32_t)o->addr[12] << 24) | ((uint32_t)o->addr[13] << 16) | ((uint32_t)o->addr[14] << 8) | o->addr[15];
            nn = pb_dns_lookup(h, nbuf, PB_DNS_MAX_NAMES);
            for (int k = 0; k < nn; k++) nptr[k] = nbuf[k];
        }
        int idx = pb_rules_eval(G.rules, G.nrules, path, o->family, o->addr, o->port, o->proto, nptr, nn);
        if (idx >= 0) {
            const struct pb_rule *r = &G.rules[idx];
            if (r->action == RULE_ACTION_PROXY) {
                struct pb_proxy *p = r->proxy_id ? find_proxy_locked(r->proxy_id) : NULL;
                if (!p) p = default_proxy_locked();
                if (!p) out->action = PB_ACT_BLOCK;
                else if (o->proto == IPPROTO_UDP && p->type == PROXY_TYPE_HTTP) out->action = PB_ACT_DIRECT;
                else { out->action = PB_ACT_PROXY; out->proxy_id = p->id; }
            } else out->action = r->action == RULE_ACTION_BLOCK ? PB_ACT_BLOCK : PB_ACT_DIRECT;
        }
    }
    if (o->exe_ino && path[0]) {                              // teach the kernel this binary so the next flow skips the relay
        size_t n;
        struct pb_rule_view *v = build_views_locked(&n);
        if (v) { pb_bpf_learn(o, path, v, n); free(v); }
    }
    pthread_rwlock_unlock(&G.lock);
}

int pb_core_take_tcp_orig(uint16_t client_port, struct pb_orig *out) { return pb_bpf_take_tcp_orig(client_port, out); }
int pb_core_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out) { return pb_bpf_get_udp_flow(flow_ip_be, out); }

// ---- public API: proxies -----------------------------------------------------------------------------------------------
uint32_t ProxyBridge_AddProxy(const char *name, ProxyType type, const char *host, uint16_t port, const char *user, const char *pass, char *err, size_t en)
{
    if (!valid_proxy(host, port, err, en)) return 0;
    pthread_rwlock_wrlock(&G.lock);
    uint32_t id = 0;
    if (G.nproxies >= MAX_PROXIES) set_err(err, en, "too many proxies (max %d)", MAX_PROXIES);
    else {
        struct pb_proxy *p = &G.proxies[G.nproxies++];
        memset(p, 0, sizeof *p);
        p->id = id = G.next_proxy_id++;
        fill_proxy(p, name, type, host, port, user, pass);
        sync_locked();
    }
    pthread_rwlock_unlock(&G.lock);
    return id;
}

bool ProxyBridge_EditProxy(uint32_t id, const char *name, ProxyType type, const char *host, uint16_t port, const char *user, const char *pass, char *err, size_t en)
{
    if (!valid_proxy(host, port, err, en)) return false;
    pthread_rwlock_wrlock(&G.lock);
    struct pb_proxy *p = find_proxy_locked(id);
    if (p) { fill_proxy(p, name, type, host, port, user, pass); sync_locked(); }
    else set_err(err, en, "unknown proxy id %u", id);
    pthread_rwlock_unlock(&G.lock);
    return p != NULL;
}

bool ProxyBridge_DeleteProxy(uint32_t id)
{
    pthread_rwlock_wrlock(&G.lock);
    bool ok = false;
    for (size_t i = 0; i < G.nproxies; i++)
        if (G.proxies[i].id == id) {
            memmove(&G.proxies[i], &G.proxies[i + 1], (G.nproxies - i - 1) * sizeof G.proxies[0]);
            G.nproxies--;
            if (G.default_proxy == id) G.default_proxy = 0;
            ok = true;
            break;
        }
    if (ok) sync_locked();
    pthread_rwlock_unlock(&G.lock);
    return ok;
}

void ProxyBridge_ClearProxies(void)
{
    pthread_rwlock_wrlock(&G.lock);
    G.nproxies = 0; G.default_proxy = 0;
    sync_locked();
    pthread_rwlock_unlock(&G.lock);
}

void ProxyBridge_SetDefaultProxy(uint32_t id)
{
    pthread_rwlock_wrlock(&G.lock);
    G.default_proxy = id;
    sync_locked();
    pthread_rwlock_unlock(&G.lock);
}

bool ProxyBridge_SetProxyConfig(ProxyType type, const char *host, uint16_t port, const char *user, const char *pass)
{
    char err[256];
    pthread_rwlock_rdlock(&G.lock);
    struct pb_proxy *d = default_proxy_locked();
    uint32_t id = d ? d->id : 0;
    pthread_rwlock_unlock(&G.lock);
    if (id) return ProxyBridge_EditProxy(id, NULL, type, host, port, user, pass, err, sizeof err);
    return ProxyBridge_AddProxy("default", type, host, port, user, pass, err, sizeof err) != 0;
}

// ---- public API: rules ---------------------------------------------------------------------------------------------------
bool ProxyBridge_ValidateRule(const char *process, const char *hosts, const char *ports, char *err, size_t en)
{
    struct pb_rule r;
    if (!pb_rule_parse(&r, process, hosts, ports, err, en)) return false;
    pb_rule_free(&r);
    return true;
}

static struct pb_rule *find_rule_locked(uint32_t id, size_t *idx)
{
    for (size_t i = 0; i < G.nrules; i++) if (G.rules[i].id == id) { if (idx) *idx = i; return &G.rules[i]; }
    return NULL;
}

uint32_t ProxyBridge_AddRule(const char *proc, const char *hosts, const char *ports, RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char *err, size_t en)
{
    struct pb_rule r;
    if (!pb_rule_parse(&r, proc, hosts, ports, err, en)) return 0;
    r.enabled = true; r.protocol = protocol; r.action = action; r.proxy_id = proxy_id;
    pthread_rwlock_wrlock(&G.lock);
    uint32_t id = 0;
    if (G.nrules >= PB_MAX_RULES) { set_err(err, en, "too many rules (max %d)", PB_MAX_RULES); pb_rule_free(&r); }
    else {
        if (G.nrules == G.caprules) {
            size_t nc = G.caprules ? G.caprules * 2 : 32;
            struct pb_rule *nr = realloc(G.rules, nc * sizeof *nr);
            if (!nr) { pb_rule_free(&r); set_err(err, en, "out of memory"); pthread_rwlock_unlock(&G.lock); return 0; }
            G.rules = nr; G.caprules = nc;
        }
        r.id = id = G.next_rule_id++;
        G.rules[G.nrules++] = r;
        sync_locked();
    }
    pthread_rwlock_unlock(&G.lock);
    return id;
}

bool ProxyBridge_EditRule(uint32_t id, const char *proc, const char *hosts, const char *ports, RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char *err, size_t en)
{
    struct pb_rule r;
    if (!pb_rule_parse(&r, proc, hosts, ports, err, en)) return false;
    pthread_rwlock_wrlock(&G.lock);
    struct pb_rule *old = find_rule_locked(id, NULL);
    if (!old) { set_err(err, en, "unknown rule id %u", id); pb_rule_free(&r); pthread_rwlock_unlock(&G.lock); return false; }
    r.id = id; r.enabled = old->enabled; r.protocol = protocol; r.action = action; r.proxy_id = proxy_id;
    pb_rule_free(old);
    *old = r;
    sync_locked();
    pthread_rwlock_unlock(&G.lock);
    return true;
}

static bool set_enabled(uint32_t id, bool on)
{
    pthread_rwlock_wrlock(&G.lock);
    struct pb_rule *r = find_rule_locked(id, NULL);
    if (r) { r->enabled = on; sync_locked(); }
    pthread_rwlock_unlock(&G.lock);
    return r != NULL;
}
bool ProxyBridge_EnableRule(uint32_t id) { return set_enabled(id, true); }
bool ProxyBridge_DisableRule(uint32_t id) { return set_enabled(id, false); }

bool ProxyBridge_DeleteRule(uint32_t id)
{
    pthread_rwlock_wrlock(&G.lock);
    size_t i;
    struct pb_rule *r = find_rule_locked(id, &i);
    if (r) {
        pb_rule_free(r);
        memmove(&G.rules[i], &G.rules[i + 1], (G.nrules - i - 1) * sizeof *r);
        G.nrules--;
        sync_locked();
    }
    pthread_rwlock_unlock(&G.lock);
    return r != NULL;
}

bool ProxyBridge_MoveRule(uint32_t id, int new_index)
{
    pthread_rwlock_wrlock(&G.lock);
    size_t i;
    struct pb_rule *r = find_rule_locked(id, &i);
    if (r) {
        size_t to = new_index < 0 ? 0 : (size_t)new_index >= G.nrules ? G.nrules - 1 : (size_t)new_index;
        struct pb_rule tmp = *r;
        if (to < i) memmove(&G.rules[to + 1], &G.rules[to], (i - to) * sizeof tmp);
        else if (to > i) memmove(&G.rules[i], &G.rules[i + 1], (to - i) * sizeof tmp);
        G.rules[to] = tmp;
        sync_locked();
    }
    pthread_rwlock_unlock(&G.lock);
    return r != NULL;
}

void ProxyBridge_ClearRules(void)
{
    pthread_rwlock_wrlock(&G.lock);
    for (size_t i = 0; i < G.nrules; i++) pb_rule_free(&G.rules[i]);
    G.nrules = 0;
    sync_locked();
    pthread_rwlock_unlock(&G.lock);
}

// ---- public API: runtime -----------------------------------------------------------------------------------------------------
void ProxyBridge_SetDnsViaProxy(bool enable)
{
    pthread_rwlock_wrlock(&G.lock);
    G.dns_via_proxy = enable;
    pb_bpf_set_flags(G.traffic_logging, G.dns_via_proxy);
    pthread_rwlock_unlock(&G.lock);
}

void ProxyBridge_SetLogCallback(LogCallback cb) { pthread_mutex_lock(&cb_lock); G.log_cb = cb; pthread_mutex_unlock(&cb_lock); }
void ProxyBridge_SetConnectionCallback(ConnectionCallback cb) { pthread_mutex_lock(&cb_lock); G.conn_cb = cb; pthread_mutex_unlock(&cb_lock); }

void ProxyBridge_SetTrafficLoggingEnabled(bool enable)
{
    pthread_rwlock_wrlock(&G.lock);
    G.traffic_logging = enable;
    pb_bpf_set_flags(G.traffic_logging, G.dns_via_proxy);
    pthread_rwlock_unlock(&G.lock);
}

void ProxyBridge_ClearConnectionLogs(void) {}

bool ProxyBridge_Start(void)
{
    pthread_rwlock_wrlock(&G.lock);
    if (G.running) { pthread_rwlock_unlock(&G.lock); return true; }
    for (size_t i = 0; i < G.nrules; i++)
        if (G.rules[i].enabled && G.rules[i].action == RULE_ACTION_PROXY && !default_proxy_locked() &&
            !(G.rules[i].proxy_id && find_proxy_locked(G.rules[i].proxy_id))) {
            pthread_rwlock_unlock(&G.lock);
            pb_core_log("cannot start: a rule uses a proxy but no proxy is configured");
            return false;
        }
    G.running = true;                                        // pb_core_* callbacks may fire as soon as the relay is up
    pthread_rwlock_unlock(&G.lock);

    bool started = false;
    for (uint16_t base = PB_TCP_RELAY_PORT_DEFAULT; base < PB_TCP_RELAY_PORT_DEFAULT + 20 && !started; base += 2) {
        struct pb_relay_cfg rc = { .tcp_port = base, .udp_port = (uint16_t)(base + 1) };
        started = pb_relay_start(&rc) == 0;
    }
    if (!started) { pthread_rwlock_wrlock(&G.lock); G.running = false; pthread_rwlock_unlock(&G.lock); return false; }

    struct pb_bpf_cfg bc = { .tcp_port = pb_relay_tcp_port(), .udp_port = pb_relay_udp_port(), .self_tgid = (uint32_t)getpid(),
                             .log = G.traffic_logging, .dns_via_proxy = G.dns_via_proxy };
    if (pb_bpf_start(&bc, on_bpf_event) != 0) {
        pb_relay_stop();
        pthread_rwlock_wrlock(&G.lock); G.running = false; pthread_rwlock_unlock(&G.lock);
        return false;
    }
    pb_dns_load_hosts("/etc/hosts", NULL);                   // static names are known without any DNS traffic
    pthread_rwlock_wrlock(&G.lock);
    sync_locked();
    pthread_rwlock_unlock(&G.lock);
    pb_core_log("ProxyBridge started (eBPF datapath, relay tcp:%u udp:%u)", pb_relay_tcp_port(), pb_relay_udp_port());
    return true;
}

bool ProxyBridge_Stop(void)
{
    pthread_rwlock_wrlock(&G.lock);
    bool was = G.running;
    G.running = false;
    pthread_rwlock_unlock(&G.lock);
    if (!was) return true;
    pb_bpf_stop();         // detach first: no new flows get redirected
    pb_relay_stop();
    pb_core_log("ProxyBridge stopped");
    return true;
}

int ProxyBridge_TestProxy(uint32_t proxy_id, const char *host, uint16_t port, char *buf, size_t n)
{
    struct pb_proxy p;
    if (pb_core_get_proxy(proxy_id, &p) != 0) { snprintf(buf, n, "no proxy configured"); return -1; }
    return pb_relay_test_proxy(&p, host, port, buf, n);
}

int ProxyBridge_TestConnection(const char *host, uint16_t port, char *buf, size_t n)
{
    return ProxyBridge_TestProxy(0, host, port, buf, n);
}
