#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include "ProxyBridge.h"
#include "pb_bpf.h"
#include "pb_dns.h"
#include "pb_internal.h"
#include "pb_proc.h"
#include "pb_rules.h"

#define MAX_PROXIES 255
#define MAINT_PERIOD_S 2
#define HOSTS_PATH "/etc/hosts"

static struct {
    pthread_rwlock_t lock;
    struct pb_rule *rules; size_t nrules, caprules;
    struct pb_rule_view *views; size_t nviews;
    struct pb_proxy proxies[MAX_PROXIES]; size_t nproxies;
    uint32_t next_rule_id, next_proxy_id, default_proxy;
    bool running;
    atomic_bool dns_via_proxy, traffic_logging, need_names, has_localhost, paused, log_every;
    pthread_t maint;
    bool maint_started, maint_stop, maint_kick;
    pthread_mutex_t maint_mu;
    pthread_cond_t maint_cv;
    uint64_t warned[16]; size_t nwarned;
    int batch; bool batch_dirty;         // BeginBatch/EndBatch: changes reach the kernel datapath once, at the end
    LogCallback log_cb;
    ConnectionCallback conn_cb;
    ConnectionCallbackEx conn_cb_ex;
} G = { .lock = PTHREAD_RWLOCK_INITIALIZER, .maint_mu = PTHREAD_MUTEX_INITIALIZER, .maint_cv = PTHREAD_COND_INITIALIZER,
       .next_rule_id = 1, .next_proxy_id = 1, .dns_via_proxy = true };

static pthread_mutex_t cb_lock = PTHREAD_MUTEX_INITIALIZER;

static void set_err(char *err, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_err(char *err, size_t n, const char *fmt, ...)
{
    if (!err || !n) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, n, fmt, ap);
    va_end(ap);
}

// Anything shown to the operator may carry bytes chosen by another local user (an executable's name, a DNS answer);
// a terminal or a log file must not receive control characters from them.
static void sanitize(char *s)
{
    for (unsigned char *p = (unsigned char *)s; *p; p++)
        if (*p < 0x20 || *p == 0x7F) *p = '?';
}

void pb_core_log(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    sanitize(buf);
    pthread_mutex_lock(&cb_lock);
    if (G.log_cb) G.log_cb(buf);
    pthread_mutex_unlock(&cb_lock);
}

static void strip_deleted(char *p)
{
    static const char suffix[] = " (deleted)";
    size_t n = strlen(p), s = sizeof suffix - 1;
    if (n > s && !strcmp(p + n - s, suffix)) p[n - s] = 0;
}

static bool exe_path_of_pid(uint32_t pid, char *out, size_t n)
{
    char link[64];
    snprintf(link, sizeof link, "/proc/%u/exe", pid);
    ssize_t r = readlink(link, out, n - 1);
    if (r <= 0) { out[0] = 0; return false; }
    out[r] = 0;
    strip_deleted(out);
    return true;
}

// Connection log history: bounded, so a busy host cannot grow it. Entries are replaced oldest-first within a short probe window.
#define SEEN_SLOTS  8192
#define SEEN_PROBES 8
#define UDP_RELOG_MS 30000
static struct seen_ent { uint64_t key; int64_t at; } *seen_tab;
static pthread_mutex_t seen_mu = PTHREAD_MUTEX_INITIALIZER;

static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint64_t conn_key(const char *name, int family, const uint8_t addr[16], uint16_t port, int proto, int action, uint32_t proxy_id)
{
    uint64_t h = 1469598103934665603ULL;
    for (const char *s = name; *s; s++) h = (h ^ (uint8_t)*s) * 1099511628211ULL;
    const uint8_t extra[] = { (uint8_t)family, (uint8_t)(port >> 8), (uint8_t)port, (uint8_t)proto, (uint8_t)action, (uint8_t)proxy_id, (uint8_t)(proxy_id >> 8) };
    for (size_t i = 0; i < sizeof extra; i++) h = (h ^ extra[i]) * 1099511628211ULL;
    for (int i = 0; i < 16; i++) h = (h ^ addr[i]) * 1099511628211ULL;
    return h ? h : 1;
}

// Should this connection appear in the log?
static bool log_wanted(uint64_t key, bool udp)
{
    bool every = atomic_load(&G.log_every), want = true;
    int64_t now = mono_ms();
    pthread_mutex_lock(&seen_mu);
    if (!seen_tab) seen_tab = calloc(SEEN_SLOTS, sizeof *seen_tab);
    if (seen_tab) {
        struct seen_ent *hit = NULL, *victim = NULL;
        for (int i = 0; i < SEEN_PROBES && !hit; i++) {
            struct seen_ent *e = &seen_tab[(key + (uint64_t)i) % SEEN_SLOTS];
            if (e->key == key) hit = e;
            else if (e->key == 0) { if (!victim || victim->key) victim = e; }
            else if (!victim || (victim->key && e->at < victim->at)) victim = e;
        }
        if (hit) {
            want = every && (!udp || now - hit->at >= UDP_RELOG_MS);
            hit->at = now;                      // traffic keeps a UDP flow "alive"
        } else if (victim) {
            victim->key = key;
            victim->at = now;
        }
    }
    pthread_mutex_unlock(&seen_mu);
    return want;
}

static void emit_connection(uint32_t pid, const char *comm, int family, const uint8_t addr[16], uint16_t port, int proto, int action, uint32_t proxy_id)
{
    if (!atomic_load(&G.traffic_logging)) return;
    char path[4096], dest[INET6_ADDRSTRLEN + 280], info[400], shown[256];
    const char *name = comm && *comm ? comm : "unknown";
    if (exe_path_of_pid(pid, path, sizeof path)) {
        const char *base = strrchr(path, '/');
        name = base ? base + 1 : path;
    }
    snprintf(shown, sizeof shown, "%s", name);
    sanitize(shown);
    name = shown;
    if (!log_wanted(conn_key(name, family, addr, port, proto, action, proxy_id), proto == IPPROTO_UDP)) return;
    if (family == AF_INET) {
        inet_ntop(AF_INET, addr + 12, dest, sizeof dest);
        uint32_t ip = ((uint32_t)addr[12] << 24) | ((uint32_t)addr[13] << 16) | ((uint32_t)addr[14] << 8) | addr[15];
        char domain[1][256];
        if (pb_dns_lookup(ip, domain, 1) == 1) {
            size_t l = strlen(dest);
            snprintf(dest + l, sizeof dest - l, " (%.*s)", (int)(sizeof dest - l - 4), domain[0]);
        }
    } else {
        inet_ntop(AF_INET6, addr, dest, sizeof dest);
    }
    struct pb_proxy p;
    if (action == PB_ACT_PROXY && pb_core_get_proxy(proxy_id, &p) == 0)
        snprintf(info, sizeof info, "%s %s:%u", p.type == PROXY_TYPE_SOCKS5 ? "SOCKS5" : "HTTP", p.host, p.port);
    else
        snprintf(info, sizeof info, "%s", action == PB_ACT_PROXY ? "PROXY" : action == PB_ACT_BLOCK ? "BLOCK" : "DIRECT");
    sanitize(dest);
    pthread_mutex_lock(&cb_lock);
    if (G.conn_cb) G.conn_cb(name, pid, dest, port, info);
    if (G.conn_cb_ex) G.conn_cb_ex(name, pid, dest, port, proto == IPPROTO_UDP ? "UDP" : "TCP", info);
    pthread_mutex_unlock(&cb_lock);
}

static void on_bpf_event(const struct pb_event *e)
{
    char comm[17];
    memcpy(comm, e->comm, 16);
    comm[16] = 0;
    emit_connection(e->pid, comm, e->family, e->addr, e->port, e->proto, e->action, e->proxy_id);
}

// The kernel already reported every flow it decided itself; the relay only reports the ones it decided.
void pb_core_flow_event(const struct pb_orig *o, int action)
{
    if (o->action != PB_ACT_DECIDE) return;
    char hint[4096];
    const char *comm = NULL;                       // the process may be gone already: the kernel's executable identity still names it
    if (pb_bpf_exe_path(o->exe_dev, o->exe_ino, hint, sizeof hint)) {
        const char *base = strrchr(hint, '/');
        comm = base ? base + 1 : hint;
    }
    emit_connection(o->pid, comm, o->family, o->addr, o->port, o->proto, action, o->proxy_id);
}

static struct pb_proxy *find_proxy_locked(uint32_t id)
{
    for (size_t i = 0; i < G.nproxies; i++)
        if (G.proxies[i].id == id) return &G.proxies[i];
    return NULL;
}

static struct pb_proxy *default_proxy_locked(void)
{
    struct pb_proxy *p = G.default_proxy ? find_proxy_locked(G.default_proxy) : NULL;
    return p ? p : (G.nproxies ? &G.proxies[0] : NULL);
}

static struct pb_proxy *proxy_for_rule_locked(const struct pb_rule *r)
{
    struct pb_proxy *p = r->proxy_id ? find_proxy_locked(r->proxy_id) : NULL;
    return p ? p : default_proxy_locked();
}

int pb_core_get_proxy(uint32_t id, struct pb_proxy *out)
{
    pthread_rwlock_rdlock(&G.lock);
    struct pb_proxy *p = id ? find_proxy_locked(id) : NULL;
    if (!p) p = default_proxy_locked();
    if (p) *out = *p;
    pthread_rwlock_unlock(&G.lock);
    return p ? 0 : -1;
}

static void maint_kick(void)
{
    pthread_mutex_lock(&G.maint_mu);
    G.maint_kick = true;
    pthread_cond_signal(&G.maint_cv);
    pthread_mutex_unlock(&G.maint_mu);
}

// Domain rules: arm the kernel for addresses whose DNS name matches a rule. Caller holds G.lock.
static void arm_ip_locked(uint32_t ip, const char *const *names, int nnames)
{
    for (size_t i = 0; i < G.nrules; i++) {
        const struct pb_rule *r = &G.rules[i];
        if (!r->enabled) continue;
        bool hit = false;
        for (int d = 0; d < r->ndomains && !hit; d++)
            for (int k = 0; k < nnames && !hit; k++) hit = pb_domain_match(r->domains[d], names[k]);
        if (hit) pb_bpf_dom_set((uint32_t)i, ip);
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
    if (atomic_load(&G.need_names)) pb_dns_for_each(arm_cb, NULL);
}

void pb_core_dns_observe(const uint8_t *msg, size_t len)
{
    if (!atomic_load(&G.need_names)) return;
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

static void warn_udp_over_http_locked(void)
{
    for (size_t i = 0; i < G.nrules; i++) {
        const struct pb_rule *r = &G.rules[i];
        if (!r->enabled || r->action != RULE_ACTION_PROXY || r->protocol == RULE_PROTOCOL_TCP) continue;
        const struct pb_proxy *p = proxy_for_rule_locked(r);
        if (!p || p->type != PROXY_TYPE_HTTP) continue;
        uint64_t key = ((uint64_t)r->id << 32) | p->id;
        bool seen = false;
        for (size_t k = 0; k < G.nwarned && !seen; k++) seen = G.warned[k] == key;
        if (seen) continue;
        if (G.nwarned < sizeof G.warned / sizeof *G.warned) G.warned[G.nwarned++] = key;
        pb_core_log("rule %u sends UDP to HTTP proxy '%s', which cannot carry UDP: that UDP traffic goes DIRECT", r->id, p->name);
    }
}

static void rebuild_views_locked(void)
{
    free(G.views);
    G.views = calloc(G.nrules ? G.nrules : 1, sizeof *G.views);
    G.nviews = G.views ? G.nrules : 0;
    bool names = false, localhost = false;
    for (size_t i = 0; i < G.nviews; i++) {
        const struct pb_rule *r = &G.rules[i];
        struct pb_rule_view *v = &G.views[i];
        v->rule = r;
        v->action = r->action;
        v->wants_names = r->enabled && r->ndomains > 0;
        if (r->action == RULE_ACTION_PROXY) {
            const struct pb_proxy *p = proxy_for_rule_locked(r);
            if (!p) {
                v->action = RULE_ACTION_BLOCK;      // no usable proxy: fail closed
            } else {
                v->proxy_id = (uint16_t)p->id;
                v->udp_direct = p->type == PROXY_TYPE_HTTP;
                v->localhost = r->enabled && r->localhost;
                v->wants_names |= r->enabled && p->send_domain;
            }
        }
        names |= v->wants_names;
        localhost |= v->localhost;
    }
    atomic_store(&G.need_names, names);
    atomic_store(&G.has_localhost, localhost);
}

static void sync_locked(void)
{
    rebuild_views_locked();
    if (!G.running) return;
    if (G.batch > 0) { G.batch_dirty = true; return; }
    if (pb_bpf_sync(G.views, G.nviews) != 0) pb_core_log("failed to apply rules to the kernel datapath");
    pb_bpf_set_flags(atomic_load(&G.traffic_logging), atomic_load(&G.dns_via_proxy));
    rearm_all_locked();
    warn_udp_over_http_locked();
}

static bool is_loopback(const struct pb_orig *o)
{
    if (o->family == AF_INET) return o->addr[12] == 127;
    static const uint8_t lo6[16] = { [15] = 1 };
    return memcmp(o->addr, lo6, 16) == 0;
}

int pb_core_name_for(const struct pb_orig *o, char *out, size_t n)
{
    if (o->family != AF_INET || !atomic_load(&G.need_names)) return -1;
    uint32_t ip = ((uint32_t)o->addr[12] << 24) | ((uint32_t)o->addr[13] << 16) | ((uint32_t)o->addr[14] << 8) | o->addr[15];
    char names[PB_DNS_MAX_NAMES][256];
    int k = pb_dns_lookup(ip, names, PB_DNS_MAX_NAMES);
    if (k <= 0) return -1;
    const char *nm = names[k - 1];                // the lookup lists the most recent query name last
    size_t len = strlen(nm);
    if (len == 0 || len > 253 || len >= n) return -1;
    for (size_t i = 0; i < len; i++) {            // the name came from the network: only host name characters go into a proxy request
        unsigned char ch = (unsigned char)nm[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.')) return -1;
    }
    if (nm[0] == '.' || nm[len - 1] == '.' ) return -1;
    memcpy(out, nm, len + 1);
    return 0;
}

void pb_core_decide(const struct pb_orig *o, struct pb_decision *out)
{
    char path[4096];
    // The executable the kernel saw at connect() time is authoritative; /proc/<pid>/exe may already belong to another
    // program if the process exited and its PID was reused before this flow reached the relay.
    if (!(o->exe_ino && pb_bpf_exe_path(o->exe_dev, o->exe_ino, path, sizeof path)) && !exe_path_of_pid(o->pid, path, sizeof path)) path[0] = 0;
    out->action = PB_ACT_DIRECT;
    out->proxy_id = 0;

    if (atomic_load(&G.paused)) return;
    pthread_rwlock_rdlock(&G.lock);
    bool lo = atomic_load(&G.has_localhost) && is_loopback(o) && o->port != 53 &&
              o->port != pb_relay_tcp_port() && o->port != pb_relay_udp_port();
    if (lo || !pb_implicit_direct(o->family, o->addr, o->port, o->proto, atomic_load(&G.dns_via_proxy))) {
        char names[PB_DNS_MAX_NAMES][256];
        const char *ptrs[PB_DNS_MAX_NAMES] = { 0 };
        int nn = 0;
        if (o->family == AF_INET && atomic_load(&G.need_names)) {
            uint32_t ip = ((uint32_t)o->addr[12] << 24) | ((uint32_t)o->addr[13] << 16) | ((uint32_t)o->addr[14] << 8) | o->addr[15];
            nn = pb_dns_lookup(ip, names, PB_DNS_MAX_NAMES);
            for (int k = 0; k < nn; k++) ptrs[k] = names[k];
        }
        int idx = pb_rules_eval(G.rules, G.nrules, path, o->family, o->addr, o->port, o->proto, ptrs, nn);
        if (idx >= 0 && lo && !(G.rules[idx].action == RULE_ACTION_PROXY && G.rules[idx].localhost)) {
            idx = -1;                                   // loopback stays direct unless the matching rule proxies it
        }
        if (idx >= 0) {
            const struct pb_rule *r = &G.rules[idx];
            if (r->action != RULE_ACTION_PROXY) {
                out->action = r->action == RULE_ACTION_BLOCK ? PB_ACT_BLOCK : PB_ACT_DIRECT;
            } else {
                const struct pb_proxy *p = proxy_for_rule_locked(r);
                if (!p) out->action = PB_ACT_BLOCK;
                else if (o->proto == IPPROTO_UDP && p->type == PROXY_TYPE_HTTP) out->action = PB_ACT_DIRECT;
                else { out->action = PB_ACT_PROXY; out->proxy_id = p->id; }
            }
        }
    }
    if (o->exe_ino && path[0]) pb_bpf_learn(o, path, G.views, G.nviews);
    pthread_rwlock_unlock(&G.lock);
}

int pb_core_take_tcp_orig(uint32_t client_ip_be, uint16_t client_port, struct pb_orig *out)
{
    return pb_bpf_take_tcp_orig(client_ip_be, client_port, out);
}

int pb_core_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out) { return pb_bpf_get_udp_flow(flow_ip_be, out); }

// ---- local proxy exemption and /etc/hosts -------------------------------------------------------------------------------
// A rule such as "*:...:PROXY" would also match the proxy's own outbound connections and send them back through itself, so
// the processes that listen on a configured local proxy address are never redirected.

struct host_cache { char host[256]; uint32_t ip_be; time_t at; };

static uint32_t resolve_proxy_ip(const char *host, struct host_cache *cache, size_t ncache, time_t now)
{
    struct in_addr a;
    if (inet_pton(AF_INET, host, &a) == 1) return a.s_addr;
    if (!strcmp(host, "localhost")) return htonl(INADDR_LOOPBACK);
    size_t slot = 0;
    for (size_t i = 0; i < ncache; i++) {
        if (!strcmp(cache[i].host, host)) { slot = i; break; }
        if (cache[i].at < cache[slot].at) slot = i;
    }
    if (strcmp(cache[slot].host, host) || now - cache[slot].at > 60) {
        struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res = NULL;
        snprintf(cache[slot].host, sizeof cache[slot].host, "%.255s", host);
        cache[slot].at = now;
        cache[slot].ip_be = 0;
        if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
            cache[slot].ip_be = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
            freeaddrinfo(res);
        }
    }
    return cache[slot].ip_be;
}

#define LOOP_CACHE 32
static struct { uint32_t pid, proxy_id; int64_t until; bool hit; } loop_cache[LOOP_CACHE];
static unsigned loop_next;
static struct host_cache loop_hosts[4];
static pthread_mutex_t loop_mu = PTHREAD_MUTEX_INITIALIZER;

int pb_core_udp_sender_ok(const struct pb_orig *o, uint16_t client_port)
{
    /* Best effort, not a proof. The datagram is refused only on positive evidence that another USER sent it: a socket bound to the
     * source port belongs to a uid that is neither the flow's owner nor root. Programs of one user are not a security boundary
     * and the check never looks into descriptor tables, so it costs the same for a process with ten sockets and with ten
     * thousand. When nobody holds the port any more (the sender closed its socket or exited right after sending) nothing can be
     * told and the datagram is delivered: a program that sends one datagram and quits must still get it through. */
    uint32_t uids[8];
    size_t n = pb_proc_udp_port_uids(client_port, uids, 8);
    if (!n) return 1;
    char dir[32];
    struct stat st;
    snprintf(dir, sizeof dir, "/proc/%u", o->pid);
    if (stat(dir, &st) != 0) return 1;                           /* the flow's owner has exited */
    if (o->exe_ino) {
        char link[64];
        struct stat ex;
        snprintf(link, sizeof link, "/proc/%u/exe", o->pid);
        if (stat(link, &ex) == 0) {
            uint32_t dev = (major(ex.st_dev) << 20) | minor(ex.st_dev);   /* same encoding as the BPF program's exe2class key */
            if (dev != o->exe_dev || ex.st_ino != o->exe_ino) return 0;   /* the pid now runs another program */
        }
    }
    for (size_t i = 0; i < n; i++)
        if (uids[i] != 0 && uids[i] != (uint32_t)st.st_uid) return 0;
    return 1;
}

int pb_core_is_proxy_process(uint32_t pid, uint32_t proxy_id)
{
    int64_t now = mono_ms();
    pthread_mutex_lock(&loop_mu);
    for (int i = 0; i < LOOP_CACHE; i++)
        if (loop_cache[i].pid == pid && loop_cache[i].proxy_id == proxy_id && loop_cache[i].until > now) {
            int hit = loop_cache[i].hit;
            pthread_mutex_unlock(&loop_mu);
            return hit;
        }
    pthread_mutex_unlock(&loop_mu);

    struct pb_proxy px;
    bool hit = false;
    if (pb_core_get_proxy(proxy_id, &px) == 0) {
        pthread_mutex_lock(&loop_mu);
        uint32_t ip = resolve_proxy_ip(px.host, loop_hosts, 4, time(NULL));
        pthread_mutex_unlock(&loop_mu);
        hit = ip && pb_proc_is_local_ip(ip) && pb_proc_pid_listens(pid, ip, px.port);
    }
    pthread_mutex_lock(&loop_mu);
    unsigned slot = loop_next++ % LOOP_CACHE;
    loop_cache[slot].pid = pid; loop_cache[slot].proxy_id = proxy_id; loop_cache[slot].hit = hit; loop_cache[slot].until = now + 3000;
    pthread_mutex_unlock(&loop_mu);
    if (hit) {
        pb_core_log("process %u serves proxy '%s': its own connections are sent direct, not back through the proxy", pid, px.name);
        maint_kick();                       // exempt it in the kernel too, so later connections skip the relay
    }
    return hit;
}

static void refresh_exempt(struct host_cache *cache, size_t ncache, uint32_t *last, size_t *nlast)
{
    struct { char host[256]; uint16_t port; } targets[MAX_PROXIES];
    size_t nt = 0;
    pthread_rwlock_rdlock(&G.lock);
    for (size_t i = 0; i < G.nproxies; i++) {
        snprintf(targets[nt].host, sizeof targets[nt].host, "%.255s", G.proxies[i].host);
        targets[nt++].port = G.proxies[i].port;
    }
    pthread_rwlock_unlock(&G.lock);

    uint32_t tgids[64];
    size_t n = 0;
    time_t now = time(NULL);
    for (size_t i = 0; i < nt && n < 64; i++) {
        uint32_t ip = resolve_proxy_ip(targets[i].host, cache, ncache, now);
        if (!ip || !pb_proc_is_local_ip(ip)) continue;
        uint32_t found[8];
        size_t nf = pb_proc_listeners(ip, targets[i].port, found, 8);
        for (size_t k = 0; k < nf && n < 64; k++) {
            bool dup = false;
            for (size_t j = 0; j < n && !dup; j++) dup = tgids[j] == found[k];
            if (!dup && found[k] != (uint32_t)getpid()) tgids[n++] = found[k];
        }
    }
    if (n != *nlast || memcmp(tgids, last, n * sizeof *tgids)) {
        pb_bpf_set_exempt(tgids, n);
        memcpy(last, tgids, n * sizeof *tgids);
        *nlast = n;
    }
}

static void reload_hosts_if_changed(time_t *mtime, off_t *size)
{
    struct stat st;
    if (stat(HOSTS_PATH, &st) != 0 || (st.st_mtime == *mtime && st.st_size == *size)) return;
    *mtime = st.st_mtime;
    *size = st.st_size;
    pb_dns_load_hosts(HOSTS_PATH, NULL);
    pthread_rwlock_rdlock(&G.lock);
    rearm_all_locked();
    pthread_rwlock_unlock(&G.lock);
}

static void *maint_loop(void *arg)
{
    (void)arg;
    struct host_cache cache[8] = { 0 };
    uint32_t last[64];
    size_t nlast = 0;
    time_t hosts_mtime = 0;
    off_t hosts_size = 0;
    pthread_mutex_lock(&G.maint_mu);
    while (!G.maint_stop) {
        G.maint_kick = false;
        pthread_mutex_unlock(&G.maint_mu);
        refresh_exempt(cache, 8, last, &nlast);
        reload_hosts_if_changed(&hosts_mtime, &hosts_size);
        pthread_mutex_lock(&G.maint_mu);
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_sec += MAINT_PERIOD_S;
        while (!G.maint_stop && !G.maint_kick && pthread_cond_timedwait(&G.maint_cv, &G.maint_mu, &until) == 0) {}
    }
    pthread_mutex_unlock(&G.maint_mu);
    return NULL;
}

// ---- proxies -------------------------------------------------------------------------------------------------------------
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

uint32_t ProxyBridge_AddProxy(const char *name, ProxyType type, const char *host, uint16_t port, const char *user, const char *pass, char *err, size_t en)
{
    if (!valid_proxy(host, port, err, en)) return 0;
    uint32_t id = 0;
    pthread_rwlock_wrlock(&G.lock);
    if (G.nproxies >= MAX_PROXIES) {
        set_err(err, en, "too many proxies (max %d)", MAX_PROXIES);
    } else {
        struct pb_proxy *p = &G.proxies[G.nproxies++];
        memset(p, 0, sizeof *p);
        p->id = id = G.next_proxy_id++;
        p->send_domain = true;
        fill_proxy(p, name, type, host, port, user, pass);
        sync_locked();
    }
    pthread_rwlock_unlock(&G.lock);
    if (id) maint_kick();
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
    if (p) maint_kick();
    return p != NULL;
}

bool ProxyBridge_SetProxySendDomain(uint32_t id, bool send_domain)
{
    pthread_rwlock_wrlock(&G.lock);
    struct pb_proxy *p = find_proxy_locked(id);
    if (p) { p->send_domain = send_domain; sync_locked(); }
    pthread_rwlock_unlock(&G.lock);
    return p != NULL;
}

bool ProxyBridge_DeleteProxy(uint32_t id)
{
    bool ok = false;
    pthread_rwlock_wrlock(&G.lock);
    for (size_t i = 0; i < G.nproxies && !ok; i++) {
        if (G.proxies[i].id != id) continue;
        memmove(&G.proxies[i], &G.proxies[i + 1], (G.nproxies - i - 1) * sizeof G.proxies[0]);
        G.nproxies--;
        if (G.default_proxy == id) G.default_proxy = 0;
        ok = true;
    }
    if (ok) sync_locked();
    pthread_rwlock_unlock(&G.lock);
    if (ok) maint_kick();
    return ok;
}

void ProxyBridge_ClearProxies(void)
{
    pthread_rwlock_wrlock(&G.lock);
    G.nproxies = 0;
    G.default_proxy = 0;
    sync_locked();
    pthread_rwlock_unlock(&G.lock);
    maint_kick();
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
    const struct pb_proxy *d = default_proxy_locked();
    uint32_t id = d ? d->id : 0;
    pthread_rwlock_unlock(&G.lock);
    if (id) return ProxyBridge_EditProxy(id, NULL, type, host, port, user, pass, err, sizeof err);
    return ProxyBridge_AddProxy("default", type, host, port, user, pass, err, sizeof err) != 0;
}

// ---- rules ---------------------------------------------------------------------------------------------------------------
bool ProxyBridge_ValidateRule(const char *process, const char *hosts, const char *ports, char *err, size_t en)
{
    struct pb_rule r;
    if (!pb_rule_parse(&r, process, hosts, ports, err, en)) return false;
    pb_rule_free(&r);
    return true;
}

static struct pb_rule *find_rule_locked(uint32_t id, size_t *idx)
{
    for (size_t i = 0; i < G.nrules; i++)
        if (G.rules[i].id == id) { if (idx) *idx = i; return &G.rules[i]; }
    return NULL;
}

uint32_t ProxyBridge_AddRule(const char *proc, const char *hosts, const char *ports, RuleProtocol protocol, RuleAction action, uint32_t proxy_id, char *err, size_t en)
{
    struct pb_rule r;
    if (!pb_rule_parse(&r, proc, hosts, ports, err, en)) return 0;
    r.enabled = true;
    r.protocol = protocol;
    r.action = action;
    r.proxy_id = proxy_id;

    uint32_t id = 0;
    pthread_rwlock_wrlock(&G.lock);
    if (G.nrules >= PB_MAX_RULES) {
        set_err(err, en, "too many rules (max %d)", PB_MAX_RULES);
    } else if (G.nrules == G.caprules) {
        size_t cap = G.caprules ? G.caprules * 2 : 32;
        struct pb_rule *grown = realloc(G.rules, cap * sizeof *grown);
        if (grown) { G.rules = grown; G.caprules = cap; }
        else set_err(err, en, "out of memory");
    }
    if (G.nrules < G.caprules && G.nrules < PB_MAX_RULES) {
        r.id = id = G.next_rule_id++;
        G.rules[G.nrules++] = r;
        sync_locked();
    } else {
        pb_rule_free(&r);
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
    if (!old) {
        set_err(err, en, "unknown rule id %u", id);
        pb_rule_free(&r);
    } else {
        r.id = id;
        r.enabled = old->enabled;
        r.localhost = old->localhost;
        r.protocol = protocol;
        r.action = action;
        r.proxy_id = proxy_id;
        pb_rule_free(old);
        *old = r;
        sync_locked();
    }
    pthread_rwlock_unlock(&G.lock);
    return old != NULL;
}

bool ProxyBridge_SetRuleLocalhost(uint32_t id, bool on)
{
    pthread_rwlock_wrlock(&G.lock);
    struct pb_rule *r = find_rule_locked(id, NULL);
    if (r) { r->localhost = on; sync_locked(); }
    pthread_rwlock_unlock(&G.lock);
    return r != NULL;
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
    size_t i;
    pthread_rwlock_wrlock(&G.lock);
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
    size_t i;
    pthread_rwlock_wrlock(&G.lock);
    struct pb_rule *r = find_rule_locked(id, &i);
    if (r) {
        size_t to = new_index < 0 ? 0 : (size_t)new_index >= G.nrules ? G.nrules - 1 : (size_t)new_index;
        struct pb_rule moved = *r;
        if (to < i) memmove(&G.rules[to + 1], &G.rules[to], (i - to) * sizeof moved);
        else if (to > i) memmove(&G.rules[i], &G.rules[i + 1], (to - i) * sizeof moved);
        G.rules[to] = moved;
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

// ---- runtime -------------------------------------------------------------------------------------------------------------
void ProxyBridge_SetDnsViaProxy(bool enable)
{
    atomic_store(&G.dns_via_proxy, enable);
    pb_bpf_set_flags(atomic_load(&G.traffic_logging), enable);
}

void ProxyBridge_SetLogCallback(LogCallback cb)
{
    pthread_mutex_lock(&cb_lock);
    G.log_cb = cb;
    pthread_mutex_unlock(&cb_lock);
}

void ProxyBridge_SetConnectionCallbackEx(ConnectionCallbackEx cb)
{
    pthread_mutex_lock(&cb_lock);
    G.conn_cb_ex = cb;
    pthread_mutex_unlock(&cb_lock);
}

void ProxyBridge_SetConnectionCallback(ConnectionCallback cb)
{
    pthread_mutex_lock(&cb_lock);
    G.conn_cb = cb;
    pthread_mutex_unlock(&cb_lock);
}

void ProxyBridge_SetTrafficLoggingEnabled(bool enable)
{
    atomic_store(&G.traffic_logging, enable);
    pb_bpf_set_flags(enable, atomic_load(&G.dns_via_proxy));
}

void ProxyBridge_ClearConnectionLogs(void)
{
    pthread_mutex_lock(&seen_mu);
    if (seen_tab) memset(seen_tab, 0, SEEN_SLOTS * sizeof *seen_tab);
    pthread_mutex_unlock(&seen_mu);
}

void ProxyBridge_SetLogEveryConnection(bool enable) { atomic_store(&G.log_every, enable); }

void ProxyBridge_BeginBatch(void)
{
    pthread_rwlock_wrlock(&G.lock);
    G.batch++;
    pthread_rwlock_unlock(&G.lock);
}

void ProxyBridge_EndBatch(void)
{
    pthread_rwlock_wrlock(&G.lock);
    if (G.batch > 0 && --G.batch == 0 && G.batch_dirty) {
        G.batch_dirty = false;
        sync_locked();
    }
    pthread_rwlock_unlock(&G.lock);
}

void ProxyBridge_SetEnabled(bool enable)
{
    atomic_store(&G.paused, !enable);
    pb_bpf_set_paused(!enable);
}

static bool proxies_missing_locked(void)
{
    for (size_t i = 0; i < G.nrules; i++) {
        const struct pb_rule *r = &G.rules[i];
        if (r->enabled && r->action == RULE_ACTION_PROXY && !proxy_for_rule_locked(r)) return true;
    }
    return false;
}

bool ProxyBridge_Start(void)
{
    pthread_rwlock_wrlock(&G.lock);
    if (G.running) { pthread_rwlock_unlock(&G.lock); return true; }
    if (proxies_missing_locked()) {
        pthread_rwlock_unlock(&G.lock);
        pb_core_log("cannot start: a rule uses a proxy but no proxy is configured");
        return false;
    }
    G.running = true;                  // relay callbacks may fire as soon as the relay is up
    pthread_rwlock_unlock(&G.lock);

    bool relay_up = false;
    for (uint16_t base = PB_TCP_RELAY_PORT_DEFAULT; base < PB_TCP_RELAY_PORT_DEFAULT + 20 && !relay_up; base += 2) {
        struct pb_relay_cfg rc = { .tcp_port = base, .udp_port = (uint16_t)(base + 1) };
        relay_up = pb_relay_start(&rc) == 0;
    }
    struct pb_bpf_cfg bc = { .tcp_port = pb_relay_tcp_port(), .udp_port = pb_relay_udp_port(), .self_tgid = (uint32_t)getpid(),
                             .log = atomic_load(&G.traffic_logging), .dns_via_proxy = atomic_load(&G.dns_via_proxy) };
    if (!relay_up || pb_bpf_start(&bc, on_bpf_event) != 0) {
        if (relay_up) pb_relay_stop();
        pthread_rwlock_wrlock(&G.lock);
        G.running = false;
        pthread_rwlock_unlock(&G.lock);
        return false;
    }

    pthread_mutex_lock(&G.maint_mu);
    G.maint_stop = false;
    pthread_mutex_unlock(&G.maint_mu);
    G.maint_started = pthread_create(&G.maint, NULL, maint_loop, NULL) == 0;

    pb_bpf_set_paused(atomic_load(&G.paused));
    pthread_rwlock_wrlock(&G.lock);
    int held = G.batch;                // starting always loads everything, even inside a batch
    G.batch = 0;
    sync_locked();
    G.batch = held;
    G.batch_dirty = false;
    pthread_rwlock_unlock(&G.lock);
    pb_core_log("ProxyBridge started (eBPF datapath, relay tcp:%u udp:%u)", pb_relay_tcp_port(), pb_relay_udp_port());
    return true;
}

bool ProxyBridge_Stop(void)
{
    pthread_rwlock_wrlock(&G.lock);
    bool was = G.running;
    G.running = false;
    G.nwarned = 0;
    pthread_rwlock_unlock(&G.lock);
    if (!was) return true;

    if (G.maint_started) {
        pthread_mutex_lock(&G.maint_mu);
        G.maint_stop = true;
        pthread_cond_signal(&G.maint_cv);
        pthread_mutex_unlock(&G.maint_mu);
        pthread_join(G.maint, NULL);
        G.maint_started = false;
    }
    pb_bpf_detach();                   // no new flows get redirected
    pb_relay_stop();                   // relay threads may use the maps until they are gone
    pb_bpf_stop();
    pb_core_log("ProxyBridge stopped");
    return true;
}

int ProxyBridge_TestProxy(uint32_t proxy_id, const char *host, uint16_t port, char *buf, size_t n)
{
    struct pb_proxy p;
    if (pb_core_get_proxy(proxy_id, &p) != 0) { snprintf(buf, n, "no proxy configured"); return -1; }
    return pb_relay_test_proxy(&p, host, port, buf, n);
}

uint32_t ProxyBridge_GetFlows(ProxyBridgeFlow *out, uint32_t max)
{
    if (!out || !max) return 0;
    if (max > PB_FLOWS_MAX) max = PB_FLOWS_MAX;
    struct pb_flow_info *raw = calloc(max, sizeof *raw);
    if (!raw) return 0;
    int n = pb_relay_flows(raw, (int)max);
    for (int i = 0; i < n; i++) {
        const struct pb_flow_info *f = &raw[i];
        ProxyBridgeFlow *o = &out[i];
        memset(o, 0, sizeof *o);
        o->id = f->id; o->pid = f->pid; o->proxy_id = f->proxy_id; o->age_ms = f->age_ms;
        o->sent = f->sent; o->received = f->recv; o->port = f->port; o->is_udp = f->udp; o->is_ipv6 = f->family == AF_INET6;
        memcpy(o->dest, f->addr, 16);
        char path[4096];
        if (exe_path_of_pid(f->pid, path, sizeof path)) {
            const char *base = strrchr(path, '/');
            snprintf(o->name, sizeof o->name, "%.*s", (int)sizeof o->name - 1, base ? base + 1 : path);
        } else {
            snprintf(o->name, sizeof o->name, "pid %u", f->pid);
        }
        if (f->family == AF_INET) {
            uint32_t ip = ((uint32_t)f->addr[12] << 24) | ((uint32_t)f->addr[13] << 16) | ((uint32_t)f->addr[14] << 8) | f->addr[15];
            char names[PB_DNS_MAX_NAMES][256];
            int k = pb_dns_lookup(ip, names, PB_DNS_MAX_NAMES);
            if (k > 0) snprintf(o->host, sizeof o->host, "%s", names[k - 1]);
            else inet_ntop(AF_INET, f->addr + 12, o->host, sizeof o->host);
        } else {
            inet_ntop(AF_INET6, f->addr, o->host, sizeof o->host);
        }
    }
    free(raw);
    return (uint32_t)n;
}

int ProxyBridge_TestProxyEx(uint32_t proxy_id, const char *host, uint16_t port, ProxyTestLogCallback cb, void *user)
{
    struct pb_proxy p;
    if (pb_core_get_proxy(proxy_id, &p) != 0) {
        if (cb) cb("Result: FAILED - no proxy configured", user);
        return -1;
    }
    return pb_relay_check_proxy(&p, host, port, cb, user);
}

int ProxyBridge_TestConnection(const char *host, uint16_t port, char *buf, size_t n)
{
    return ProxyBridge_TestProxy(0, host, port, buf, n);
}
