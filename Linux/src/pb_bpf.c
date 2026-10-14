#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "pb_bpf.h"
#include "proxybridge.skel.h"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

#define MAX_KNOWN_EXES 16384

struct exe_ent { uint32_t dev; uint64_t ino; char path[240]; };

static struct {
    pthread_mutex_t lock;
    struct proxybridge_bpf *skel;
    int linkfds[16];
    int nlinks;
    struct ring_buffer *rb;
    pthread_t evt_thread;
    bool evt_started;
    volatile bool stop;
    pb_event_cb cb;
    bool running;

    struct exe_ent *exes; size_t nexes;                       // executables we know about (kernel-side keys)
    struct pb_bclass *cls; size_t ncls;                       // current class table (index = class id)
    bool have_rules;
} G = { .lock = PTHREAD_MUTEX_INITIALIZER };

// ---- logging bridge -------------------------------------------------------------------------------------------------
static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG) return 0;
    char buf[1024];
    vsnprintf(buf, sizeof buf, fmt, ap);
    size_t n = strlen(buf);
    while (n && (buf[n - 1] == '\n')) buf[--n] = 0;
    if (n) pb_core_log("libbpf: %s", buf);
    return 0;
}

// ---- cgroup2 root -----------------------------------------------------------------------------------------------------
static int open_cgroup_root(void)
{
    static const char *cands[] = { "/sys/fs/cgroup", "/sys/fs/cgroup/unified", NULL };
    for (int i = 0; cands[i]; i++) {
        struct statfs sf;
        if (statfs(cands[i], &sf) == 0 && (unsigned long)sf.f_type == CGROUP2_SUPER_MAGIC)
            return open(cands[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    return -1;
}

// ---- cfg ---------------------------------------------------------------------------------------------------------------
static void cfg_set(uint32_t slot, uint32_t val)
{
    bpf_map_update_elem(bpf_map__fd(G.skel->maps.cfg), &slot, &val, BPF_ANY);
}

// ---- attach ------------------------------------------------------------------------------------------------------------
static bool attach(struct bpf_program *prog, enum bpf_attach_type type, int cgfd, bool optional)
{
    if (!bpf_program__autoload(prog)) return true;
    // ALLOW_MULTI lets us coexist with other sock_addr programs on the root cgroup; fall back to a plain attach
    LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = BPF_F_ALLOW_MULTI);
    int lfd = bpf_link_create(bpf_program__fd(prog), cgfd, type, &opts);
    if (lfd < 0 && errno == EINVAL)
        lfd = bpf_link_create(bpf_program__fd(prog), cgfd, type, NULL);
    if (lfd < 0) {
        if (optional) return true;
        pb_core_log("attach %s failed: %s", bpf_program__name(prog), strerror(errno));
        return false;
    }
    G.linkfds[G.nlinks++] = lfd;
    return true;
}

static void detach_all(void)
{
    for (int i = 0; i < G.nlinks; i++) close(G.linkfds[i]);
    G.nlinks = 0;
}

// ---- events ------------------------------------------------------------------------------------------------------------
static int on_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len >= sizeof(struct pb_event) && G.cb) G.cb(data);
    return 0;
}

static void *evt_loop(void *arg)
{
    (void)arg;
    while (!G.stop) ring_buffer__poll(G.rb, 200);
    return NULL;
}

// ---- start / stop -----------------------------------------------------------------------------------------------------
int pb_bpf_start(const struct pb_bpf_cfg *cfg, pb_event_cb cb)
{
    pthread_mutex_lock(&G.lock);
    if (G.running) { pthread_mutex_unlock(&G.lock); return 0; }
    int rc = -1, cgfd = -1;

    if (geteuid() != 0) { pb_core_log("ProxyBridge needs root (CAP_BPF/CAP_SYS_ADMIN) to load its eBPF programs"); goto out; }
    libbpf_set_print(libbpf_print);
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);                            // pre-5.11 kernels charge maps to memlock

    cgfd = open_cgroup_root();
    if (cgfd < 0) { pb_core_log("cgroup v2 is not mounted (need a unified hierarchy at /sys/fs/cgroup)"); goto out; }

    G.skel = proxybridge_bpf__open();
    if (!G.skel) { pb_core_log("cannot open BPF object: %s", strerror(errno)); goto out; }
    int err = proxybridge_bpf__load(G.skel);
    if (err) {
        // getpeername hooks need kernel >= 5.8; retry without them
        proxybridge_bpf__destroy(G.skel);
        G.skel = proxybridge_bpf__open();
        if (G.skel) {
            bpf_program__set_autoload(G.skel->progs.pb_getpeername4, false);
            bpf_program__set_autoload(G.skel->progs.pb_getpeername6, false);
            err = proxybridge_bpf__load(G.skel);
        }
        if (err || !G.skel) { pb_core_log("loading the BPF programs failed (kernel needs BTF and cgroup sock_addr support, >= 5.11): %s", strerror(-err ? -err : errno)); goto out; }
    }

    {   // sockets of other network namespaces (containers) must not be redirected to our loopback relay
        int ns = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        uint64_t cookie = 0; socklen_t cl = sizeof cookie;
        if (ns >= 0 && getsockopt(ns, SOL_SOCKET, 71 /* SO_NETNS_COOKIE */, &cookie, &cl) == 0 && cookie) {
            cfg_set(PB_CFG_NETNS_LO, (uint32_t)cookie);
            cfg_set(PB_CFG_NETNS_HI, (uint32_t)(cookie >> 32));
        } else pb_core_log("kernel has no SO_NETNS_COOKIE: connections from other network namespaces are not isolated");
        if (ns >= 0) close(ns);
    }
    cfg_set(PB_CFG_SELF_TGID, cfg->self_tgid);
    cfg_set(PB_CFG_TCP_PORT, cfg->tcp_port);
    cfg_set(PB_CFG_UDP_PORT, cfg->udp_port);
    cfg_set(PB_CFG_LOG, cfg->log);
    cfg_set(PB_CFG_DNS_VIA_PROXY, cfg->dns_via_proxy);
    cfg_set(PB_CFG_ENABLED, 0);

    bool ok = attach(G.skel->progs.pb_connect4, BPF_CGROUP_INET4_CONNECT, cgfd, false) &&
              attach(G.skel->progs.pb_connect6, BPF_CGROUP_INET6_CONNECT, cgfd, true) &&
              attach(G.skel->progs.pb_sendmsg4, BPF_CGROUP_UDP4_SENDMSG, cgfd, false) &&
              attach(G.skel->progs.pb_sendmsg6, BPF_CGROUP_UDP6_SENDMSG, cgfd, true) &&
              attach(G.skel->progs.pb_recvmsg4, BPF_CGROUP_UDP4_RECVMSG, cgfd, false) &&
              attach(G.skel->progs.pb_recvmsg6, BPF_CGROUP_UDP6_RECVMSG, cgfd, true) &&
              attach(G.skel->progs.pb_getpeername4, BPF_CGROUP_INET4_GETPEERNAME, cgfd, true) &&
              attach(G.skel->progs.pb_getpeername6, BPF_CGROUP_INET6_GETPEERNAME, cgfd, true) &&
              attach(G.skel->progs.pb_sockops, BPF_CGROUP_SOCK_OPS, cgfd, false);
    if (!ok) goto out;

    G.cb = cb;
    G.stop = false;
    G.rb = ring_buffer__new(bpf_map__fd(G.skel->maps.events), on_event, NULL, NULL);
    if (!G.rb) { pb_core_log("cannot create event ring buffer"); goto out; }
    if (pthread_create(&G.evt_thread, NULL, evt_loop, NULL) != 0) { pb_core_log("cannot start event thread"); goto out; }
    G.evt_started = true;
    G.running = true;
    rc = 0;
out:
    if (cgfd >= 0) close(cgfd);
    if (rc != 0) {
        detach_all();
        if (G.rb) { ring_buffer__free(G.rb); G.rb = NULL; }
        if (G.skel) { proxybridge_bpf__destroy(G.skel); G.skel = NULL; }
    }
    pthread_mutex_unlock(&G.lock);
    return rc;
}

void pb_bpf_stop(void)
{
    pthread_mutex_lock(&G.lock);
    if (G.skel) {
        G.stop = true;
        if (G.evt_started) { pthread_mutex_unlock(&G.lock); pthread_join(G.evt_thread, NULL); pthread_mutex_lock(&G.lock); G.evt_started = false; }
        detach_all();
        if (G.rb) { ring_buffer__free(G.rb); G.rb = NULL; }
        proxybridge_bpf__destroy(G.skel);
        G.skel = NULL;
    }
    free(G.exes); G.exes = NULL; G.nexes = 0;
    free(G.cls); G.cls = NULL; G.ncls = 0;
    G.running = false;
    pthread_mutex_unlock(&G.lock);
}

bool pb_bpf_running(void) { return G.running; }

void pb_bpf_set_flags(bool log, bool dns_via_proxy)
{
    pthread_mutex_lock(&G.lock);
    if (G.skel) { cfg_set(PB_CFG_LOG, log); cfg_set(PB_CFG_DNS_VIA_PROXY, dns_via_proxy); }
    pthread_mutex_unlock(&G.lock);
}

// ---- executables --------------------------------------------------------------------------------------------------------
static uint32_t kernel_dev(dev_t d) { return (major(d) << 20) | minor(d); }

static struct exe_ent *exe_find(uint32_t dev, uint64_t ino)
{
    for (size_t i = 0; i < G.nexes; i++)
        if (G.exes[i].ino == ino && G.exes[i].dev == dev) return &G.exes[i];
    return NULL;
}

static struct exe_ent *exe_add(uint32_t dev, uint64_t ino, const char *path)
{
    struct exe_ent *e = exe_find(dev, ino);
    if (e) { if (path && *path) snprintf(e->path, sizeof e->path, "%s", path); return e; }
    if (G.nexes >= MAX_KNOWN_EXES) return NULL;
    if (!G.exes) { G.exes = calloc(MAX_KNOWN_EXES, sizeof *G.exes); if (!G.exes) return NULL; }
    e = &G.exes[G.nexes++];
    e->dev = dev; e->ino = ino;
    snprintf(e->path, sizeof e->path, "%s", path ? path : "");
    return e;
}

static void strip_deleted(char *p)
{
    size_t n = strlen(p);
    static const char suf[] = " (deleted)";
    if (n > sizeof suf - 1 && !strcmp(p + n - (sizeof suf - 1), suf)) p[n - (sizeof suf - 1)] = 0;
}

static void scan_proc(void)
{
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        char lnk[300], path[240];
        snprintf(lnk, sizeof lnk, "/proc/%.200s/exe", de->d_name);
        struct stat st;
        if (stat(lnk, &st) != 0) continue;
        ssize_t n = readlink(lnk, path, sizeof path - 1);
        if (n <= 0) continue;
        path[n] = 0;
        strip_deleted(path);
        exe_add(kernel_dev(st.st_dev), st.st_ino, path);
    }
    closedir(d);
}

// ---- compilation -----------------------------------------------------------------------------------------------------------
static void compile_rule(const struct pb_rule_view *v, struct pb_brule *b)
{
    const struct pb_rule *r = v->rule;
    memset(b, 0, sizeof *b);
    b->action = (uint8_t)v->action;
    b->proxy_id = v->action == RULE_ACTION_PROXY ? v->proxy_id : 0;
    b->proto_mask = r->protocol == RULE_PROTOCOL_TCP ? 1 : r->protocol == RULE_PROTOCOL_UDP ? 2 : 3;
    if (v->action == RULE_ACTION_PROXY && v->udp_direct) b->flags |= PB_RF_UDP_DIRECT;

    if (r->any_port) b->flags |= PB_RF_ANY_PORT;
    else {
        for (int i = 0; i < r->nports; i++) {
            if (b->n_port < PB_BPF_MAX_PORT) { b->port[b->n_port].lo = r->ports[i].lo; b->port[b->n_port].hi = r->ports[i].hi; b->n_port++; }
            else b->flags |= PB_RF_PORT_COMPLEX;
        }
    }
    if (r->any_host) b->flags |= PB_RF_ANY_HOST;
    else {
        if (r->ndomains) b->flags |= PB_RF_DOMAINS;
        for (int i = 0; i < r->nhosts; i++) {
            const struct pb_host_pat *h = &r->hosts[i];
            if (h->kind == PB_HOST_V4_RANGE && b->n_v4 < PB_BPF_MAX_V4) { b->v4[b->n_v4].lo = h->lo4; b->v4[b->n_v4].hi = h->hi4; b->n_v4++; }
            else if (h->kind == PB_HOST_V6_RANGE) b->flags |= PB_RF_HAS_V6;
            else b->flags |= PB_RF_HOST_COMPLEX;           // box patterns / too many ranges: let the relay decide
        }
    }
}

// a rule that cannot be skipped by later ones: every host, every port, both protocols
static bool rule_is_catchall(const struct pb_brule *b)
{
    return (b->flags & PB_RF_ANY_HOST) && (b->flags & PB_RF_ANY_PORT) && b->proto_mask == 3;
}

static int class_for(const struct pb_rule_view *v, const struct pb_brule *br, size_t n, const char *path, struct pb_bclass *out)
{
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < n; i++) {
        if (!v[i].rule->enabled) continue;
        if (!pb_rule_match_process(v[i].rule, path)) continue;
        if (pb_rule_has_domains(v[i].rule)) out->tap = 1;
        if (out->n >= PB_RULES_PER_CLASS) { memset(out, 0, sizeof *out); out->n = PB_CLASS_DECIDE; out->tap = 1; return 0; }
        out->rule[out->n++] = (uint32_t)i;
        if (rule_is_catchall(&br[i])) break;               // nothing after a catch-all can apply
    }
    return 0;
}

static int class_intern(const struct pb_bclass *c)
{
    for (size_t i = 0; i < G.ncls; i++)
        if (!memcmp(&G.cls[i], c, sizeof *c)) return (int)i;
    if (G.ncls >= PB_MAX_CLASSES) return -1;
    G.cls[G.ncls] = *c;
    return (int)G.ncls++;
}

static void write_class_slot(uint32_t id)
{
    bpf_map_update_elem(bpf_map__fd(G.skel->maps.classes), &id, &G.cls[id], BPF_ANY);
}

int pb_bpf_sync(const struct pb_rule_view *v, size_t n)
{
    if (n > PB_MAX_RULES) { pb_core_log("too many rules (max %d)", PB_MAX_RULES); return -1; }
    pthread_mutex_lock(&G.lock);
    if (!G.skel) { pthread_mutex_unlock(&G.lock); return -1; }

    struct pb_brule *br = calloc(n ? n : 1, sizeof *br);
    if (!G.cls) G.cls = calloc(PB_MAX_CLASSES, sizeof *G.cls);
    if (!br || !G.cls) { free(br); pthread_mutex_unlock(&G.lock); return -1; }

    size_t active = 0;
    for (size_t i = 0; i < n; i++) {
        compile_rule(&v[i], &br[i]);
        uint32_t k = (uint32_t)i;
        bpf_map_update_elem(bpf_map__fd(G.skel->maps.brules), &k, &br[i], BPF_ANY);
        if (v[i].rule->enabled) active++;
    }

    scan_proc();
    G.ncls = 0;
    memset(G.cls, 0, PB_MAX_CLASSES * sizeof *G.cls);
    G.ncls = 1;                                            // class 0 = no rule applies (direct)
    int mapfd = bpf_map__fd(G.skel->maps.exe2class);

    // remember what was installed so entries for vanished binaries can be dropped
    struct pb_exe_key k = {}, next;
    struct pb_exe_key *old = NULL; size_t nold = 0, capold = 0;
    int ret = bpf_map_get_next_key(mapfd, NULL, &next);
    while (ret == 0) {
        if (nold == capold) { capold = capold ? capold * 2 : 256; old = realloc(old, capold * sizeof *old); if (!old) break; }
        old[nold++] = next;
        k = next;
        ret = bpf_map_get_next_key(mapfd, &k, &next);
    }

    for (size_t i = 0; i < G.nexes; i++) {
        struct pb_bclass c;
        class_for(v, br, n, G.exes[i].path, &c);
        int id = class_intern(&c);
        struct pb_exe_key key = { .dev = G.exes[i].dev, .ino = G.exes[i].ino };
        if (id < 0) { bpf_map_delete_elem(mapfd, &key); continue; }   // out of classes: slow path
        uint32_t cid = (uint32_t)id;
        bpf_map_update_elem(mapfd, &key, &cid, BPF_ANY);
    }
    for (size_t i = 0; i < G.ncls; i++) write_class_slot((uint32_t)i);
    for (size_t i = 0; i < nold; i++)
        if (!exe_find(old[i].dev, old[i].ino)) bpf_map_delete_elem(mapfd, &old[i]);
    free(old);
    free(br);

    bool domains = false;
    for (size_t i = 0; i < n; i++) domains |= v[i].rule->enabled && pb_rule_has_domains(v[i].rule);
    cfg_set(PB_CFG_DNS_TAP, domains ? 1 : 0);
    G.have_rules = active > 0;
    cfg_set(PB_CFG_ENABLED, G.have_rules ? 1 : 0);
    pthread_mutex_unlock(&G.lock);
    return 0;
}

void pb_bpf_learn(const struct pb_orig *o, const char *exe_path, const struct pb_rule_view *v, size_t n)
{
    if (!o->exe_ino || n > PB_MAX_RULES) return;
    pthread_mutex_lock(&G.lock);
    if (!G.skel || !G.cls) { pthread_mutex_unlock(&G.lock); return; }
    struct exe_ent *known = exe_find(o->exe_dev, o->exe_ino);
    struct exe_ent *e = known ? NULL : exe_add(o->exe_dev, o->exe_ino, exe_path);   // already classified: nothing to learn
    if (e) {
        struct pb_brule *br = calloc(n ? n : 1, sizeof *br);
        if (br) {
            for (size_t i = 0; i < n; i++) compile_rule(&v[i], &br[i]);
            struct pb_bclass c;
            class_for(v, br, n, e->path, &c);
            int id = class_intern(&c);
            if (id >= 0) {
                write_class_slot((uint32_t)id);
                struct pb_exe_key key = { .dev = e->dev, .ino = e->ino };
                uint32_t cid = (uint32_t)id;
                bpf_map_update_elem(bpf_map__fd(G.skel->maps.exe2class), &key, &cid, BPF_ANY);
            }
            free(br);
        }
    }
    pthread_mutex_unlock(&G.lock);
}

// ---- lookups for the relay -------------------------------------------------------------------------------------------------
int pb_bpf_take_tcp_orig(uint16_t client_port, struct pb_orig *out)
{
    uint32_t key = client_port;
    int fd = G.skel ? bpf_map__fd(G.skel->maps.by_port) : -1;
    if (fd < 0 || bpf_map_lookup_elem(fd, &key, out) != 0) return -1;
    bpf_map_delete_elem(fd, &key);
    return 0;
}

int pb_bpf_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out)
{
    int fd = G.skel ? bpf_map__fd(G.skel->maps.flows) : -1;
    return (fd >= 0 && bpf_map_lookup_elem(fd, &flow_ip_be, out) == 0) ? 0 : -1;
}

// ---- domain rules ------------------------------------------------------------------------------------------------------------
void pb_bpf_dom_set(uint32_t rule_idx, uint32_t ip_host)
{
    if (!G.skel) return;
    struct pb_dom_key k = { .rule = rule_idx, .ip = ip_host };
    uint8_t one = 1;
    bpf_map_update_elem(bpf_map__fd(G.skel->maps.dom_hit), &k, &one, BPF_ANY);
}

void pb_bpf_dom_clear(void)
{
    if (!G.skel) return;
    int fd = bpf_map__fd(G.skel->maps.dom_hit);
    struct pb_dom_key k, next;
    int rc = bpf_map_get_next_key(fd, NULL, &next);
    while (rc == 0) {
        k = next;
        rc = bpf_map_get_next_key(fd, &k, &next);
        bpf_map_delete_elem(fd, &k);
    }
}

void pb_bpf_set_dns_tap(bool on)
{
    pthread_mutex_lock(&G.lock);
    if (G.skel) cfg_set(PB_CFG_DNS_TAP, on ? 1 : 0);
    pthread_mutex_unlock(&G.lock);
}
