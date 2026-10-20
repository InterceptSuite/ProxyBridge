#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "pb_bpf.h"
#include "proxybridge.skel.h"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif

#define MAX_KNOWN_EXES 16384
#define MAX_EXEMPT 64

struct exe_ent { uint32_t dev; uint64_t ino; char *path; };

static struct {
    pthread_mutex_t lock;
    struct proxybridge_bpf *skel;
    int linkfds[16], nlinks;
    struct ring_buffer *rb;
    pthread_t evt_thread;
    bool evt_started, running;
    int stop_fd;
    pb_event_cb cb;
    struct exe_ent *exes; size_t nexes;
    struct pb_bclass *cls; size_t ncls;
    struct pb_brule *br; size_t nbr;
} G = { .lock = PTHREAD_MUTEX_INITIALIZER, .stop_fd = -1 };

#define MAPFD(name) bpf_map__fd(G.skel->maps.name)

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    if (lvl == LIBBPF_DEBUG) return 0;
    char buf[1024];
    vsnprintf(buf, sizeof buf, fmt, ap);
    size_t n = strlen(buf);
    while (n && buf[n - 1] == '\n') buf[--n] = 0;
    if (n) pb_core_log("libbpf: %s", buf);
    return 0;
}

static int open_cgroup_root(void)
{
    static const char *const cands[] = { "/sys/fs/cgroup", "/sys/fs/cgroup/unified" };
    for (size_t i = 0; i < sizeof cands / sizeof *cands; i++) {
        struct statfs sf;
        if (statfs(cands[i], &sf) == 0 && (unsigned long)sf.f_type == CGROUP2_SUPER_MAGIC)
            return open(cands[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    return -1;
}

// ALLOW_MULTI lets us coexist with other sock_addr programs on the root cgroup.
static bool attach(struct bpf_program *prog, enum bpf_attach_type type, int cgfd, bool optional)
{
    if (!bpf_program__autoload(prog)) return true;
    LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = BPF_F_ALLOW_MULTI);
    int lfd = bpf_link_create(bpf_program__fd(prog), cgfd, type, &opts);
    if (lfd < 0 && errno == EINVAL) lfd = bpf_link_create(bpf_program__fd(prog), cgfd, type, NULL);
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
    while (G.nlinks) close(G.linkfds[--G.nlinks]);
}

static int on_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len >= sizeof(struct pb_event) && G.cb) G.cb(data);
    return 0;
}

static void *evt_loop(void *arg)
{
    (void)arg;
    struct pollfd p[2] = { { ring_buffer__epoll_fd(G.rb), POLLIN, 0 }, { G.stop_fd, POLLIN, 0 } };
    while (poll(p, 2, -1) >= 0 || errno == EINTR) {
        if (p[1].revents) break;
        if (p[0].revents) ring_buffer__consume(G.rb);
    }
    return NULL;
}

static uint64_t netns_cookie(void)
{
    uint64_t cookie = 0;
    socklen_t len = sizeof cookie;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd >= 0) {
        if (getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, &cookie, &len) != 0) cookie = 0;
        close(fd);
    }
    return cookie;
}

static bool attach_all(int cgfd)
{
#define ATTACH(prog, type, optional) attach(G.skel->progs.prog, type, cgfd, optional)
    return ATTACH(pb_connect4, BPF_CGROUP_INET4_CONNECT, false) &&
           ATTACH(pb_connect6, BPF_CGROUP_INET6_CONNECT, true) &&
           ATTACH(pb_sendmsg4, BPF_CGROUP_UDP4_SENDMSG, false) &&
           ATTACH(pb_sendmsg6, BPF_CGROUP_UDP6_SENDMSG, true) &&
           ATTACH(pb_recvmsg4, BPF_CGROUP_UDP4_RECVMSG, false) &&
           ATTACH(pb_recvmsg6, BPF_CGROUP_UDP6_RECVMSG, true) &&
           ATTACH(pb_getpeername4, BPF_CGROUP_INET4_GETPEERNAME, true) &&
           ATTACH(pb_getpeername6, BPF_CGROUP_INET6_GETPEERNAME, true) &&
           ATTACH(pb_sockops, BPF_CGROUP_SOCK_OPS, false);
#undef ATTACH
}

// getpeername hooks need a newer kernel than the rest; load without them if the first attempt fails.
static int load_skeleton(void)
{
    G.skel = proxybridge_bpf__open();
    if (!G.skel) return -errno;
    int err = proxybridge_bpf__load(G.skel);
    if (!err) return 0;
    proxybridge_bpf__destroy(G.skel);
    G.skel = proxybridge_bpf__open();
    if (!G.skel) return -errno;
    bpf_program__set_autoload(G.skel->progs.pb_getpeername4, false);
    bpf_program__set_autoload(G.skel->progs.pb_getpeername6, false);
    return proxybridge_bpf__load(G.skel);
}

static void free_tables(void)
{
    for (size_t i = 0; i < G.nexes; i++) free(G.exes[i].path);
    free(G.exes); G.exes = NULL; G.nexes = 0;
    free(G.cls); G.cls = NULL; G.ncls = 0;
    free(G.br); G.br = NULL; G.nbr = 0;
}

int pb_bpf_start(const struct pb_bpf_cfg *cfg, pb_event_cb cb)
{
    pthread_mutex_lock(&G.lock);
    if (G.running) { pthread_mutex_unlock(&G.lock); return 0; }
    int rc = -1, cgfd = -1;

    if (geteuid() != 0) { pb_core_log("ProxyBridge needs root (CAP_BPF/CAP_SYS_ADMIN) to load its eBPF programs"); goto out; }
    libbpf_set_print(libbpf_print);
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    cgfd = open_cgroup_root();
    if (cgfd < 0) { pb_core_log("cgroup v2 is not mounted (need a unified hierarchy at /sys/fs/cgroup)"); goto out; }

    int err = load_skeleton();
    if (err) {
        pb_core_log("loading the BPF programs failed (needs a kernel >= 5.11 with BTF and cgroup sock_addr support): %s", strerror(-err));
        goto out;
    }

    volatile struct pb_cfg *c = &G.skel->bss->cfg;
    c->tcp_port = cfg->tcp_port;
    c->udp_port = cfg->udp_port;
    c->self_tgid = cfg->self_tgid;
    c->log = cfg->log;
    c->dns_via_proxy = cfg->dns_via_proxy;
    c->netns = netns_cookie();
    if (!c->netns) pb_core_log("kernel has no SO_NETNS_COOKIE: connections from other network namespaces are not isolated");

    if (!attach_all(cgfd)) goto out;

    G.cb = cb;
    G.stop_fd = eventfd(0, EFD_CLOEXEC);
    G.rb = ring_buffer__new(MAPFD(events), on_event, NULL, NULL);
    if (G.stop_fd < 0 || !G.rb || pthread_create(&G.evt_thread, NULL, evt_loop, NULL) != 0) {
        pb_core_log("cannot start the event reader");
        goto out;
    }
    G.evt_started = G.running = true;
    rc = 0;
out:
    if (cgfd >= 0) close(cgfd);
    if (rc != 0) {
        detach_all();
        if (G.rb) { ring_buffer__free(G.rb); G.rb = NULL; }
        if (G.stop_fd >= 0) { close(G.stop_fd); G.stop_fd = -1; }
        if (G.skel) { proxybridge_bpf__destroy(G.skel); G.skel = NULL; }
    }
    pthread_mutex_unlock(&G.lock);
    return rc;
}

void pb_bpf_detach(void)
{
    pthread_mutex_lock(&G.lock);
    if (G.evt_started) {
        eventfd_write(G.stop_fd, 1);
        pthread_mutex_unlock(&G.lock);
        pthread_join(G.evt_thread, NULL);
        pthread_mutex_lock(&G.lock);
        G.evt_started = false;
    }
    detach_all();
    pthread_mutex_unlock(&G.lock);
}

void pb_bpf_stop(void)
{
    pb_bpf_detach();
    pthread_mutex_lock(&G.lock);
    if (G.rb) { ring_buffer__free(G.rb); G.rb = NULL; }
    if (G.stop_fd >= 0) { close(G.stop_fd); G.stop_fd = -1; }
    if (G.skel) { proxybridge_bpf__destroy(G.skel); G.skel = NULL; }
    free_tables();
    G.running = false;
    pthread_mutex_unlock(&G.lock);
}

void pb_bpf_set_paused(bool paused)
{
    pthread_mutex_lock(&G.lock);
    if (G.skel) G.skel->bss->cfg.paused = paused;
    pthread_mutex_unlock(&G.lock);
}

void pb_bpf_set_flags(bool log, bool dns_via_proxy)
{
    pthread_mutex_lock(&G.lock);
    if (G.skel) {
        G.skel->bss->cfg.log = log;
        G.skel->bss->cfg.dns_via_proxy = dns_via_proxy;
    }
    pthread_mutex_unlock(&G.lock);
}

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
    if (e) return e;
    if (G.nexes >= MAX_KNOWN_EXES) return NULL;
    if (!G.exes && !(G.exes = calloc(MAX_KNOWN_EXES, sizeof *G.exes))) return NULL;
    char *copy = strdup(path ? path : "");
    if (!copy) return NULL;
    e = &G.exes[G.nexes++];
    e->dev = dev; e->ino = ino; e->path = copy;
    return e;
}

static void strip_deleted(char *p)
{
    static const char suffix[] = " (deleted)";
    size_t n = strlen(p), s = sizeof suffix - 1;
    if (n > s && !strcmp(p + n - s, suffix)) p[n - s] = 0;
}

static void scan_proc(void)
{
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        char link[300], path[4096];
        struct stat st;
        snprintf(link, sizeof link, "/proc/%.200s/exe", de->d_name);
        if (stat(link, &st) != 0) continue;
        ssize_t n = readlink(link, path, sizeof path - 1);
        if (n <= 0) continue;
        path[n] = 0;
        strip_deleted(path);
        exe_add(kernel_dev(st.st_dev), st.st_ino, path);
    }
    closedir(d);
}

static void compile_rule(const struct pb_rule_view *v, struct pb_brule *b)
{
    const struct pb_rule *r = v->rule;
    memset(b, 0, sizeof *b);
    b->action = (uint8_t)v->action;
    b->proxy_id = v->action == RULE_ACTION_PROXY ? v->proxy_id : 0;
    b->proto_mask = r->protocol == RULE_PROTOCOL_TCP ? 1 : r->protocol == RULE_PROTOCOL_UDP ? 2 : 3;
    if (v->action == RULE_ACTION_PROXY && v->udp_direct) b->flags |= PB_RF_UDP_DIRECT;
    if (v->action == RULE_ACTION_PROXY && v->localhost) b->flags |= PB_RF_LOCALHOST;

    if (r->any_port) b->flags |= PB_RF_ANY_PORT;
    for (int i = 0; i < r->nports; i++) {
        if (b->n_port < PB_BPF_MAX_PORT) { b->port[b->n_port].lo = r->ports[i].lo; b->port[b->n_port].hi = r->ports[i].hi; b->n_port++; }
        else b->flags |= PB_RF_PORT_COMPLEX;
    }
    if (r->any_host) { b->flags |= PB_RF_ANY_HOST; return; }
    if (r->ndomains) b->flags |= PB_RF_DOMAINS;
    for (int i = 0; i < r->nhosts; i++) {
        const struct pb_host_pat *h = &r->hosts[i];
        if (h->kind == PB_HOST_V4_RANGE && b->n_v4 < PB_BPF_MAX_V4) { b->v4[b->n_v4].lo = h->lo4; b->v4[b->n_v4].hi = h->hi4; b->n_v4++; }
        else if (h->kind == PB_HOST_V6_RANGE) b->flags |= PB_RF_HAS_V6;
        else b->flags |= PB_RF_HOST_COMPLEX;
    }
}

// A catch-all rule shadows every later one.
static bool is_catchall(const struct pb_brule *b)
{
    return (b->flags & PB_RF_ANY_HOST) && (b->flags & PB_RF_ANY_PORT) && b->proto_mask == 3;
}

static void class_for(const struct pb_rule_view *v, const struct pb_brule *br, size_t n, const char *path, struct pb_bclass *out)
{
    memset(out, 0, sizeof *out);
    for (size_t i = 0; i < n; i++) {
        if (!v[i].rule->enabled || !pb_rule_match_process(v[i].rule, path)) continue;
        if (v[i].wants_names) out->tap = 1;
        if (out->n >= PB_RULES_PER_CLASS) {
            memset(out->rule, 0, sizeof out->rule);
            out->n = PB_CLASS_DECIDE;
            out->tap = 1;
            return;
        }
        out->rule[out->n++] = (uint32_t)i;
        if (is_catchall(&br[i])) return;
    }
}

static int class_intern(const struct pb_bclass *c)
{
    for (size_t i = 0; i < G.ncls; i++)
        if (!memcmp(&G.cls[i], c, sizeof *c)) return (int)i;
    if (G.ncls >= PB_MAX_CLASSES) return -1;
    G.cls[G.ncls] = *c;
    return (int)G.ncls++;
}

static void write_class(uint32_t id)
{
    bpf_map_update_elem(MAPFD(classes), &id, &G.cls[id], BPF_ANY);
}

static void install_exe(const struct exe_ent *e, const struct pb_rule_view *v, size_t n)
{
    struct pb_bclass c;
    class_for(v, G.br, n, e->path, &c);
    struct pb_exe_key key = { .dev = e->dev, .ino = e->ino };
    int id = class_intern(&c);
    if (id < 0) { bpf_map_delete_elem(MAPFD(exe2class), &key); return; }
    uint32_t cid = (uint32_t)id;
    write_class((uint32_t)id);
    bpf_map_update_elem(MAPFD(exe2class), &key, &cid, BPF_ANY);
}

static size_t installed_keys(struct pb_exe_key **out)
{
    size_t n = 0, cap = 0;
    struct pb_exe_key *keys = NULL, cur, next;
    int fd = MAPFD(exe2class), rc = bpf_map_get_next_key(fd, NULL, &next);
    while (rc == 0) {
        if (n == cap) {
            struct pb_exe_key *grown = realloc(keys, (cap ? cap * 2 : 256) * sizeof *keys);
            if (!grown) break;
            keys = grown; cap = cap ? cap * 2 : 256;
        }
        keys[n++] = cur = next;
        rc = bpf_map_get_next_key(fd, &cur, &next);
    }
    *out = keys;
    return n;
}

int pb_bpf_sync(const struct pb_rule_view *v, size_t n)
{
    if (n > PB_MAX_RULES) { pb_core_log("too many rules (max %d)", PB_MAX_RULES); return -1; }
    pthread_mutex_lock(&G.lock);
    if (!G.skel) { pthread_mutex_unlock(&G.lock); return -1; }

    struct pb_brule *br = calloc(n ? n : 1, sizeof *br);
    if (!G.cls) G.cls = calloc(PB_MAX_CLASSES, sizeof *G.cls);
    if (!br || !G.cls) { free(br); pthread_mutex_unlock(&G.lock); return -1; }
    free(G.br);
    G.br = br; G.nbr = n;

    bool active = false, domains = false;
    uint32_t localhost = 0;
    for (size_t i = 0; i < n; i++) {
        compile_rule(&v[i], &br[i]);
        uint32_t k = (uint32_t)i;
        bpf_map_update_elem(MAPFD(brules), &k, &br[i], BPF_ANY);
        if (v[i].rule->enabled) {
            active = true;
            domains |= v[i].wants_names;
            localhost += v[i].localhost;
        }
    }

    scan_proc();
    memset(G.cls, 0, PB_MAX_CLASSES * sizeof *G.cls);
    G.ncls = 1;                                           // class 0: no rule applies
    struct pb_exe_key *stale;
    size_t nstale = installed_keys(&stale);
    for (size_t i = 0; i < G.nexes; i++) install_exe(&G.exes[i], v, n);
    write_class(0);
    for (size_t i = 0; i < nstale; i++)
        if (!exe_find(stale[i].dev, stale[i].ino)) bpf_map_delete_elem(MAPFD(exe2class), &stale[i]);
    free(stale);

    G.skel->bss->cfg.dns_tap = domains;
    G.skel->bss->cfg.n_localhost = localhost;
    G.skel->bss->cfg.enabled = active;
    pthread_mutex_unlock(&G.lock);
    return 0;
}

void pb_bpf_learn(const struct pb_orig *o, const char *exe_path, const struct pb_rule_view *v, size_t n)
{
    if (!o->exe_ino) return;
    pthread_mutex_lock(&G.lock);
    if (G.skel && G.cls && n == G.nbr && !exe_find(o->exe_dev, o->exe_ino)) {
        struct exe_ent *e = exe_add(o->exe_dev, o->exe_ino, exe_path);
        if (e) install_exe(e, v, n);
    }
    pthread_mutex_unlock(&G.lock);
}

void pb_bpf_set_exempt(const uint32_t *tgids, size_t n)
{
    pthread_mutex_lock(&G.lock);
    if (!G.skel) { pthread_mutex_unlock(&G.lock); return; }
    int fd = MAPFD(exempt);
    uint32_t cur, next, stale[MAX_EXEMPT];
    size_t nstale = 0;
    for (int rc = bpf_map_get_next_key(fd, NULL, &next); rc == 0 && nstale < MAX_EXEMPT; rc = bpf_map_get_next_key(fd, &cur, &next)) {
        cur = next;
        bool keep = false;
        for (size_t i = 0; i < n && !keep; i++) keep = tgids[i] == cur;
        if (!keep) stale[nstale++] = cur;
    }
    for (size_t i = 0; i < nstale; i++) bpf_map_delete_elem(fd, &stale[i]);
    uint8_t one = 1;
    size_t count = n < MAX_EXEMPT ? n : MAX_EXEMPT;
    for (size_t i = 0; i < count; i++) bpf_map_update_elem(fd, &tgids[i], &one, BPF_ANY);
    G.skel->bss->cfg.n_exempt = (uint32_t)count;
    pthread_mutex_unlock(&G.lock);
}

bool pb_bpf_exe_path(uint32_t dev, uint64_t ino, char *out, size_t n)
{
    bool found = false;
    pthread_mutex_lock(&G.lock);
    struct exe_ent *e = ino ? exe_find(dev, ino) : NULL;
    if (e && e->path) { snprintf(out, n, "%s", e->path); found = true; }
    pthread_mutex_unlock(&G.lock);
    return found;
}

void pb_bpf_dom_set(uint32_t rule_idx, uint32_t ip_host)
{
    if (!G.skel) return;
    struct pb_dom_key k = { .rule = rule_idx, .ip = ip_host };
    uint8_t one = 1;
    bpf_map_update_elem(MAPFD(dom_hit), &k, &one, BPF_ANY);
}

void pb_bpf_dom_clear(void)
{
    if (!G.skel) return;
    int fd = MAPFD(dom_hit);
    struct pb_dom_key k, next;
    for (int rc = bpf_map_get_next_key(fd, NULL, &next); rc == 0;) {
        k = next;
        rc = bpf_map_get_next_key(fd, &k, &next);
        bpf_map_delete_elem(fd, &k);
    }
}

int pb_bpf_take_tcp_orig(uint32_t client_ip_be, uint16_t client_port, struct pb_orig *out)
{
    if (!G.skel) return -1;
    struct pb_port_key key = { .ip = client_ip_be, .port = client_port };
    int fd = MAPFD(by_port);
    if (bpf_map_lookup_elem(fd, &key, out) != 0) return -1;
    bpf_map_delete_elem(fd, &key);
    return 0;
}

int pb_bpf_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out)
{
    return G.skel && bpf_map_lookup_elem(MAPFD(flows), &flow_ip_be, out) == 0 ? 0 : -1;
}
