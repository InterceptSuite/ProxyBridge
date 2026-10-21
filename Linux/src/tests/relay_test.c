// Root-free loopback test harness for pb_relay.c: fake pb_core_* services, in-process SOCKS5 / HTTP proxies and echo servers.
// The kernel redirect is simulated by registering original destinations keyed by the client's (ip,port) or by flow address.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sched.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "../pb_internal.h"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
#define TCP_SLOTS 65536
static struct tcp_slot { uint64_t key; struct pb_orig o; uint8_t state; } g_tcp[TCP_SLOTS];   // 0 free, 1 used, 2 tombstone
static inline uint64_t tcp_key(uint32_t ip_be, uint16_t port) { return (uint64_t)ip_be << 16 | port; }
static inline uint32_t tcp_hash(uint64_t k) { return (uint32_t)((k * 0x9E3779B97F4A7C15ull) >> 48); }
static struct { uint32_t ip_be; struct pb_orig o; bool used; } g_flows[64];
static struct pb_proxy g_px[16];
static bool g_px_used[16];
static uint32_t g_default_px = 1;
static struct pb_decision g_decision = { PB_ACT_DIRECT, 0 };
static atomic_int g_ev, g_ev_proxy, g_ev_direct, g_ev_block, g_decide_calls;
static atomic_int g_loop_pid;             // tests: non-zero = every flow counts as made by the proxy process itself
static char g_log[64][512];
static int g_log_n;

int pb_core_take_tcp_orig(uint32_t ip_be, uint16_t port, struct pb_orig *out)
{
    uint64_t k = tcp_key(ip_be, port);
    int ok = 0;
    pthread_mutex_lock(&g_mu);
    for (uint32_t i = tcp_hash(k), n = 0; n < TCP_SLOTS && g_tcp[i].state; i = (i + 1) % TCP_SLOTS, n++) {
        if (g_tcp[i].state == 1 && g_tcp[i].key == k) {
            *out = g_tcp[i].o;
            g_tcp[i].state = g_tcp[(i + 1) % TCP_SLOTS].state ? 2 : 0;
            ok = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return ok ? 0 : -1;
}
int pb_core_get_udp_flow(uint32_t ip, struct pb_orig *out)
{
    int ok = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < 64; i++)
        if (g_flows[i].used && g_flows[i].ip_be == ip) { *out = g_flows[i].o; ok = 1; break; }
    pthread_mutex_unlock(&g_mu);
    return ok ? 0 : -1;
}
void pb_core_decide(const struct pb_orig *o, struct pb_decision *out)
{
    (void)o;
    atomic_fetch_add(&g_decide_calls, 1);
    pthread_mutex_lock(&g_mu);
    *out = g_decision;
    pthread_mutex_unlock(&g_mu);
}
int pb_core_get_proxy(uint32_t id, struct pb_proxy *out)
{
    if (id == 0) id = g_default_px;
    if (id >= 16 || !g_px_used[id]) return -1;
    *out = g_px[id];
    return 0;
}
void pb_core_log(const char *fmt, ...)
{
    char b[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&g_mu);
    snprintf(g_log[g_log_n++ % 64], 512, "%s", b);
    pthread_mutex_unlock(&g_mu);
    if (getenv("VERBOSE")) fprintf(stderr, "  [log] %s\n", b);
}
void pb_core_flow_event(const struct pb_orig *o, int action)
{
    (void)o;
    atomic_fetch_add(&g_ev, 1);
    if (action == PB_ACT_PROXY) atomic_fetch_add(&g_ev_proxy, 1);
    else if (action == PB_ACT_DIRECT) atomic_fetch_add(&g_ev_direct, 1);
    else atomic_fetch_add(&g_ev_block, 1);
}

struct obs { int64_t t0, t1; size_t len; uint32_t h; };
static struct obs g_obs[64];
static atomic_int g_obs_n, g_obs_sleep;
static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static uint32_t fnv(const uint8_t *p, size_t n)
{
    uint32_t h = 2166136261u;
    while (n--) { h ^= *p++; h *= 16777619u; }
    return h;
}
static atomic_int g_sender_bad;
int pb_core_udp_sender_ok(const struct pb_orig *o, uint16_t client_port)
{
    (void)o; (void)client_port;
    return !atomic_load(&g_sender_bad);
}
int pb_core_is_proxy_process(uint32_t pid, uint32_t proxy_id)
{
    (void)pid; (void)proxy_id;
    return atomic_load(&g_loop_pid) != 0;
}

int pb_core_name_for(const struct pb_orig *o, char *out, size_t n)
{
    (void)o; (void)out; (void)n;
    return -1;
}

void pb_core_dns_observe(const uint8_t *m, size_t len)
{
    int64_t t0 = mono_ms();
    int sl = atomic_load(&g_obs_sleep);
    if (sl) usleep((useconds_t)sl * 1000);
    int i = atomic_fetch_add(&g_obs_n, 1);
    if (i < 64) g_obs[i] = (struct obs){ t0, mono_ms(), len, fnv(m, len) };
}

static bool log_has(const char *s)
{
    bool r = false;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < 64 && i < g_log_n; i++) if (strstr(g_log[i], s)) r = true;
    pthread_mutex_unlock(&g_mu);
    return r;
}
static void set_decision(struct pb_decision d)
{
    pthread_mutex_lock(&g_mu);
    g_decision = d;
    pthread_mutex_unlock(&g_mu);
}
static void log_clear(void) { pthread_mutex_lock(&g_mu); g_log_n = 0; memset(g_log, 0, sizeof g_log); pthread_mutex_unlock(&g_mu); }
static void ev_clear(void) { g_ev = g_ev_proxy = g_ev_direct = g_ev_block = 0; }

static int g_pass, g_fail;
static const char *volatile g_cur = "startup";
static void watchdog(int sig)
{
    (void)sig;
    static const char m1[] = "\nFATAL: watchdog expired while running: ";
    if (write(2, m1, sizeof m1 - 1) < 0) {}
    const char *c = g_cur;
    if (write(2, c, strlen(c)) < 0) {}
    if (write(2, "\n", 1) < 0) {}
    _exit(3);
}
static void arm_watchdog(void)
{
    const char *e = getenv("PB_TEST_WATCHDOG");
    int secs = e ? atoi(e) : 300;
    signal(SIGALRM, watchdog);
    alarm((unsigned)(secs > 0 ? secs : 300));
}
#define RUN(fn) do { const char *only_ = getenv("PB_TEST_ONLY"); if (only_ && !strstr(only_, #fn)) break; g_cur = #fn; printf("---- %s\n", #fn); fn(); } while (0)
#define CHECK(cond, ...) do { if (cond) { g_pass++; printf("PASS  "); } else { g_fail++; printf("FAIL  "); } \
                              printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while (0)

static const uint16_t TPORT = 39011, UPORT = 39012;
static atomic_int g_next_port = 20000;

static void fill_orig(struct pb_orig *o, const char *ip, uint16_t port, int proto, int action, uint32_t px)
{
    memset(o, 0, sizeof *o);
    struct in_addr a;
    inet_pton(AF_INET, ip, &a);
    memset(o->addr + 10, 0xff, 2);
    memcpy(o->addr + 12, &a, 4);
    o->port = port; o->family = AF_INET; o->proto = (uint8_t)proto; o->action = (uint8_t)action; o->proxy_id = (uint16_t)px;
}
static void set_tcp_from(uint32_t src_ip_be, uint16_t src, const char *ip, uint16_t port, int action, uint32_t px)
{
    uint64_t k = tcp_key(src_ip_be, src);
    pthread_mutex_lock(&g_mu);
    uint32_t i = tcp_hash(k);
    while (g_tcp[i].state == 1 && g_tcp[i].key != k) i = (i + 1) % TCP_SLOTS;
    g_tcp[i].key = k;
    g_tcp[i].state = 1;
    fill_orig(&g_tcp[i].o, ip, port, IPPROTO_TCP, action, px);
    pthread_mutex_unlock(&g_mu);
}
static void set_tcp(uint16_t src, const char *ip, uint16_t port, int action, uint32_t px)
{
    set_tcp_from(htonl(INADDR_LOOPBACK), src, ip, port, action, px);
}
static int g_nflows;
static void set_flow(const char *flow_ip, const char *ip, uint16_t port, int action, uint32_t px)
{
    struct in_addr f;
    inet_pton(AF_INET, flow_ip, &f);
    pthread_mutex_lock(&g_mu);
    int i;
    for (i = 0; i < g_nflows; i++) if (g_flows[i].ip_be == f.s_addr) break;
    if (i == g_nflows) g_nflows++;
    g_flows[i].used = true; g_flows[i].ip_be = f.s_addr;
    fill_orig(&g_flows[i].o, ip, port, IPPROTO_UDP, action, px);
    pthread_mutex_unlock(&g_mu);
}
static void set_proxy_host(uint32_t id, const char *host)
{
    snprintf(g_px[id].host, sizeof g_px[id].host, "%s", host);
}
static void set_proxy(uint32_t id, ProxyType t, uint16_t port, const char *u, const char *p)
{
    memset(&g_px[id], 0, sizeof g_px[id]);
    g_px[id].id = id; g_px[id].type = t; snprintf(g_px[id].name, 64, "px%u", id);
    snprintf(g_px[id].host, sizeof g_px[id].host, "127.0.0.1");
    g_px[id].port = port;
    if (u) snprintf(g_px[id].user, sizeof g_px[id].user, "%s", u);
    if (p) snprintf(g_px[id].pass, sizeof g_px[id].pass, "%s", p);
    g_px_used[id] = true;
}

static int count_fds(void)
{
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    while (readdir(d)) n++;
    closedir(d);
    return n - 3;
}
static int settle_fds(int target, int ms);
static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static void msleep(int ms) { usleep((useconds_t)ms * 1000); }
static int settle_fds(int target, int ms)
{
    int64_t t0 = now_ms();
    int n = count_fds();
    while (n > target && now_ms() - t0 < ms) { msleep(50); n = count_fds(); }
    return n;
}

struct srvcfg { bool auth; char user[64], pass[64]; bool leftover; bool silent; };
struct srv { int lfd; uint16_t port; void (*h)(int, const struct srvcfg *); struct srvcfg cfg; };
struct hctx { int fd; struct srv *s; };

static atomic_int g_assoc_count, g_s5_udp_dgrams, g_socks_conns;

static int rd_full(int fd, void *b, size_t n)
{
    uint8_t *p = b;
    while (n) { ssize_t r = recv(fd, p, n, 0); if (r <= 0) return -1; p += r; n -= (size_t)r; }
    return 0;
}
static int wr_full(int fd, const void *b, size_t n)
{
    const uint8_t *p = b;
    while (n) { ssize_t r = send(fd, p, n, MSG_NOSIGNAL); if (r <= 0) return -1; p += r; n -= (size_t)r; }
    return 0;
}

struct pipe_arg { int a, b; };
static void *pipe_dir(void *p)
{
    struct pipe_arg *x = p;
    char *buf = malloc(262144);
    ssize_t r;
    while ((r = recv(x->a, buf, 262144, 0)) > 0)
        if (wr_full(x->b, buf, (size_t)r)) break;
    free(buf);
    shutdown(x->b, SHUT_WR);
    if (r < 0) shutdown(x->a, SHUT_RD);
    return NULL;
}
static void pipe_both(int a, int b)
{
    struct pipe_arg x = { a, b }, y = { b, a };
    pthread_t t;
    pthread_create(&t, NULL, pipe_dir, &x);
    pipe_dir(&y);
    pthread_join(t, NULL);
}

static void echo_handler(int fd, const struct srvcfg *c)
{
    (void)c;
    char buf[32768];
    ssize_t r;
    while ((r = recv(fd, buf, sizeof buf, 0)) > 0)
        if (wr_full(fd, buf, (size_t)r)) break;
    shutdown(fd, SHUT_WR);
}

static int connect_target(int atyp, const uint8_t *addr, const char *host, uint16_t port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (atyp == 1) memcpy(&a.sin_addr, addr, 4);
    else if (atyp == 3) { if (!strcmp(host, "localhost") || !strcmp(host, "echo.test")) a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); else return -1; }
    else return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

static void socks_udp_assoc(int tfd)
{
    atomic_fetch_add(&g_assoc_count, 1);
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(u, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(u, (struct sockaddr *)&a, &al);
    uint8_t rep[10] = { 5, 0, 0, 1, 127, 0, 0, 1, (uint8_t)(ntohs(a.sin_port) >> 8), (uint8_t)ntohs(a.sin_port) };
    wr_full(tfd, rep, 10);
    struct sockaddr_in cli = { 0 };
    bool have = false;
    for (;;) {
        struct pollfd p[2] = { { tfd, POLLIN, 0 }, { u, POLLIN, 0 } };
        if (poll(p, 2, 10000) < 0) break;
        if (p[0].revents) { char b[64]; if (recv(tfd, b, sizeof b, 0) <= 0) break; }
        if (p[1].revents & POLLIN) {
            uint8_t b[70000];
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            ssize_t n = recvfrom(u, b, sizeof b, 0, (struct sockaddr *)&from, &fl);
            if (n < 1) continue;
            if (!have) { cli = from; have = true; }
            if (from.sin_addr.s_addr == cli.sin_addr.s_addr && from.sin_port == cli.sin_port) {
                if (n < 10 || b[3] != 1) continue;
                struct sockaddr_in d = { .sin_family = AF_INET };
                memcpy(&d.sin_addr, b + 4, 4); memcpy(&d.sin_port, b + 8, 2);
                sendto(u, b + 10, (size_t)n - 10, 0, (struct sockaddr *)&d, sizeof d);
                atomic_fetch_add(&g_s5_udp_dgrams, 1);
            } else {
                uint8_t o[70020] = { 0, 0, 0, 1 };
                memcpy(o + 4, &from.sin_addr, 4); memcpy(o + 8, &from.sin_port, 2);
                memcpy(o + 10, b, (size_t)n);
                sendto(u, o, (size_t)n + 10, 0, (struct sockaddr *)&cli, sizeof cli);
            }
        }
    }
    close(u);
}

static void socks_handler(int fd, const struct srvcfg *c)
{
    atomic_fetch_add(&g_socks_conns, 1);
    if (c->silent) { char b[16]; while (recv(fd, b, sizeof b, 0) > 0) {} return; }
    uint8_t h[2], m[256];
    if (rd_full(fd, h, 2) || h[0] != 5 || rd_full(fd, m, h[1])) return;
    bool has0 = false, has2 = false;
    for (int i = 0; i < h[1]; i++) { if (m[i] == 0) has0 = true; if (m[i] == 2) has2 = true; }
    uint8_t sel[2] = { 5, 0xFF };
    if (c->auth && has2) sel[1] = 2; else if (!c->auth && has0) sel[1] = 0;
    wr_full(fd, sel, 2);
    if (sel[1] == 0xFF) return;
    if (sel[1] == 2) {
        uint8_t v, l; char u[256], p[256];
        if (rd_full(fd, &v, 1) || rd_full(fd, &l, 1) || rd_full(fd, u, l)) return;
        u[l] = 0;
        if (rd_full(fd, &l, 1) || rd_full(fd, p, l)) return;
        p[l] = 0;
        bool ok = !strcmp(u, c->user) && !strcmp(p, c->pass);
        uint8_t r[2] = { 1, ok ? 0 : 1 };
        wr_full(fd, r, 2);
        if (!ok) return;
    }
    uint8_t rq[4];
    if (rd_full(fd, rq, 4)) return;
    uint8_t addr[16] = { 0 };
    char host[256] = "";
    if (rq[3] == 1) { if (rd_full(fd, addr, 4)) return; }
    else if (rq[3] == 4) { if (rd_full(fd, addr, 16)) return; }
    else if (rq[3] == 3) { uint8_t l; if (rd_full(fd, &l, 1) || rd_full(fd, host, l)) return; host[l] = 0; }
    uint8_t pt[2];
    if (rd_full(fd, pt, 2)) return;
    uint16_t port = (uint16_t)(pt[0] << 8 | pt[1]);
    if (rq[1] == 3) { socks_udp_assoc(fd); return; }
    int t = connect_target(rq[3], addr, host, port);
    uint8_t rep[10] = { 5, t < 0 ? 5 : 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    wr_full(fd, rep, 10);
    if (t < 0) return;
    pipe_both(fd, t);
    close(t);
}

static void http_handler(int fd, const struct srvcfg *c)
{
    char b[4096];
    size_t n = 0;
    while (n < sizeof b - 1) {
        ssize_t r = recv(fd, b + n, 1, 0);
        if (r <= 0) return;
        n++;
        if (n >= 4 && !memcmp(b + n - 4, "\r\n\r\n", 4)) break;
    }
    b[n] = 0;
    if (c->auth) {
        char want[200];
        snprintf(want, sizeof want, "Proxy-Authorization: Basic %s", c->pass);
        if (!strstr(b, want)) { const char *r = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"; wr_full(fd, r, strlen(r)); return; }
    }
    char host[200]; unsigned port;
    if (sscanf(b, "CONNECT %199[^:]:%u", host, &port) != 2) return;
    struct in_addr a;
    int t = -1;
    if (inet_pton(AF_INET, host, &a) == 1) t = connect_target(1, (uint8_t *)&a, "", (uint16_t)port);
    else t = connect_target(3, NULL, host, (uint16_t)port);
    if (t < 0) { const char *r = "HTTP/1.1 502 Bad Gateway\r\n\r\n"; wr_full(fd, r, strlen(r)); return; }
    const char *ok = c->leftover ? "HTTP/1.1 200 Connection established\r\nX: y\r\n\r\nLEFTOVER" : "HTTP/1.1 200 Connection established\r\n\r\n";
    wr_full(fd, ok, strlen(ok));
    pipe_both(fd, t);
    close(t);
}

static void *conn_thread(void *p)
{
    struct hctx *x = p;
    x->s->h(x->fd, &x->s->cfg);
    close(x->fd);
    free(x);
    return NULL;
}
static void *accept_thread(void *p)
{
    struct srv *s = p;
    for (;;) {
        int fd = accept(s->lfd, NULL, NULL);
        if (fd < 0) { if (errno == EINTR) continue; return NULL; }
        struct hctx *x = malloc(sizeof *x);
        x->fd = fd; x->s = s;
        pthread_t t;
        pthread_create(&t, NULL, conn_thread, x);
        pthread_detach(t);
    }
}
static struct srv *srv_start_p(void (*h)(int, const struct srvcfg *), const struct srvcfg *cfg, uint16_t port)
{
    struct srv *s = calloc(1, sizeof *s);
    s->h = h;
    if (cfg) s->cfg = *cfg;
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(port) };
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof a) < 0) { close(s->lfd); free(s); return NULL; }
    listen(s->lfd, 256);
    socklen_t al = sizeof a;
    getsockname(s->lfd, (struct sockaddr *)&a, &al);
    s->port = ntohs(a.sin_port);
    pthread_t t;
    pthread_create(&t, NULL, accept_thread, s);
    pthread_detach(t);
    return s;
}
#define srv_start(h, c) srv_start_p(h, c, 0)

struct udpecho { int fd; uint16_t port; };
static void *udpecho_thread(void *p)
{
    struct udpecho *e = p;
    char b[70000];
    for (;;) {
        struct sockaddr_in f;
        socklen_t fl = sizeof f;
        ssize_t n = recvfrom(e->fd, b, sizeof b, 0, (struct sockaddr *)&f, &fl);
        if (n < 0) { if (errno == EINTR) continue; return NULL; }
        sendto(e->fd, b, (size_t)n, 0, (struct sockaddr *)&f, fl);
    }
}
static uint16_t udpecho_start(void)
{
    struct udpecho *e = calloc(1, sizeof *e);
    e->fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rb = 4 << 20;
    setsockopt(e->fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(e->fd, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(e->fd, (struct sockaddr *)&a, &al);
    e->port = ntohs(a.sin_port);
    pthread_t t;
    pthread_create(&t, NULL, udpecho_thread, e);
    pthread_detach(t);
    return e->port;
}

static int g_last_connect_errno;
static int relay_connect_from(uint32_t src_ip_be, uint16_t src)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = src_ip_be, .sin_port = htons(src) };
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        g_last_connect_errno = errno;
        printf("      relay_connect: bind(127.0.0.1:%u) failed: %s\n", src, strerror(errno));
        close(fd); return -1;
    }
    a.sin_port = htons(pb_relay_tcp_port());
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        g_last_connect_errno = errno;
        // an ECONNRESET here is legitimate for flows the relay aborts (BLOCK, cap): on a fast loopback the RST can arrive
        // before connect() returns. Callers that expect a close accept it through closed_by_relay().
        if (errno != ECONNRESET)
            printf("      relay_connect: connect(src port %u -> relay port %u) failed: %s\n", src, pb_relay_tcp_port(), strerror(errno));
        close(fd); return -1;
    }
    tv.tv_sec = 30;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}
static int relay_connect(uint16_t src) { return relay_connect_from(htonl(INADDR_LOOPBACK), src); }
static uint16_t new_src(void) { return (uint16_t)atomic_fetch_add(&g_next_port, 1); }

static inline uint8_t pat(uint64_t i) { return (uint8_t)((i * 0x9E3779B1u) >> 11); }

struct xf { int fd; uint64_t total; bool half; };
static void *xf_send(void *p)
{
    struct xf *x = p;
    uint8_t buf[65536];
    uint64_t off = 0;
    while (off < x->total) {
        size_t n = x->total - off > sizeof buf ? sizeof buf : (size_t)(x->total - off);
        for (size_t j = 0; j < n; j++) buf[j] = pat(off + j);
        if (wr_full(x->fd, buf, n)) break;
        off += n;
    }
    if (x->half) shutdown(x->fd, SHUT_WR);
    return NULL;
}
static int64_t xfer(int fd, uint64_t total, bool half)
{
    struct xf x = { fd, total, half };
    pthread_t t;
    pthread_create(&t, NULL, xf_send, &x);
    uint8_t buf[65536];
    uint64_t got = 0;
    int64_t res = 0;
    for (;;) {
        if (!half && got >= total) break;
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r <= 0) break;
        for (ssize_t j = 0; j < r; j++) if (buf[j] != pat(got + (uint64_t)j)) { res = -1; goto out; }
        got += (uint64_t)r;
    }
    res = (int64_t)got;
out:
    if (res < 0) shutdown(fd, SHUT_RDWR);
    pthread_join(t, NULL);
    return res;
}
static bool expect_closed(int fd, int timeout_ms)
{
    if (timeout_ms < 10000) timeout_ms = 10000;
    struct pollfd p = { fd, POLLIN, 0 };
    int pr = poll(&p, 1, timeout_ms);
    if (pr <= 0) { printf("      expect_closed(fd=%d): poll=%d errno=%d revents=0x%x\n", fd, pr, errno, p.revents); return false; }
    char b[64];
    ssize_t r = recv(fd, b, sizeof b, 0);
    int e = errno;
    bool ok = r == 0 || (r < 0 && e != EAGAIN);
    if (!ok) printf("      expect_closed(fd=%d): poll=%d revents=0x%x recv=%zd errno=%d\n", fd, pr, p.revents, r, e);
    return ok;
}

// True when the relay closed the connection: either connect() itself was reset (the relay aborted the flow before connect()
// returned, which happens on a fast loopback) or the client sees EOF/RST afterwards.
static bool closed_by_relay(int fd, int timeout_ms)
{
    if (fd < 0) return g_last_connect_errno == ECONNRESET;
    return expect_closed(fd, timeout_ms);
}

static int relay_up(int tcp_idle, int udp_idle, int maxc, int hs)
{
    struct pb_relay_cfg c = { TPORT, UPORT, maxc, tcp_idle, udp_idle, hs };
    return pb_relay_start(&c);
}

static uint16_t free_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(fd, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &al);
    close(fd);
    return ntohs(a.sin_port);
}

static int64_t tcp_roundtrip(const char *dst_ip, uint16_t dst_port, int action, uint32_t px, uint64_t n, bool half)
{
    uint16_t src = new_src();
    set_tcp(src, dst_ip, dst_port, action, px);
    int fd = relay_connect(src);
    if (fd < 0) return -2;
    int64_t r = xfer(fd, n, half);
    close(fd);
    return r;
}

static int udp_client(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(fd, (struct sockaddr *)&a, sizeof a);
    return fd;
}
static void udp_send_flow(int fd, const char *flow_ip, const char *msg)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(pb_relay_udp_port()) };
    inet_pton(AF_INET, flow_ip, &a.sin_addr);
    sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&a, sizeof a);
}
static int udp_recv_to(int fd, char *buf, size_t n, char *src_ip, uint16_t *src_port, int ms)
{
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct sockaddr_in f;
    socklen_t fl = sizeof f;
    ssize_t r = recvfrom(fd, buf, n - 1, 0, (struct sockaddr *)&f, &fl);
    if (r < 0) return -1;
    buf[r] = 0;
    inet_ntop(AF_INET, &f.sin_addr, src_ip, 32);
    *src_port = ntohs(f.sin_port);
    return (int)r;
}
static int udp_recv(int fd, char *buf, size_t n, char *ip, uint16_t *sp) { return udp_recv_to(fd, buf, n, ip, sp, 6000); }
static int udp_recv_neg(int fd, char *buf, size_t n, char *ip, uint16_t *sp) { return udp_recv_to(fd, buf, n, ip, sp, 1500); }
static bool udp_echo_ok(int fd, const char *flow_ip, const char *msg)
{
    char b[256], ip[32];
    uint16_t sp;
    udp_send_flow(fd, flow_ip, msg);
    int r = udp_recv(fd, b, sizeof b, ip, &sp);
    return r == (int)strlen(msg) && !strcmp(b, msg) && !strcmp(ip, flow_ip) && sp == pb_relay_udp_port();
}

static struct srv *g_echo, *g_s5, *g_s5auth, *g_http, *g_httpauth, *g_httpleft, *g_silent;
static uint16_t g_uecho1, g_uecho2;

static void *conc_thread(void *p)
{
    int idx = (int)(intptr_t)p;
    uint64_t mb = getenv("LARGE_MB") ? strtoull(getenv("LARGE_MB"), NULL, 10) : 8;
    int mode = idx % 3;
    int64_t r = tcp_roundtrip("127.0.0.1", g_echo->port, mode == 2 ? PB_ACT_DIRECT : PB_ACT_PROXY, mode == 0 ? 1 : (mode == 1 ? 3 : 0),
                              mb << 20, false);
    return (void *)(intptr_t)(r == (int64_t)(mb << 20));
}

static long vmrss_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = -1;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "VmRSS:", 6)) { v = atol(line + 6); break; }
    if (f) fclose(f);
    return v;
}

static atomic_uint g_churn_ctr;
static atomic_int g_churn_bad, g_churn_udp_lost;
static uint16_t g_dead_port;

static void churn_one(unsigned n)
{
    uint32_t ip = htonl(0x7f000002 + n % 60);
    uint16_t src = (uint16_t)(20000 + (n / 60) % 12000);
    int mode = (int)(n % 9);
    uint32_t px = 0;
    int action = PB_ACT_PROXY;
    uint16_t dport = g_echo->port;
    switch (mode) {
    case 0: px = 1; break;
    case 1: px = 3; break;
    case 2: action = PB_ACT_DIRECT; break;
    case 3: action = PB_ACT_BLOCK; break;
    case 4: px = 6; break;
    case 5: px = 7; break;
    case 6: px = 1; break;
    case 7: action = PB_ACT_DIRECT; dport = g_dead_port; break;
    default: action = PB_ACT_DIRECT; break;
    }
    set_tcp_from(ip, src, "127.0.0.1", dport, action, px);
    int fd = relay_connect_from(ip, src);
    if (fd < 0) {
        if (mode != 3 && mode != 4 && mode != 5 && mode != 7) atomic_fetch_add(&g_churn_bad, 1);
        return;
    }
    char b[128];
    switch (mode) {
    case 0: case 1: case 2:
        if (send(fd, "z", 1, MSG_NOSIGNAL) != 1 || rd_full(fd, b, 1) || b[0] != 'z') atomic_fetch_add(&g_churn_bad, 1);
        break;
    case 6: {
        struct linger l = { 1, 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof l);
        break;
    }
    case 8: {
        char big[100] = { 0 };
        send(fd, big, sizeof big, MSG_NOSIGNAL);
        struct linger l = { 1, 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof l);
        break;
    }
    default:
        (void)expect_closed(fd, 10000);
    }
    close(fd);
}

struct churn_arg { unsigned count; };
static void *churn_tcp_thread(void *p)
{
    struct churn_arg *a = p;
    for (unsigned i = 0; i < a->count; i++) churn_one(atomic_fetch_add(&g_churn_ctr, 1));
    return NULL;
}

struct churn_udp { unsigned total; int bad; };
static void *churn_udp_thread(void *p)
{
    struct churn_udp *a = p;
    enum { B = 1000 };
    int *fds = malloc(B * sizeof *fds);
    for (unsigned done = 0; done < a->total;) {
        int n = a->total - done < B ? (int)(a->total - done) : B;
        for (int lo = 0; lo < n; lo += 50) {          // paced so a starved echo server cannot overflow its socket buffer
            int hi = lo + 50 < n ? lo + 50 : n;
            for (int i = lo; i < hi; i++) {
                fds[i] = udp_client();
                udp_send_flow(fds[i], (done + (unsigned)i) % 10 == 0 ? "127.1.9.2" : "127.1.9.1", "churn");
            }
            for (int i = lo; i < hi; i++) {
                char r[32], ip[32];
                uint16_t sp;
                if (udp_recv_to(fds[i], r, sizeof r, ip, &sp, 4000) != 5) a->bad++;
                close(fds[i]);
            }
        }
        done += (unsigned)n;
        if (done < a->total) msleep(2200);
    }
    free(fds);
    return NULL;
}

static void churn_phase(unsigned tcp_total, unsigned udp_total)
{
    enum { T = 8 };
    pthread_t th[T], ut;
    struct churn_arg ca = { tcp_total / T };
    struct churn_udp cu = { udp_total, 0 };
    pthread_create(&ut, NULL, churn_udp_thread, &cu);
    for (int i = 0; i < T; i++) pthread_create(&th[i], NULL, churn_tcp_thread, &ca);
    for (int i = 0; i < T; i++) pthread_join(th[i], NULL);
    pthread_join(ut, NULL);
    atomic_fetch_add(&g_churn_udp_lost, cu.bad);
}

static void test_churn(void)
{
    unsigned tcp_total = getenv("PB_CHURN_TCP") ? (unsigned)atoi(getenv("PB_CHURN_TCP")) : 100000;
    unsigned udp_total = getenv("PB_CHURN_UDP") ? (unsigned)atoi(getenv("PB_CHURN_UDP")) : 20000;
    long limit_kb = (getenv("PB_CHURN_RSS_MB") ? atol(getenv("PB_CHURN_RSS_MB")) : 6) * 1024;
    pb_relay_stop();
    CHECK(relay_up(300, 1, 0, 5) == 0, "restart relay for churn (udp_idle=1s)");
    g_dead_port = free_port();
    set_proxy(6, PROXY_TYPE_SOCKS5, g_dead_port, NULL, NULL);
    set_proxy(7, PROXY_TYPE_SOCKS5, g_s5auth->port, "alice", "WRONG");
    set_flow("127.1.9.1", "127.0.0.1", g_uecho1, PB_ACT_DIRECT, 0);
    set_flow("127.1.9.2", "127.0.0.1", g_uecho2, PB_ACT_PROXY, 1);
    msleep(300);
    int base_fds = count_fds();

    unsigned chunk_tcp = tcp_total / 10 / 8 * 8, chunk_udp = udp_total / 10;
    long budget_ms = (getenv("PB_CHURN_BUDGET_S") ? atol(getenv("PB_CHURN_BUDGET_S")) : 60) * 1000;
    int64_t t0 = now_ms();
    churn_phase(chunk_tcp, chunk_udp);
    msleep(3000);
    long rss0 = vmrss_kb();
    int chunks = 1;
    while (chunks < 10 && now_ms() - t0 < budget_ms) { churn_phase(chunk_tcp, chunk_udp); chunks++; }
    msleep(3500);
    int fds_end = settle_fds(base_fds, 10000);
    long rss1 = vmrss_kb();
    unsigned tcp_done = chunk_tcp * (unsigned)chunks, udp_done = chunk_udp * (unsigned)chunks;
    printf("      churn: %u TCP + %u UDP sessions in %lld ms; RSS after warm-up %ld KB, final %ld KB (+%ld KB); fds base=%d end=%d\n",
           tcp_done, udp_done, (long long)(now_ms() - t0), rss0, rss1, rss1 - rss0, base_fds, fds_end);
    CHECK(chunks >= 4, "churn: completed %d of 10 chunks within the time budget", chunks);
    CHECK(g_churn_bad == 0, "churn: every TCP flow that must succeed did (failures=%d)", (int)g_churn_bad);
    CHECK(g_churn_udp_lost * 50 <= (int)udp_done, "churn: UDP datagrams lost <= 2%% (%d of %u; session-limit drop logged: %s)", (int)g_churn_udp_lost, udp_done,
          log_has("UDP session limit") ? "yes" : "no");
    CHECK(fds_end <= base_fds, "churn: fd count back to baseline (base=%d end=%d)", base_fds, fds_end);
    CHECK(rss1 - rss0 < limit_kb, "churn: RSS growth after warm-up < %ld MB (+%ld KB)", limit_kb / 1024, rss1 - rss0);
    pb_relay_stop();
    CHECK(relay_up(300, 60, 0, 5) == 0, "restart relay");
}

static void *perf_conn_thread(void *p)
{
    int n = (int)(intptr_t)p, ok = 0;
    for (int i = 0; i < n; i++) {
        uint16_t src = new_src();
        set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 1);
        int fd = relay_connect(src);
        char b = 'a';
        if (fd >= 0 && send(fd, &b, 1, MSG_NOSIGNAL) == 1 && recv(fd, &b, 1, 0) == 1) ok++;
        if (fd >= 0) close(fd);
    }
    return (void *)(intptr_t)ok;
}

static void test_perf(void)
{
    unsigned dg = getenv("PB_PERF_UDP") ? (unsigned)atoi(getenv("PB_PERF_UDP")) : 60000;
    int conns = getenv("PB_PERF_CONNS") ? atoi(getenv("PB_PERF_CONNS")) : 1500;
    set_flow("127.1.10.1", "127.0.0.1", g_uecho1, PB_ACT_DIRECT, 0);
    set_flow("127.1.10.2", "127.0.0.1", g_uecho2, PB_ACT_PROXY, 1);
    const char *fl[2] = { "127.1.10.1", "127.1.10.2" };
    const char *nm[2] = { "DIRECT", "SOCKS5" };
    for (int k = 0; k < 2; k++) {
        int c = udp_client();
        struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(pb_relay_udp_port()) };
        inet_pton(AF_INET, fl[k], &a.sin_addr);
        char msg[64] = "perf-datagram", rx[128], ip[32];
        uint16_t sp;
        udp_echo_ok(c, fl[k], "warm");
        unsigned got = 0;
        int64_t t0 = now_ms();
        for (unsigned sent = 0; sent < dg; sent += 16) {
            for (int i = 0; i < 16; i++) sendto(c, msg, sizeof msg, 0, (struct sockaddr *)&a, sizeof a);
            for (int i = 0; i < 16; i++) if (udp_recv_to(c, rx, sizeof rx, ip, &sp, 2000) > 0) got++;
        }
        int64_t ms = now_ms() - t0;
        CHECK(got >= dg * 99 / 100, "perf UDP %s: %u datagrams round trip, %.0f pps (%lld ms, %u received)", nm[k], dg,
              (double)got * 1000.0 / (double)(ms + 1), (long long)ms, got);
        close(c);
    }
    enum { T = 8 };
    pthread_t th[T];
    int64_t t0 = now_ms();
    for (int i = 0; i < T; i++) pthread_create(&th[i], NULL, perf_conn_thread, (void *)(intptr_t)(conns / T));
    int ok = 0;
    for (int i = 0; i < T; i++) { void *r; pthread_join(th[i], &r); ok += (int)(intptr_t)r; }
    int64_t ms = now_ms() - t0;
    CHECK(ok == conns / T * T, "perf TCP via SOCKS5: %d short connections, %.0f conn/s (%lld ms)", ok, (double)ok * 1000.0 / (double)(ms + 1), (long long)ms);
}

static void test_tcp_basic(void)
{
    ev_clear();
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 1, 100000, false) == 100000, "TCP via SOCKS5 (no auth)");
    CHECK(g_ev == 1 && g_ev_proxy == 1, "flow_event exactly once for proxied flow (got %d)", (int)g_ev);
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 2, 100000, false) == 100000, "TCP via SOCKS5 (user/pass auth)");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 3, 100000, false) == 100000, "TCP via HTTP CONNECT");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 4, 100000, false) == 100000, "TCP via HTTP CONNECT with Basic auth");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 0, 5000, false) == 5000, "TCP via default proxy (id 0)");
    ev_clear();
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0, 100000, false) == 100000, "TCP DIRECT");
    CHECK(g_ev == 1 && g_ev_direct == 1, "flow_event for direct");

    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 5);
    int fd = relay_connect(src);
    char b[16] = { 0 };
    bool ok = fd >= 0 && rd_full(fd, b, 8) == 0 && !memcmp(b, "LEFTOVER", 8);
    CHECK(ok, "HTTP CONNECT leftover bytes forwarded to client");
    if (fd >= 0) close(fd);

    ev_clear();
    src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_BLOCK, 0);
    fd = relay_connect(src);
    send(fd, "x", 1, MSG_NOSIGNAL);
    CHECK(closed_by_relay(fd, 3000), "TCP BLOCK closes client");
    CHECK(g_ev_block == 1, "flow_event BLOCK");
    close(fd);

    set_decision((struct pb_decision){ PB_ACT_DIRECT, 0 });
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DECIDE, 0, 5000, false) == 5000, "TCP DECIDE -> DIRECT");
    set_decision((struct pb_decision){ PB_ACT_PROXY, 1 });
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DECIDE, 0, 5000, false) == 5000, "TCP DECIDE -> PROXY");
    set_decision((struct pb_decision){ PB_ACT_BLOCK, 0 });
    src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_DECIDE, 0);
    fd = relay_connect(src);
    CHECK(closed_by_relay(fd, 3000), "TCP DECIDE -> BLOCK");
    close(fd);

    fd = relay_connect(new_src());
    CHECK(closed_by_relay(fd, 3000), "TCP without original destination is closed");
    close(fd);

}

static void test_tcp_identity(void)
{
    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0);
    int fd = relay_connect_from(htonl(0x7f000002), src);
    if (fd >= 0) send(fd, "x", 1, MSG_NOSIGNAL);
    CHECK(closed_by_relay(fd, 3000), "connection from 127.0.0.2 with a registered port is closed");
    if (fd >= 0) close(fd);
    fd = relay_connect(src);
    char b = 0;
    bool ok = fd >= 0 && send(fd, "y", 1, MSG_NOSIGNAL) == 1 && rd_full(fd, &b, 1) == 0 && b == 'y';
    CHECK(ok, "registered flow from the right source address still works (entry not consumed by the impostor)");
    if (fd >= 0) close(fd);
    fd = relay_connect_from(htonl(0x7f000003), new_src());
    CHECK(closed_by_relay(fd, 3000), "connection from an unregistered address/port is closed");
    if (fd >= 0) close(fd);
}

static void test_tcp_bad_proxy(void)
{
    log_clear();
    uint16_t dead = free_port();
    set_proxy(6, PROXY_TYPE_SOCKS5, dead, NULL, NULL);
    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 6);
    int fd = relay_connect(src);
    CHECK(closed_by_relay(fd, 5000) && log_has("refused"), "bad proxy (connection refused): client closed + logged");
    close(fd);

    log_clear();
    set_proxy(7, PROXY_TYPE_SOCKS5, g_s5auth->port, "alice", "WRONG");
    src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 7);
    fd = relay_connect(src);
    CHECK(closed_by_relay(fd, 5000) && log_has("authentication failed"), "SOCKS5 wrong password: client closed + logged");
    close(fd);

    log_clear();
    set_proxy(8, PROXY_TYPE_HTTP, g_httpauth->port, "alice", "WRONG");
    src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 8);
    fd = relay_connect(src);
    CHECK(closed_by_relay(fd, 5000) && log_has("407"), "HTTP 407: client closed + logged");
    close(fd);

    log_clear();
    src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 12);
    fd = relay_connect(src);
    CHECK(closed_by_relay(fd, 5000) && log_has("no proxy configured"), "unknown proxy id: client closed + logged");
    close(fd);

    log_clear();
    src = new_src();
    set_tcp(src, "127.0.0.1", dead, PB_ACT_PROXY, 1);
    fd = relay_connect(src);
    CHECK(closed_by_relay(fd, 5000) && log_has("connection refused by target"), "SOCKS5 REP code mapped in log");
    close(fd);
}

static void sink_handler(int fd, const struct srvcfg *c)
{
    (void)c;
    char *buf = malloc(262144);
    uint64_t total = 0;
    ssize_t r;
    while ((r = recv(fd, buf, 262144, 0)) > 0) total += (uint64_t)r;
    free(buf);
    wr_full(fd, &total, 8);
}
static struct srv *g_sink;
struct thru { int action; uint32_t px; uint64_t bytes; int ok; };
static void *thru_thread(void *p)
{
    struct thru *t = p;
    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", g_sink->port, t->action, t->px);
    int fd = relay_connect(src);
    static const char z[65536];
    uint64_t sent = 0, total = 0;
    while (fd >= 0 && sent < t->bytes) { if (wr_full(fd, z, sizeof z)) break; sent += sizeof z; }
    if (fd >= 0) { shutdown(fd, SHUT_WR); t->ok = rd_full(fd, &total, 8) == 0 && total == sent && sent == t->bytes; close(fd); }
    return NULL;
}
static void test_throughput(void)
{
    uint64_t mb = getenv("THRU_MB") ? strtoull(getenv("THRU_MB"), NULL, 10) : 256;
    struct { const char *name; int action; uint32_t px; } m[] = { { "DIRECT via relay", PB_ACT_DIRECT, 0 }, { "SOCKS5 via relay + fake proxy", PB_ACT_PROXY, 1 } };
    for (int k = 0; k < 2; k++) {
        enum { N = 8 };
        pthread_t th[N];
        struct thru t[N];
        int64_t t0 = now_ms();
        for (int i = 0; i < N; i++) { t[i] = (struct thru){ m[k].action, m[k].px, mb << 20, 0 }; pthread_create(&th[i], NULL, thru_thread, &t[i]); }
        int ok = 0;
        for (int i = 0; i < N; i++) { pthread_join(th[i], NULL); ok += t[i].ok; }
        int64_t ms = now_ms() - t0;
        CHECK(ok == N, "throughput %s: %d x %lluMB, %.0f MB/s aggregate (%lld ms)", m[k].name, N, (unsigned long long)mb,
              (double)(N * mb) * 1000.0 / (double)(ms + 1), (long long)ms);
    }
}

// A server that streams data until the connection breaks, and one that resets every connection at once.
static void burst_handler(int fd, const struct srvcfg *c)
{
    (void)c;
    char buf[16384];
    memset(buf, 'b', sizeof buf);
    for (int i = 0; i < 400; i++)
        if (send(fd, buf, sizeof buf, MSG_NOSIGNAL) < 0) break;
}
static void reset_handler(int fd, const struct srvcfg *c)
{
    (void)c;
    struct linger lg = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);      // close() sends RST
}

// splice() into a connection the peer already reset raises SIGPIPE, which would end the process that hosts the relay
// (GitHub issue 268). Every such write must just fail and close that one connection; other connections keep working.
static void test_sigpipe(void)
{
    struct srv *burst = srv_start(burst_handler, NULL), *rst = srv_start(reset_handler, NULL);
    CHECK(burst && rst, "SIGPIPE: helper servers started");
    if (!burst || !rst) return;
    for (int i = 0; i < 20; i++) {                 // server -> client: the client resets while data is still being forwarded
        uint16_t src = new_src();
        set_tcp(src, "127.0.0.1", burst->port, PB_ACT_DIRECT, 0);
        int fd = relay_connect(src);
        if (fd < 0) continue;
        char b[64];
        recv(fd, b, sizeof b, 0);
        struct linger lg = { 1, 0 };
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(fd);
    }
    msleep(300);
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0, 50000, false) == 50000, "SIGPIPE: relay still serves traffic after clients reset mid-transfer");
    for (int i = 0; i < 20; i++) {                 // client -> server: the server resets, the client keeps sending
        uint16_t src = new_src();
        set_tcp(src, "127.0.0.1", rst->port, PB_ACT_DIRECT, 0);
        int fd = relay_connect(src);
        if (fd < 0) continue;
        char buf[65536];
        memset(buf, 'c', sizeof buf);
        for (int k = 0; k < 8; k++) if (send(fd, buf, sizeof buf, MSG_NOSIGNAL) < 0) break;
        close(fd);
    }
    msleep(300);
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0, 50000, false) == 50000, "SIGPIPE: relay still serves traffic after servers reset mid-transfer");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 1, 50000, false) == 50000, "SIGPIPE: proxied traffic also unaffected");
}

static void test_tcp_halfclose(void)
{
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 1, 300000, true) == 300000, "half-close via SOCKS5: all echoed then EOF");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 3, 300000, true) == 300000, "half-close via HTTP CONNECT");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0, 300000, true) == 300000, "half-close DIRECT");
}

static void test_tcp_large(void)
{
    uint64_t mb = getenv("LARGE_MB") ? strtoull(getenv("LARGE_MB"), NULL, 10) : 8;
    int64_t t0 = now_ms();
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 1, 50ull << 20, false) == (int64_t)(50ull << 20), "50MB single transfer via SOCKS5, checksum ok (%lld ms, %.0f MB/s each way)", (long long)(now_ms() - t0), 50000.0 / (double)(now_ms() - t0 + 1));
    enum { N = 50 };
    pthread_t th[N];
    t0 = now_ms();
    for (int i = 0; i < N; i++) pthread_create(&th[i], NULL, conc_thread, (void *)(intptr_t)i);
    int ok = 0;
    for (int i = 0; i < N; i++) { void *r; pthread_join(th[i], &r); ok += (int)(intptr_t)r; }
    CHECK(ok == N, "%d concurrent x %lluMB (socks5/http/direct mix) integrity: %d/%d ok (%lld ms)", N, (unsigned long long)mb, ok, N, (long long)(now_ms() - t0));
}

// Single-threaded SOCKS5 "hold" server: accepts any CONNECT and then just swallows data, so 10k connections cost
// the test process almost nothing and the RSS delta mostly reflects the relay.
static atomic_int g_hold_ready;
static void *hold_thread(void *arg)
{
    int lfd = (int)(intptr_t)arg;
    enum { MAXFD = 1 << 18 };
    uint8_t *stage = calloc(MAXFD, 1);
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = lfd };
    epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev);
    for (;;) {
        struct epoll_event evs[128];
        int n = epoll_wait(ep, evs, 128, -1);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == lfd) {
                int c;
                while ((c = accept4(lfd, NULL, NULL, SOCK_NONBLOCK)) >= 0) {
                    if (c >= MAXFD) { close(c); continue; }
                    stage[c] = 0;
                    struct epoll_event e = { .events = EPOLLIN, .data.fd = c };
                    epoll_ctl(ep, EPOLL_CTL_ADD, c, &e);
                }
                continue;
            }
            uint8_t b[4096];
            ssize_t r;
            if (stage[fd] == 0) {
                r = recv(fd, b, 3, 0);
                if (r == 3) { send(fd, "\5\0", 2, MSG_NOSIGNAL); stage[fd] = 1; continue; }
            } else if (stage[fd] == 1) {
                r = recv(fd, b, 10, 0);
                if (r == 10) {
                    uint8_t rep[10] = { 5, 0, 0, 1 };
                    send(fd, rep, 10, MSG_NOSIGNAL);
                    stage[fd] = 2;
                    atomic_fetch_add(&g_hold_ready, 1);
                    continue;
                }
            } else {
                r = recv(fd, b, sizeof b, 0);
                if (r > 0) continue;
            }
            if (r < 0 && errno == EAGAIN) continue;
            close(fd);
        }
    }
    return NULL;
}

static long rss_kb(void)
{
    long pages = 0, rss = 0;
    FILE *f = fopen("/proc/self/statm", "r");
    if (f) { if (fscanf(f, "%ld %ld", &pages, &rss) != 2) rss = 0; fclose(f); }
    return rss * (sysconf(_SC_PAGESIZE) / 1024);
}

static void test_tcp_10k(void)
{
    enum { N = 10000 };
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max < 200000 ? rl.rlim_max : 200000;
    setrlimit(RLIMIT_NOFILE, &rl);
    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(lfd, (struct sockaddr *)&a, sizeof a);
    listen(lfd, 4096);
    socklen_t al = sizeof a;
    getsockname(lfd, (struct sockaddr *)&a, &al);
    pthread_t t;
    pthread_create(&t, NULL, hold_thread, (void *)(intptr_t)lfd);
    pthread_detach(t);
    set_proxy(10, PROXY_TYPE_SOCKS5, ntohs(a.sin_port), NULL, NULL);

    pb_relay_stop();
    CHECK(relay_up(300, 60, 0, 10) == 0, "restart relay with default limits for 10k test");
    msleep(300);
    atomic_store(&g_next_port, 21000);
    atomic_store(&g_hold_ready, 0);
    int base_fds = count_fds();
    long rss0 = rss_kb();
    int *fds = malloc(N * sizeof *fds);
    for (int i = 0; i < N; i++) fds[i] = -1;
    int opened = 0, consec_fail = 0;
    bool stalled = false;
    for (int i = 0; i < N && !stalled; i++) {
        fds[i] = -1;
        for (int tries = 0; tries < 5 && fds[i] < 0; tries++) {
            uint16_t src = new_src();
            set_tcp(src, "127.0.0.1", 9, PB_ACT_PROXY, 10);
            fds[i] = relay_connect(src);
        }
        if (fds[i] >= 0) { opened++; consec_fail = 0; }
        else if (++consec_fail >= 20) { printf("      10k test: 20 consecutive connect failures at i=%d (%s), giving up\n", i, strerror(errno)); stalled = true; }
        if (i % 100 == 99) {            // pace so the bounded handshake queue is not what we measure
            int64_t t0 = now_ms();
            while (atomic_load(&g_hold_ready) < i - 200 && now_ms() - t0 < 30000) msleep(2);
            if (atomic_load(&g_hold_ready) < i - 200) { printf("      10k test: handshakes stalled at i=%d (ready=%d), giving up\n", i, (int)g_hold_ready); stalled = true; }
        }
    }
    int64_t t0 = now_ms();
    while (!stalled && atomic_load(&g_hold_ready) < N && now_ms() - t0 < 60000) msleep(20);
    msleep(500);
    long rss1 = rss_kb();
    int alive = 0;
    for (int i = 0; i < N; i += 100) {
        struct pollfd p = { fds[i], POLLIN, 0 };
        if (fds[i] >= 0 && poll(&p, 1, 0) == 0) alive++;
    }
    CHECK(opened == N && g_hold_ready == N, "10000 idle connections established through SOCKS5 (opened=%d handshaken=%d)", opened, (int)g_hold_ready);
    CHECK(alive == N / 100, "sampled idle connections still open (%d/%d)", alive, N / 100);
    printf("      RSS before=%ld KB after=%ld KB delta=%ld MB\n", rss0, rss1, (rss1 - rss0) / 1024);
    CHECK((rss1 - rss0) / 1024 < 100, "RSS delta for 10k idle connections < 100MB (%ld MB)", (rss1 - rss0) / 1024);
    for (int i = 0; i < N; i++) if (fds[i] >= 0) close(fds[i]);
    free(fds);
    t0 = now_ms();
    while (count_fds() > base_fds + 1 && now_ms() - t0 < 20000) msleep(50);
    CHECK(count_fds() <= base_fds + 1, "all fds released after closing 10k connections (base=%d now=%d)", base_fds, count_fds());
    pb_relay_stop();
    CHECK(relay_up(300, 60, 0, 5) == 0, "restart relay");
}

static void test_tcp_idle(void)
{
    pb_relay_stop();
    CHECK(relay_up(3, 60, 0, 5) == 0, "restart relay with tcp_idle=3s");
    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 1);
    int fd = relay_connect(src);
    send(fd, "hi", 2, 0);
    char b[4];
    rd_full(fd, b, 2);
    int64_t t0 = now_ms();
    bool closed = expect_closed(fd, 15000);
    CHECK(closed && now_ms() - t0 >= 1000 && now_ms() - t0 < 14000, "idle TCP connection closed after ~2s (%lld ms)", (long long)(now_ms() - t0));
    close(fd);

    src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0);
    fd = relay_connect(src);
    bool alive = true;
    for (int i = 0; i < 10 && alive; i++) {
        send(fd, "p", 1, 0);
        alive = rd_full(fd, b, 1) == 0;
        msleep(500);
    }
    CHECK(alive, "active connection survives past idle timeout");
    close(fd);
}

static void test_tcp_cap(void)
{
    pb_relay_stop();
    CHECK(relay_up(300, 60, 5, 5) == 0, "restart relay with max_tcp_conns=5");
    int fds[5];
    int up = 0;
    for (int i = 0; i < 5; i++) {
        uint16_t s = new_src();
        set_tcp(s, "127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0);
        fds[i] = relay_connect(s);
        char b[1];
        send(fds[i], "x", 1, 0);
        if (rd_full(fds[i], b, 1) == 0) up++;
    }
    CHECK(up == 5, "5 connections within cap work");
    uint16_t s = new_src();
    set_tcp(s, "127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0);
    int extra = relay_connect(s);
    send(extra, "x", 1, MSG_NOSIGNAL);
    CHECK(closed_by_relay(extra, 3000), "6th connection closed immediately (cap)");
    close(extra);
    close(fds[0]);
    bool freed = false;
    for (int i = 0; i < 100 && !freed; i++) {
        msleep(100);
        freed = tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0, 1000, false) == 1000;
    }
    CHECK(freed, "slot freed after close");
    for (int i = 1; i < 5; i++) close(fds[i]);
    msleep(300);
}

static void test_handshake_timeout(void)
{
    pb_relay_stop();
    CHECK(relay_up(300, 60, 0, 2) == 0, "restart relay with handshake_timeout=2s");
    log_clear();
    set_proxy(9, PROXY_TYPE_SOCKS5, g_silent->port, NULL, NULL);
    uint16_t s = new_src();
    set_tcp(s, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 9);
    int fd = relay_connect(s);
    int64_t t0 = now_ms();
    bool closed = expect_closed(fd, 6000);
    CHECK(closed && now_ms() - t0 >= 1500 && now_ms() - t0 < 14000 && log_has("timed out"), "silent proxy: handshake times out (%lld ms)", (long long)(now_ms() - t0));
    close(fd);
}

// More concurrent UDP sockets of one process than its share of the session table. Sessions are replaced oldest first, but never
// one that a worker thread is still setting up (that was a use-after-free found by the full end-to-end suite). Under ASan this
// test fails on the old code; in every build the relay must survive and keep serving.
static void test_udp_session_cap(void)
{
    set_flow("127.1.2.3", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 1);
    enum { N = 2400 };            // more than the per-process share (half of 4096)
    int fds[N];
    for (int i = 0; i < N; i++) {
        fds[i] = udp_client();
        char m[16];
        snprintf(m, sizeof m, "cap%d", i);
        udp_send_flow(fds[i], "127.1.2.3", m);
    }
    msleep(2500);                                    // let the associations finish and the answers arrive
    int answered = 0;
    for (int i = 0; i < N; i++) {
        char b[64], ip[32];
        uint16_t sp;
        if (udp_recv_to(fds[i], b, sizeof b, ip, &sp, 20) > 0) answered++;   // sockets whose session was replaced get nothing
        close(fds[i]);
    }
    CHECK(answered >= 1000, "UDP: %d sockets past the per-process session share, the relay survives and answers (%d answered)", (int)N, answered);
    msleep(500);
    int c = udp_client();
    CHECK(udp_echo_ok(c, "127.1.2.3", "after-cap"), "UDP still works after the session table was full");
    close(c);
}

static void test_udp(void)
{
    char b[256], ip[32];
    uint16_t sp;
    int c = udp_client();
    set_flow("127.1.2.3", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 1);
    set_flow("127.1.2.4", "127.0.0.1", g_uecho2, PB_ACT_PROXY, 1);
    int a0 = g_assoc_count;
    CHECK(udp_echo_ok(c, "127.1.2.3", "hello-one"), "UDP via SOCKS5 UDP ASSOCIATE, reply from flow address 127.1.2.3");
    CHECK(udp_echo_ok(c, "127.1.2.4", "hello-two"), "second destination from same client socket, reply from 127.1.2.4");
    CHECK(udp_echo_ok(c, "127.1.2.3", "again"), "first destination again");
    {   // a datagram that does not come from the flow's own process is dropped, and the flow keeps working for its owner
        atomic_store(&g_sender_bad, 1);
        int imp = udp_client();
        char b[64], ip[32]; uint16_t sp;
        udp_send_flow(imp, "127.1.2.3", "impostor");
        CHECK(udp_recv_neg(imp, b, sizeof b, ip, &sp) < 0, "UDP from a process that does not own the flow gets nothing back");
        atomic_store(&g_sender_bad, 0);
        close(imp);
        CHECK(udp_echo_ok(c, "127.1.2.3", "owner-again"), "the owner's datagrams still flow");
    }
    CHECK(g_assoc_count - a0 == 1, "exactly one UDP ASSOCIATE for the session (got %d)", (int)g_assoc_count - a0);

    int c2 = udp_client();
    for (int i = 0; i < 10; i++) { char m[32]; snprintf(m, sizeof m, "burst%d", i); udp_send_flow(c2, "127.1.2.3", m); }
    int got = 0;
    while (udp_recv_to(c2, b, sizeof b, ip, &sp, 3000) > 0) got++;
    CHECK(got == 10, "10 datagrams sent during association setup delivered (got %d)", got);
    close(c2);

    set_flow("127.1.2.5", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 2);
    c2 = udp_client();
    CHECK(udp_echo_ok(c2, "127.1.2.5", "auth-udp"), "UDP via authenticated SOCKS5");
    close(c2);

    set_flow("127.1.3.1", "127.0.0.1", g_uecho1, PB_ACT_DIRECT, 0);
    set_flow("127.1.3.2", "127.0.0.1", g_uecho2, PB_ACT_DIRECT, 0);
    CHECK(udp_echo_ok(c, "127.1.3.1", "direct-1") && udp_echo_ok(c, "127.1.3.2", "direct-2"), "UDP DIRECT, two destinations");

    set_flow("127.1.4.1", "127.0.0.1", g_uecho1, PB_ACT_BLOCK, 0);
    udp_send_flow(c, "127.1.4.1", "blocked");
    CHECK(udp_recv_neg(c, b, sizeof b, ip, &sp) < 0, "UDP BLOCK dropped");
    udp_send_flow(c, "127.9.9.9", "unknown");
    CHECK(udp_recv_neg(c, b, sizeof b, ip, &sp) < 0, "UDP unknown flow dropped");

    log_clear();
    set_flow("127.1.4.2", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 3);
    udp_send_flow(c, "127.1.4.2", "via-http");
    udp_send_flow(c, "127.1.4.2", "via-http2");
    CHECK(udp_recv_neg(c, b, sizeof b, ip, &sp) < 0 && log_has("HTTP proxy"), "UDP via HTTP proxy dropped + logged");

    set_decision((struct pb_decision){ PB_ACT_DIRECT, 0 });
    set_flow("127.1.4.3", "127.0.0.1", g_uecho1, PB_ACT_DECIDE, 0);
    g_decide_calls = 0;
    bool ok = udp_echo_ok(c, "127.1.4.3", "d1") && udp_echo_ok(c, "127.1.4.3", "d2") && udp_echo_ok(c, "127.1.4.3", "d3");
    CHECK(ok && g_decide_calls == 1, "UDP DECIDE -> DIRECT, decided once (calls=%d)", (int)g_decide_calls);

    set_flow("127.1.4.4", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 6);
    udp_send_flow(c, "127.1.4.4", "dead-proxy");
    CHECK(udp_recv_neg(c, b, sizeof b, ip, &sp) < 0, "UDP via dead SOCKS5 proxy: no reply, relay survives");
    CHECK(udp_echo_ok(c, "127.1.3.1", "still-alive"), "relay still serves UDP afterwards");
    close(c);
}


static int flows_of(struct pb_flow_info *out, int max, int udp)
{
    int n = pb_relay_flows(out, max), k = 0;
    for (int i = 0; i < n; i++) if (out[i].udp == udp) out[k++] = out[i];
    return k;
}

static bool wait_flow_count(int want, int udp, int ms)
{
    struct pb_flow_info f[64];
    for (int t = 0; t < ms; t += 50) {
        if (flows_of(f, 64, udp) == want) return true;
        usleep(50000);
    }
    return false;
}

static void test_flows(void)
{
    struct pb_flow_info f[64];
    CHECK(flows_of(f, 64, 0) == 0, "no flows listed before any connection");

    int fds[3];
    for (int i = 0; i < 3; i++) {
        uint16_t src = new_src();
        set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 1);
        fds[i] = relay_connect(src);
        usleep(30000);
    }
    CHECK(wait_flow_count(3, 0, 3000), "three proxied TCP connections are listed");
    int n = flows_of(f, 64, 0);
    bool fields = n == 3;
    for (int i = 0; i < n; i++) fields &= f[i].proxy_id == 1 && f[i].port == g_echo->port && f[i].family == AF_INET && f[i].id != 0;
    CHECK(fields, "each flow has its proxy, destination port and id");
    CHECK(n == 3 && f[0].age_ms <= f[1].age_ms && f[1].age_ms <= f[2].age_ms, "newest first");
    CHECK(n == 3 && f[0].id != f[1].id && f[1].id != f[2].id, "ids are unique");

    char buf[4096];
    memset(buf, 'a', sizeof buf);
    bool ok = fds[0] >= 0 && send(fds[0], buf, sizeof buf, MSG_NOSIGNAL) == (ssize_t)sizeof buf && rd_full(fds[0], buf, sizeof buf) == 0;
    CHECK(ok, "data goes through the first connection");
    usleep(100000);
    n = flows_of(f, 64, 0);
    uint64_t best_sent = 0, best_recv = 0;
    for (int i = 0; i < n; i++) { if (f[i].sent > best_sent) best_sent = f[i].sent; if (f[i].recv > best_recv) best_recv = f[i].recv; }
    CHECK(best_sent >= sizeof buf && best_recv >= sizeof buf, "byte counters follow the traffic (sent %llu, received %llu)",
          (unsigned long long)best_sent, (unsigned long long)best_recv);

    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0);
    int direct = relay_connect(src);
    usleep(100000);
    CHECK(flows_of(f, 64, 0) == 3, "a direct connection is not a proxied flow");
    if (direct >= 0) close(direct);

    close(fds[1]);
    CHECK(wait_flow_count(2, 0, 3000), "a closed connection leaves the list");
    close(fds[0]); close(fds[2]);
    CHECK(wait_flow_count(0, 0, 3000), "all closed: the list is empty");

    // UDP flows are published once a second; earlier tests left flows behind, so start from a clean relay
    pb_relay_stop();
    CHECK(relay_up(300, 60, 0, 5) == 0, "relay restarted for the UDP part");
    int c = udp_client();
    set_flow("127.1.6.1", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 1);
    CHECK(udp_echo_ok(c, "127.1.6.1", "flow-one") && udp_echo_ok(c, "127.1.6.1", "flow-two"), "UDP traffic through the proxy");
    CHECK(wait_flow_count(1, 1, 3000), "the UDP flow is listed");
    n = flows_of(f, 64, 1);
    CHECK(n == 1 && f[0].sent >= 16 && f[0].recv >= 16 && f[0].proxy_id == 1 && f[0].port == g_uecho1,
          "UDP counters and destination (sent %llu, received %llu)", n ? (unsigned long long)f[0].sent : 0ULL, n ? (unsigned long long)f[0].recv : 0ULL);
    set_flow("127.1.6.2", "127.0.0.1", g_uecho2, PB_ACT_DIRECT, 0);
    int c2 = udp_client();
    CHECK(udp_echo_ok(c2, "127.1.6.2", "direct"), "a direct UDP flow to the other echo server");
    sleep(2);
    n = flows_of(f, 64, 1);
    bool direct_listed = false;
    for (int i = 0; i < n; i++) direct_listed |= f[i].port == g_uecho2;
    CHECK(!direct_listed, "direct UDP is never listed (%d UDP flows listed)", n);
    close(c2);
    close(c);

    CHECK(pb_relay_flows(f, 0) == 0 && pb_relay_flows(NULL, 5) == 0, "degenerate arguments");
}


static void test_proxy_process_loop(void)
{
    // the process that serves the proxy must never be sent through it: the relay connects such flows directly
    int before = g_socks_conns;
    atomic_store(&g_loop_pid, 1);
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 1, 20000, false) == 20000, "TCP of the proxy's own process still works");
    CHECK(g_socks_conns == before, "...without touching the proxy (%d new proxy connections)", (int)g_socks_conns - before);
    set_decision((struct pb_decision){ PB_ACT_PROXY, 1 });
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DECIDE, 0, 5000, false) == 5000 && g_socks_conns == before,
          "also when the relay itself decided to use the proxy");
    int a0 = g_assoc_count;
    int c = udp_client();
    set_flow("127.1.7.1", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 1);
    CHECK(udp_echo_ok(c, "127.1.7.1", "own-process") && g_assoc_count == a0, "UDP of the proxy's own process goes direct, no association (%d)", (int)g_assoc_count - a0);
    close(c);
    atomic_store(&g_loop_pid, 0);
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 1, 20000, false) == 20000 && g_socks_conns > before,
          "any other process still goes through the proxy");
}

static void test_udp_idle(void)
{
    pb_relay_stop();
    CHECK(relay_up(300, 2, 0, 5) == 0, "restart relay with udp_idle=2s");
    int c = udp_client();
    set_flow("127.1.5.1", "127.0.0.1", g_uecho1, PB_ACT_DIRECT, 0);
    set_flow("127.1.5.2", "127.0.0.1", g_uecho2, PB_ACT_PROXY, 1);
    int base = count_fds();
    bool ok = udp_echo_ok(c, "127.1.5.1", "x") && udp_echo_ok(c, "127.1.5.2", "y");
    int mid = count_fds();
    int end = settle_fds(base, 15000);
    CHECK(ok && mid > base && end <= base, "UDP sessions expire after idle and free their fds (base=%d mid=%d end=%d)", base, mid, end);
    CHECK(udp_echo_ok(c, "127.1.5.1", "again"), "new session after expiry works");
    close(c);
}

static void test_start_stop(void)
{
    pb_relay_stop();
    pb_relay_stop();
    msleep(500);
    int before = count_fds();
    int bad = 0;
    for (int i = 0; i < 20; i++) {
        if (relay_up(0, 0, 0, 0) != 0) { bad++; continue; }
        if (i % 4 == 0) {
            bool a = tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 1, 2000, false) == 2000;
            int c = udp_client();
            set_flow("127.1.6.1", "127.0.0.1", g_uecho1, PB_ACT_DIRECT, 0);
            bool b = udp_echo_ok(c, "127.1.6.1", "z");
            close(c);
            if (!a || !b) bad++;
        }
        pb_relay_stop();
    }
    pb_relay_stop();
    int after = settle_fds(before, 5000);
    CHECK(bad == 0 && after <= before, "start/stop x20 (with traffic): fds before=%d after=%d, failures=%d", before, after, bad);

    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(TPORT) };
    if (bind(l, (struct sockaddr *)&a, sizeof a) < 0) perror("test bind");
    listen(l, 1);
    int b4 = count_fds();
    log_clear();
    int r1 = relay_up(0, 0, 0, 0);
    int af = settle_fds(b4, 3000);
    CHECK(r1 == -1 && af <= b4 && log_has("cannot listen"), "start fails when TCP port busy, no fd leak, logged");
    close(l);
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    a.sin_port = htons(UPORT);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(u, (struct sockaddr *)&a, sizeof a) < 0) perror("test bind");
    b4 = count_fds();
    r1 = relay_up(0, 0, 0, 0);
    af = settle_fds(b4, 3000);
    CHECK(r1 == -1 && af <= b4, "start fails when UDP port busy, no fd leak (TCP listener released)");
    close(u);
    CHECK(relay_up(0, 0, 0, 0) == 0, "start works after failed starts");
    pb_relay_stop();
}

static void test_proxy_helper(void)
{
    char b[256];
    int r = pb_relay_test_proxy(&g_px[1], "echo.test", g_echo->port, b, sizeof b);
    CHECK(r == 0 && !strcmp(b, "Tunnel established"), "test_proxy SOCKS5 domain ATYP, non-80 port: '%s'", b);
    r = pb_relay_test_proxy(&g_px[2], "127.0.0.1", g_echo->port, b, sizeof b);
    CHECK(r == 0, "test_proxy SOCKS5 with auth: '%s'", b);
    r = pb_relay_test_proxy(&g_px[3], "echo.test", g_echo->port, b, sizeof b);
    CHECK(r == 0 && !strcmp(b, "Tunnel established"), "test_proxy HTTP CONNECT hostname: '%s'", b);
    r = pb_relay_test_proxy(&g_px[7], "127.0.0.1", g_echo->port, b, sizeof b);
    CHECK(r == -1 && strstr(b, "authentication failed"), "test_proxy wrong password -> readable error: '%s'", b);
    r = pb_relay_test_proxy(&g_px[6], "127.0.0.1", 80, b, sizeof b);
    CHECK(r == -1 && strstr(b, "Cannot reach proxy"), "test_proxy dead proxy -> readable error: '%s'", b);
    r = pb_relay_test_proxy(&g_px[1], "nonexistent.test", 443, b, sizeof b);
    CHECK(r == -1 && strstr(b, "refused"), "test_proxy unreachable target -> error: '%s'", b);
}

static bool loopback_ok(void)
{
    int l = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    bool ok = false;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    struct timeval tv = { 3, 0 };
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (l >= 0 && c >= 0 && bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 1) == 0) {
        socklen_t al = sizeof a;
        getsockname(l, (struct sockaddr *)&a, &al);
        if (connect(c, (struct sockaddr *)&a, sizeof a) == 0) {
            struct pollfd p = { l, POLLIN, 0 };
            ok = poll(&p, 1, 3000) == 1;
        }
    }
    if (l >= 0) close(l);
    if (c >= 0) close(c);
    return ok;
}
static bool can_bind53(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(53) };
    bool ok = bind(fd, (struct sockaddr *)&a, sizeof a) == 0;
    close(fd);
    return ok;
}
// Runs in the forked DNS child only: gets a private netns where port 53 is bindable. Returns false if impossible.
static bool isolate_for_port53(void)
{
    bool force_no_lo = getenv("PB_TEST_FORCE_NO_LO") != NULL;
    if (!force_no_lo && can_bind53() && loopback_ok()) return true;
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) { printf("NOTE  DNS child: unshare failed: %s\n", strerror(errno)); return false; }
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) { if (write(fd, "deny", 4) < 0) {} close(fd); }
    char b[64];
    fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd >= 0) { int n = snprintf(b, sizeof b, "0 %u 1", uid); if (write(fd, b, (size_t)n) < 0) {} close(fd); }
    fd = open("/proc/self/gid_map", O_WRONLY);
    if (fd >= 0) { int n = snprintf(b, sizeof b, "0 %u 1", gid); if (write(fd, b, (size_t)n) < 0) {} close(fd); }
    if (!force_no_lo) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr;
        memset(&ifr, 0, sizeof ifr);
        snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
        ifr.ifr_flags = IFF_UP | IFF_RUNNING;
        if (s >= 0) { if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) printf("NOTE  DNS child: cannot bring lo up: %s\n", strerror(errno)); close(s); }
    }
    if (!loopback_ok()) { printf("NOTE  DNS child: loopback unusable in the new namespace\n"); return false; }
    if (!can_bind53()) { printf("NOTE  DNS child: port 53 not bindable in the new namespace\n"); return false; }
    return true;
}

struct shared { int pass, fail, status; };      // status: 0 = not run, 1 = ran, 3 = cannot isolate
static struct shared *g_shared;

static void mk_msg(int mode, int idx, uint8_t *m, size_t len)
{
    for (size_t i = 0; i < len; i++) m[i] = (uint8_t)(mode * 31 + idx * 17 + (int)i * 7);
}
static void dns_tcp_handler(int fd, const struct srvcfg *c)
{
    (void)c;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    uint8_t l[2], q[512];
    if (rd_full(fd, l, 2)) return;
    size_t n = (size_t)(l[0] << 8 | l[1]);
    if (n > sizeof q || rd_full(fd, q, n)) return;
    int mode = q[0];
    uint8_t out[300];
    if (mode == 'a') {
        out[0] = 0; out[1] = 100; mk_msg(mode, 0, out + 2, 100);
        for (int i = 0; i < 102; i++) { wr_full(fd, out + i, 1); usleep(1500); }
    } else if (mode == 'b') {
        out[0] = 0; out[1] = 40; mk_msg(mode, 0, out + 2, 40);
        out[42] = 0; out[43] = 60; mk_msg(mode, 1, out + 44, 60);
        wr_full(fd, out, 104);
    } else {
        out[0] = 0; out[1] = 100; mk_msg(mode, 0, out + 2, 100);
        wr_full(fd, out, 102);
    }
}
static void *dns_udp_thread(void *p)
{
    int fd = (int)(intptr_t)p;
    uint8_t b[600];
    for (;;) {
        struct sockaddr_in f;
        socklen_t fl = sizeof f;
        ssize_t n = recvfrom(fd, b, sizeof b, 0, (struct sockaddr *)&f, &fl);
        if (n < 1) continue;
        uint8_t m[100];
        mk_msg(b[0], 0, m, 100);
        sendto(fd, m, 100, 0, (struct sockaddr *)&f, fl);
    }
    return NULL;
}

static bool dns_tcp_case(const char *name, int action, uint32_t px, int mode, int nmsg)
{
    atomic_store(&g_obs_n, 0);
    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", 53, action, px);
    int fd = relay_connect(src);
    uint8_t q[3] = { 0, 1, (uint8_t)mode };
    wr_full(fd, q, 3);
    uint8_t got[400];
    size_t have = 0;
    int64_t first = 0;
    for (;;) {
        ssize_t r = recv(fd, got + have, sizeof got - have, 0);
        if (r <= 0) break;
        if (!have) first = mono_ms();
        have += (size_t)r;
    }
    close(fd);
    uint8_t exp[300];
    size_t el = 0;
    size_t lens[2] = { mode == 'b' ? 40 : 100, 60 };
    uint32_t hashes[2];
    for (int i = 0; i < nmsg; i++) {
        exp[el++] = 0; exp[el++] = (uint8_t)lens[i];
        mk_msg(mode, i, exp + el, lens[i]);
        hashes[i] = fnv(exp + el, lens[i]);
        el += lens[i];
    }
    bool ok = have == el && !memcmp(got, exp, el) && g_obs_n == nmsg;
    for (int i = 0; ok && i < nmsg; i++) ok = g_obs[i].len == lens[i] && g_obs[i].h == hashes[i];
    bool before = nmsg > 0 && g_obs[0].t1 <= first;          // observe finished before the client saw any byte
    CHECK(ok && before, "TCP DNS tap %s: stream intact, %d observe call(s) (got %d), observe completed %lld ms before first client byte", name,
          nmsg, (int)g_obs_n, nmsg ? (long long)(first - g_obs[0].t1) : -1LL);
    return ok;
}

static void test_dns(void)
{
    CHECK(g_obs_n == 0, "no DNS observe calls for non-port-53 flows so far (%d)", (int)g_obs_n);
    struct srv *d = srv_start_p(dns_tcp_handler, NULL, 53);
    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(53) };
    int ub = bind(ufd, (struct sockaddr *)&a, sizeof a);
    CHECK(d && ub == 0, "DNS fake servers on 127.0.0.1:53");
    if (!d || ub) return;
    pthread_t t;
    pthread_create(&t, NULL, dns_udp_thread, (void *)(intptr_t)ufd);
    pthread_detach(t);
    atomic_store(&g_obs_sleep, 50);

    dns_tcp_case("DIRECT single write", PB_ACT_DIRECT, 0, 'c', 1);
    dns_tcp_case("DIRECT 1-byte writes", PB_ACT_DIRECT, 0, 'a', 1);
    dns_tcp_case("DIRECT two messages in one write", PB_ACT_DIRECT, 0, 'b', 2);
    dns_tcp_case("via SOCKS5 single write", PB_ACT_PROXY, 1, 'c', 1);
    dns_tcp_case("via SOCKS5 1-byte writes", PB_ACT_PROXY, 1, 'a', 1);
    dns_tcp_case("via SOCKS5 two messages", PB_ACT_PROXY, 1, 'b', 2);
    dns_tcp_case("via HTTP CONNECT 1-byte writes", PB_ACT_PROXY, 3, 'a', 1);
    dns_tcp_case("via HTTP CONNECT two messages", PB_ACT_PROXY, 3, 'b', 2);

    atomic_store(&g_obs_n, 0);
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_DIRECT, 0, 1000, false) == 1000 && g_obs_n == 0, "TCP non-53 not observed");

    struct { const char *name; int action; uint32_t px; const char *flow; } u[] = {
        { "UDP DIRECT", PB_ACT_DIRECT, 0, "127.1.7.1" }, { "UDP via SOCKS5", PB_ACT_PROXY, 1, "127.1.7.2" } };
    for (int k = 0; k < 2; k++) {
        set_flow(u[k].flow, "127.0.0.1", 53, u[k].action, u[k].px);
        atomic_store(&g_obs_n, 0);
        int c = udp_client();
        char b[256], ip[32];
        uint16_t sp;
        udp_send_flow(c, u[k].flow, "q");
        int n = udp_recv(c, b, sizeof b, ip, &sp);
        int64_t tr = mono_ms();
        uint8_t m[100];
        mk_msg('q', 0, m, 100);
        bool ok = n == 100 && !memcmp(b, m, 100) && !strcmp(ip, u[k].flow) && g_obs_n == 1 && g_obs[0].h == fnv(m, 100) && g_obs[0].t1 <= tr;
        CHECK(ok, "%s DNS tap: reply observed (calls=%d) before delivery, from flow address", u[k].name, (int)g_obs_n);
        close(c);
    }
    atomic_store(&g_obs_n, 0);
    int c = udp_client();
    set_flow("127.1.7.3", "127.0.0.1", g_uecho1, PB_ACT_DIRECT, 0);
    CHECK(udp_echo_ok(c, "127.1.7.3", "plain") && g_obs_n == 0, "UDP non-53 not observed");
    close(c);
    atomic_store(&g_obs_sleep, 0);
}

static double pingpong_us(int fd, int n)
{
    char b = 'x';
    int64_t t0 = now_ms();
    struct timespec a, z;
    clock_gettime(CLOCK_MONOTONIC, &a);
    (void)t0;
    for (int i = 0; i < n; i++) {
        if (send(fd, &b, 1, MSG_NOSIGNAL) != 1 || recv(fd, &b, 1, 0) != 1) return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &z);
    return ((double)(z.tv_sec - a.tv_sec) * 1e9 + (double)(z.tv_nsec - a.tv_nsec)) / 1000.0 / n;
}
static void test_latency(void)
{
    int one = 1;
    int d = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(g_echo->port) };
    connect(d, (struct sockaddr *)&a, sizeof a);
    setsockopt(d, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    double direct = pingpong_us(d, 1000);
    close(d);
    double res[3];
    int acts[3] = { PB_ACT_DIRECT, PB_ACT_PROXY, PB_ACT_PROXY };
    uint32_t pxs[3] = { 0, 1, 3 };
    for (int k = 0; k < 3; k++) {
        uint16_t src = new_src();
        set_tcp(src, "127.0.0.1", g_echo->port, acts[k], pxs[k]);
        int fd = relay_connect(src);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        res[k] = pingpong_us(fd, 1000);
        close(fd);
    }
    printf("      avg RTT per 1-byte round trip: direct echo %.0f us, relay DIRECT %.0f us, relay+SOCKS5 %.0f us, relay+HTTP %.0f us\n",
           direct, res[0], res[1], res[2]);
    CHECK(direct > 0 && res[0] > 0 && res[1] > 0 && res[2] > 0 && res[0] < 20000 && res[1] < 20000 && res[2] < 20000,
          "no Nagle/delayed-ACK stall through relay (all averages < 20 ms; a stall would be >= 40 ms per trip)");
}

static void test_hostname(void)
{
    set_proxy(11, PROXY_TYPE_SOCKS5, g_s5->port, NULL, NULL);
    set_proxy_host(11, "localhost");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 11, 20000, false) == 20000, "TCP via SOCKS5 proxy configured as hostname 'localhost'");
    CHECK(tcp_roundtrip("127.0.0.1", g_echo->port, PB_ACT_PROXY, 11, 20000, false) == 20000, "second connection uses resolver cache");
    set_proxy(12, PROXY_TYPE_HTTP, g_http->port, NULL, NULL);
    set_proxy_host(12, "localhost");
    char b[256];
    int r = pb_relay_test_proxy(&g_px[12], "echo.test", g_echo->port, b, sizeof b);
    CHECK(r == 0, "pb_relay_test_proxy with hostname proxy: '%s'", b);
    set_proxy(13, PROXY_TYPE_SOCKS5, g_s5->port, NULL, NULL);
    set_proxy_host(13, "no-such-host.invalid");
    int64_t t0 = now_ms();
    r = pb_relay_test_proxy(&g_px[13], "echo.test", g_echo->port, b, sizeof b);
    int64_t dt = now_ms() - t0;
    CHECK(r == -1 && strstr(b, "cannot resolve") && dt < 9000, "unresolvable proxy hostname -> readable error in %lld ms: '%s'", (long long)dt, b);
    log_clear();
    uint16_t src = new_src();
    set_tcp(src, "127.0.0.1", g_echo->port, PB_ACT_PROXY, 13);
    int fd = relay_connect(src);
    CHECK(closed_by_relay(fd, 8000) && log_has("cannot resolve"), "relay TCP with unresolvable proxy: client closed + logged");
    close(fd);
}

// A UDP server that answers from a different socket than the one it received on.
//   payload starting with 'B': reply from another port on 127.0.0.1;  'C': reply from 127.0.0.2.
static void *odd_udp_thread(void *p)
{
    int fd = (int)(intptr_t)p;
    int b = socket(AF_INET, SOCK_DGRAM, 0), c = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in x = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(b, (struct sockaddr *)&x, sizeof x);
    x.sin_addr.s_addr = htonl(0x7f000002);
    bind(c, (struct sockaddr *)&x, sizeof x);
    char m[600];
    for (;;) {
        struct sockaddr_in f;
        socklen_t fl = sizeof f;
        ssize_t n = recvfrom(fd, m, sizeof m, 0, (struct sockaddr *)&f, &fl);
        if (n < 1) continue;
        sendto(m[0] == 'C' ? c : b, m, (size_t)n, 0, (struct sockaddr *)&f, fl);
    }
    return NULL;
}

static bool udp_big(int c, const char *flow, size_t n, bool expect)
{
    uint8_t *tx = malloc(n), *rx = malloc(70000);
    for (size_t i = 0; i < n; i++) tx[i] = pat(i);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(pb_relay_udp_port()) };
    inet_pton(AF_INET, flow, &a.sin_addr);
    ssize_t s = sendto(c, tx, n, 0, (struct sockaddr *)&a, sizeof a);
    struct sockaddr_in f;
    socklen_t fl = sizeof f;
    struct timeval tv = { expect ? 6 : 1, expect ? 0 : 500000 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ssize_t r = recvfrom(c, rx, 70000, 0, (struct sockaddr *)&f, &fl);
    char ip[32];
    inet_ntop(AF_INET, &f.sin_addr, ip, sizeof ip);
    bool ok = s == (ssize_t)n && (expect ? (r == (ssize_t)n && !memcmp(rx, tx, n) && !strcmp(ip, flow)) : r < 0);
    free(tx); free(rx);
    return ok;
}

static void test_udp_odd(void)
{
    int c = udp_client();
    int rb = 1 << 21;
    setsockopt(c, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    set_flow("127.1.8.1", "127.0.0.1", g_uecho1, PB_ACT_DIRECT, 0);
    set_flow("127.1.8.2", "127.0.0.1", g_uecho1, PB_ACT_PROXY, 1);
    CHECK(udp_big(c, "127.1.8.1", 65507, true), "UDP DIRECT 65507-byte datagram round trip intact");
    CHECK(udp_big(c, "127.1.8.2", 65497, true), "UDP via SOCKS5 65497-byte datagram (max with 10-byte header) round trip intact");
    CHECK(udp_big(c, "127.1.8.2", 30000, true), "UDP via SOCKS5 30000-byte datagram intact");
    CHECK(udp_big(c, "127.1.8.2", 65507, false), "UDP via SOCKS5 65507 (header would exceed IPv4 limit): dropped, no corruption");
    CHECK(udp_echo_ok(c, "127.1.8.2", "small-after-big") && udp_echo_ok(c, "127.1.8.1", "small-direct-after-big"), "small datagrams unaffected after oversized ones");

    uint16_t odd_port;
    int ofd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in x = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    bind(ofd, (struct sockaddr *)&x, sizeof x);
    socklen_t xl = sizeof x;
    getsockname(ofd, (struct sockaddr *)&x, &xl);
    odd_port = ntohs(x.sin_port);
    pthread_t t;
    pthread_create(&t, NULL, odd_udp_thread, (void *)(intptr_t)ofd);
    pthread_detach(t);
    set_flow("127.1.8.3", "127.0.0.1", odd_port, PB_ACT_DIRECT, 0);
    set_flow("127.1.8.4", "127.0.0.1", odd_port, PB_ACT_PROXY, 1);
    char b[64], ip[32];
    uint16_t sp;
    const char *fl[2] = { "127.1.8.3", "127.1.8.4" };
    const char *nm[2] = { "DIRECT", "SOCKS5" };
    for (int k = 0; k < 2; k++) {
        udp_send_flow(c, fl[k], "Bport");
        int n = udp_recv(c, b, sizeof b, ip, &sp);
        CHECK(n == 5 && !strcmp(ip, fl[k]), "%s: reply from a different port of the same host delivered from the flow address", nm[k]);
        udp_send_flow(c, fl[k], "Chost");
        n = udp_recv_neg(c, b, sizeof b, ip, &sp);
        CHECK(n < 0, "%s: reply from a different host dropped", nm[k]);
    }
    close(c);
}

static void init_world(void)
{
    struct srvcfg c = { 0 };
    g_echo = srv_start(echo_handler, NULL);
    g_s5 = srv_start(socks_handler, &c);
    struct srvcfg ca = { .auth = true }; strcpy(ca.user, "alice"); strcpy(ca.pass, "secret");
    g_s5auth = srv_start(socks_handler, &ca);
    g_http = srv_start(http_handler, &c);
    struct srvcfg ch = { .auth = true }; strcpy(ch.pass, "YWxpY2U6c2VjcmV0");
    g_httpauth = srv_start(http_handler, &ch);
    struct srvcfg cl = { .leftover = true };
    g_httpleft = srv_start(http_handler, &cl);
    struct srvcfg cs = { .silent = true };
    g_silent = srv_start(socks_handler, &cs);
    g_sink = srv_start(sink_handler, NULL);
    g_uecho1 = udpecho_start();
    g_uecho2 = udpecho_start();

    set_proxy(1, PROXY_TYPE_SOCKS5, g_s5->port, NULL, NULL);
    set_proxy(2, PROXY_TYPE_SOCKS5, g_s5auth->port, "alice", "secret");
    set_proxy(3, PROXY_TYPE_HTTP, g_http->port, NULL, NULL);
    set_proxy(4, PROXY_TYPE_HTTP, g_httpauth->port, "alice", "secret");
    set_proxy(5, PROXY_TYPE_HTTP, g_httpleft->port, NULL, NULL);
    g_default_px = 1;
}

// The port-53 tests run in a forked child (before any thread exists) so that a private network namespace never
// affects the main process. Status/counters come back through shared memory.
static void run_dns_child(void)
{
    arm_watchdog();
    if (!isolate_for_port53()) { g_shared->status = 3; _exit(0); }
    init_world();
    if (relay_up(300, 60, 0, 5) != 0) { printf("FAIL  DNS child: pb_relay_start\n"); g_shared->fail = 1; g_shared->status = 1; _exit(0); }
    RUN(test_dns);
    pb_relay_stop();
    g_shared->pass = g_pass;
    g_shared->fail = g_fail;
    g_shared->status = 1;
    fflush(stdout);
    _exit(0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!loopback_ok()) {
        fprintf(stderr, "FATAL: 127.0.0.1 loopback is not usable in this environment (bind+connect failed)\n");
        return 2;
    }
    g_shared = mmap(NULL, sizeof *g_shared, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_shared == MAP_FAILED) { perror("mmap"); return 2; }
    memset(g_shared, 0, sizeof *g_shared);
    g_cur = "dns child";
    pid_t pid = fork();
    if (pid == 0) run_dns_child();
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) < 0) st = -1;
    arm_watchdog();
    if (g_shared->status == 1 && WIFEXITED(st) && WEXITSTATUS(st) == 0) {
        g_pass += g_shared->pass;
        g_fail += g_shared->fail;
    } else if (g_shared->status == 3) {
        printf("SKIP  DNS tests: cannot isolate a private network namespace with port 53 here\n");
    } else {
        g_fail++;
        printf("FAIL  DNS child crashed or timed out (wait status 0x%x)\n", st);
    }

    init_world();
    g_cur = "pb_relay_start";
    CHECK(relay_up(300, 60, 0, 5) == 0, "pb_relay_start");
    RUN(test_tcp_basic);
    RUN(test_tcp_identity);
    RUN(test_tcp_bad_proxy);
    RUN(test_tcp_halfclose);
    RUN(test_sigpipe);
    RUN(test_udp);
    RUN(test_udp_session_cap);
    RUN(test_flows);
    RUN(test_proxy_process_loop);
    RUN(test_proxy_helper);
    RUN(test_udp_odd);
    RUN(test_hostname);
    RUN(test_latency);
    RUN(test_tcp_large);
    RUN(test_throughput);
    RUN(test_perf);
    RUN(test_tcp_10k);
    RUN(test_churn);
    RUN(test_tcp_idle);
    RUN(test_tcp_cap);
    RUN(test_handshake_timeout);
    RUN(test_udp_idle);
    RUN(test_start_stop);
    pb_relay_stop();
    printf("\nRESULT: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
