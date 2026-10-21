// Userspace relay for the eBPF backend: TCP (SOCKS5 / HTTP CONNECT / DIRECT) and UDP (SOCKS5 UDP ASSOCIATE / DIRECT).
// Every conn/session is owned by exactly one epoll thread; handshake workers hand finished objects over through queues.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include "pb_internal.h"

#define SCRATCH_SZ      65536
#define HDR_MAX         8192
#define WORKERS_MIN     8       // handshake workers: a few always, more while handshakes pile up, extras leave after a pause
#define WORKERS_MAX     64
#define WORKER_IDLE_S   20
#define UPSTREAM_CAP    48      // handshakes in flight per upstream, so a dead proxy cannot take every worker
#define MAX_DATA        8
#define PIPE_SZ         (1 << 20)
#define JOBQ_MAX        4096    // handshake queue; excess accepts are shed with a log
#define MAX_UDP_SESS    4096
#define MAX_FLOWS       64
#define UDP_QMAX        32
#define UDP_QBYTES      (256 * 1024)
#define UDP_MAXDG       65536
#define UDP_BATCH       16
#define FLOW_TTL_MS     1000
#define DC_SIZE         1024
#define UFLOWS_MAX      200
#define UDP_LIVE_MS     30000
#define SESS_BUCKETS    256
#define DIRECT_ID       0xFFFFFFFFu

static char TAG_STOP, TAG_WAKE, TAG_UDP, TAG_TIMER;

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void close_fd(int *fd)
{
    if (*fd >= 0) { close(*fd); *fd = -1; }
}

static void fmt_ip(int family, const uint8_t *addr16, char *out, size_t n)
{
    if (family == AF_INET) inet_ntop(AF_INET, addr16 + 12, out, (socklen_t)n);
    else inet_ntop(AF_INET6, addr16, out, (socklen_t)n);
}

static void orig_str(const struct pb_orig *o, char *out, size_t n)
{
    char ip[INET6_ADDRSTRLEN];
    fmt_ip(o->family, o->addr, ip, sizeof ip);
    snprintf(out, n, "%s:%u", ip, o->port);
}

static socklen_t orig_to_sa(const struct pb_orig *o, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof *ss);
    if (o->family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(o->port);
        memcpy(&a->sin_addr, o->addr + 12, 4);
        return sizeof *a;
    }
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
    a->sin6_family = AF_INET6;
    a->sin6_port = htons(o->port);
    memcpy(&a->sin6_addr, o->addr, 16);
    return sizeof *a;
}

// Waits for fd readiness. 0 = ready (or error/hup: the next I/O call reports it), -1 = timeout, -2 = stop requested.
static int wait_fd(int fd, short ev, int64_t deadline, int stopfd)
{
    for (;;) {
        int64_t rem = deadline - now_ms();
        if (rem <= 0) return -1;
        struct pollfd p[2] = { { .fd = fd, .events = ev }, { .fd = stopfd, .events = POLLIN } };
        int r = poll(p, stopfd >= 0 ? 2 : 1, rem > 60000 ? 60000 : (int)rem);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) continue;
        if (stopfd >= 0 && p[1].revents) return -2;
        if (p[0].revents) return 0;
    }
}

struct io {
    int     fd;
    int64_t dl;
    int     stopfd;
    char    err[200];
};

static void seterr(struct io *x, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void seterr(struct io *x, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(x->err, sizeof x->err, fmt, ap);
    va_end(ap);
}

static void io_waitfail(struct io *x, int w)
{
    seterr(x, w == -1 ? "timed out" : "relay stopping");
}

static int io_send(struct io *x, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = send(x->fd, p, n, MSG_NOSIGNAL);
        if (r > 0) { p += r; n -= (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && errno == EAGAIN) {
            int w = wait_fd(x->fd, POLLOUT, x->dl, x->stopfd);
            if (w) { io_waitfail(x, w); return -1; }
            continue;
        }
        seterr(x, "send failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static ssize_t io_recv(struct io *x, void *buf, size_t n)
{
    for (;;) {
        ssize_t r = recv(x->fd, buf, n, 0);
        if (r > 0) return r;
        if (r == 0) { seterr(x, "connection closed by peer during handshake"); return -1; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN) {
            int w = wait_fd(x->fd, POLLIN, x->dl, x->stopfd);
            if (w) { io_waitfail(x, w); return -1; }
            continue;
        }
        seterr(x, "recv failed: %s", strerror(errno));
        return -1;
    }
}

static int io_recv_exact(struct io *x, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = io_recv(x, p, n);
        if (r < 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static void tune_sock(int fd)
{
    int one = 1, idle = 60, intvl = 15, cnt = 4;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
}

static int connect_addr(const struct sockaddr *sa, socklen_t len, int64_t dl, int stopfd, int *eno)
{
    int fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { *eno = errno; return -1; }
    tune_sock(fd);
    if (connect(fd, sa, len) < 0) {
        if (errno != EINPROGRESS) { *eno = errno; close(fd); return -1; }
        int w = wait_fd(fd, POLLOUT, dl, stopfd);
        if (w) { *eno = w == -1 ? ETIMEDOUT : ECANCELED; close(fd); return -1; }
        int e = 0;
        socklen_t el = sizeof e;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el);
        if (e) { *eno = e; close(fd); return -1; }
    }
    return fd;
}

// Hostname resolution (IPv4): at most RES_MAX_THREADS short-lived detached lookups, deadline-bounded for the waiter,
// results cached (fresh for 60 s; last good answer reused for up to 10 min when re-resolution fails).
#define RES_MAX_THREADS 4
#define RES_DEADLINE_MS 5000
#define RES_TTL_MS      60000
#define RES_STALE_MS    600000
#define RES_CACHE_N     64

struct resreq {
    struct resreq *next;
    char           name[256];
    int            refs;
    bool           done;
    int            gai;
    struct in_addr addr;
    pthread_cond_t cv;
};
struct rescache { char name[256]; struct in_addr addr; int64_t when; bool used; };

static pthread_mutex_t res_mu = PTHREAD_MUTEX_INITIALIZER;
static struct resreq *res_inflight;
static int res_threads;
static struct rescache res_cache[RES_CACHE_N];

static struct rescache *res_cache_find(const char *name)      // res_mu held
{
    for (int i = 0; i < RES_CACHE_N; i++) if (res_cache[i].used && !strcmp(res_cache[i].name, name)) return &res_cache[i];
    return NULL;
}

static void res_unref(struct resreq *r)                       // res_mu held
{
    if (--r->refs == 0) { pthread_cond_destroy(&r->cv); free(r); }
}

static bool block_sigpipe(void);

static void *res_thread(void *arg)
{
    struct resreq *r = arg;
    block_sigpipe();
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int gr = getaddrinfo(r->name, NULL, &hints, &res);
    pthread_mutex_lock(&res_mu);
    if (gr == 0 && res && res->ai_family == AF_INET) {
        r->addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        struct rescache *c = res_cache_find(r->name);
        if (!c) {
            c = &res_cache[0];
            for (int i = 0; i < RES_CACHE_N; i++) {
                if (!res_cache[i].used) { c = &res_cache[i]; break; }
                if (res_cache[i].when < c->when) c = &res_cache[i];
            }
        }
        snprintf(c->name, sizeof c->name, "%s", r->name);
        c->addr = r->addr; c->when = now_ms(); c->used = true;
    } else {
        r->gai = gr ? gr : EAI_NONAME;
    }
    r->done = true;
    for (struct resreq **pp = &res_inflight; *pp; pp = &(*pp)->next)
        if (*pp == r) { *pp = r->next; break; }
    res_threads--;
    pthread_cond_broadcast(&r->cv);
    res_unref(r);
    pthread_mutex_unlock(&res_mu);
    if (res) freeaddrinfo(res);
    return NULL;
}

static int resolve_v4(const char *name, int64_t dl, int stopfd, struct in_addr *out, char *err, size_t errn)
{
    int64_t limit = now_ms() + RES_DEADLINE_MS;
    if (dl > limit) dl = limit;
    pthread_mutex_lock(&res_mu);
    struct rescache *c = res_cache_find(name);
    if (c && now_ms() - c->when < RES_TTL_MS) { *out = c->addr; pthread_mutex_unlock(&res_mu); return 0; }
    struct resreq *r;
    for (r = res_inflight; r; r = r->next) if (!strcmp(r->name, name)) break;
    const char *why = NULL;
    if (!r) {
        if (res_threads >= RES_MAX_THREADS) {
            why = "resolver busy";
        } else {
            r = calloc(1, sizeof *r);
            pthread_condattr_t ca;
            pthread_condattr_init(&ca);
            pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
            if (r) pthread_cond_init(&r->cv, &ca);
            pthread_condattr_destroy(&ca);
            pthread_t th;
            pthread_attr_t at;
            pthread_attr_init(&at);
            pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
            pthread_attr_setstacksize(&at, 256 * 1024);
            if (r) {
                snprintf(r->name, sizeof r->name, "%s", name);
                r->refs = 2;
                r->next = res_inflight; res_inflight = r;
                res_threads++;
                if (pthread_create(&th, &at, res_thread, r) != 0) {
                    res_inflight = r->next; res_threads--; r->refs = 1;
                    res_unref(r); r = NULL; why = "cannot start resolver thread";
                }
            } else why = "out of memory";
            pthread_attr_destroy(&at);
        }
    } else {
        r->refs++;
    }
    int rc = -1;
    if (r) {
        while (!r->done) {
            int64_t rem = dl - now_ms();
            if (rem <= 0) { why = "timed out"; break; }
            struct pollfd sp = { .fd = stopfd, .events = POLLIN };
            if (stopfd >= 0 && poll(&sp, 1, 0) > 0) { why = "relay stopping"; break; }
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            int64_t ms = rem < 50 ? rem : 50;
            ts.tv_nsec += ms * 1000000;
            ts.tv_sec += ts.tv_nsec / 1000000000; ts.tv_nsec %= 1000000000;
            pthread_cond_timedwait(&r->cv, &res_mu, &ts);
        }
        if (r->done && !r->gai) { *out = r->addr; rc = 0; }
        else if (r->done) { snprintf(err, errn, "cannot resolve '%s': %s", name, gai_strerror(r->gai)); why = NULL; }
        res_unref(r);
    }
    if (rc != 0) {
        c = res_cache_find(name);
        if (c && now_ms() - c->when < RES_STALE_MS) { *out = c->addr; rc = 0; }
    }
    pthread_mutex_unlock(&res_mu);
    if (rc != 0 && why) snprintf(err, errn, "cannot resolve '%s': %s", name, why);
    return rc;
}

// Resolves and connects to the proxy; on failure writes a readable reason to err.
static int connect_host(const char *host, uint16_t port, int64_t dl, int stopfd, char *err, size_t errn)
{
    struct sockaddr_storage ss[1];
    socklen_t sl[1];
    int n = 0;
    struct in_addr a4;
    struct in6_addr a6;
    memset(ss, 0, sizeof ss);
    if (inet_pton(AF_INET, host, &a4) == 1 || (inet_pton(AF_INET6, host, &a6) != 1 && resolve_v4(host, dl, stopfd, &a4, err, errn) == 0)) {
        struct sockaddr_in *s = (struct sockaddr_in *)&ss[0];
        s->sin_family = AF_INET; s->sin_port = htons(port); s->sin_addr = a4;
        sl[0] = sizeof *s; n = 1;
    } else if (inet_pton(AF_INET6, host, &a6) == 1) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss[0];
        s->sin6_family = AF_INET6; s->sin6_port = htons(port); s->sin6_addr = a6;
        sl[0] = sizeof *s; n = 1;
    } else {
        return -1;
    }
    int eno = ETIMEDOUT;
    for (int i = 0; i < n; i++) {
        int64_t rem = dl - now_ms();
        int64_t d = (i + 1 < n && rem > 2) ? now_ms() + rem / 2 : dl;
        int fd = connect_addr((struct sockaddr *)&ss[i], sl[i], d, stopfd, &eno);
        if (fd >= 0) return fd;
        if (eno == ECANCELED) break;
    }
    snprintf(err, errn, "connect to %s:%u failed: %s", host, port, strerror(eno));
    return -1;
}

struct s5dst { uint8_t atyp; uint8_t addr[16]; char host[256]; uint16_t port; };
struct s5bnd { uint8_t atyp; uint8_t addr[16]; uint16_t port; };

static const char *socks5_rep_str(int rep)
{
    switch (rep) {
    case 1: return "general SOCKS server failure";
    case 2: return "connection not allowed by ruleset";
    case 3: return "network unreachable";
    case 4: return "host unreachable";
    case 5: return "connection refused by target";
    case 6: return "TTL expired";
    case 7: return "command not supported";
    case 8: return "address type not supported";
    default: return "unknown error";
    }
}

static void s5dst_from_orig(struct s5dst *d, const struct pb_orig *o)
{
    memset(d, 0, sizeof *d);
    d->port = o->port;
    if (o->family == AF_INET) { d->atyp = 1; memcpy(d->addr, o->addr + 12, 4); }
    else { d->atyp = 4; memcpy(d->addr, o->addr, 16); }
}

static int socks5_request(struct io *x, const struct pb_proxy *p, uint8_t cmd, const struct s5dst *d, struct s5bnd *b)
{
    bool auth = p->user[0] != 0;
    uint8_t g[4] = { 5, auth ? 2 : 1, 0, 2 };
    if (io_send(x, g, auth ? 4 : 3)) return -1;
    uint8_t r[2];
    if (io_recv_exact(x, r, 2)) return -1;
    if (r[0] != 5) { seterr(x, "not a SOCKS5 server (bad greeting reply 0x%02x)", r[0]); return -1; }
    if (r[1] == 0xFF) { seterr(x, "SOCKS5 proxy rejected all auth methods (credentials required or not accepted)"); return -1; }
    if (r[1] == 2) {
        size_t ul = strlen(p->user), pl = strlen(p->pass);
        if (!auth) { seterr(x, "SOCKS5 proxy requires username/password but none configured"); return -1; }
        if (ul > 255 || pl > 255) { seterr(x, "SOCKS5 credentials too long"); return -1; }
        uint8_t ab[3 + 255 + 255];
        size_t o = 0;
        ab[o++] = 1; ab[o++] = (uint8_t)ul; memcpy(ab + o, p->user, ul); o += ul;
        ab[o++] = (uint8_t)pl; memcpy(ab + o, p->pass, pl); o += pl;
        int sent = io_send(x, ab, o);
        explicit_bzero(ab, sizeof ab);
        if (sent) return -1;
        if (io_recv_exact(x, r, 2)) return -1;
        if (r[1] != 0) { seterr(x, "SOCKS5 authentication failed (wrong username or password)"); return -1; }
    } else if (r[1] != 0) {
        seterr(x, "SOCKS5 proxy selected unsupported auth method 0x%02x", r[1]);
        return -1;
    }
    uint8_t rq[4 + 1 + 255 + 2];
    size_t o = 0;
    rq[o++] = 5; rq[o++] = cmd; rq[o++] = 0; rq[o++] = d->atyp;
    if (d->atyp == 1) { memcpy(rq + o, d->addr, 4); o += 4; }
    else if (d->atyp == 4) { memcpy(rq + o, d->addr, 16); o += 16; }
    else {
        size_t hl = strlen(d->host);
        if (hl == 0 || hl > 255) { seterr(x, "invalid target host name"); return -1; }
        rq[o++] = (uint8_t)hl; memcpy(rq + o, d->host, hl); o += hl;
    }
    rq[o++] = (uint8_t)(d->port >> 8); rq[o++] = (uint8_t)d->port;
    if (io_send(x, rq, o)) return -1;
    uint8_t h[4];
    if (io_recv_exact(x, h, 4)) return -1;
    if (h[0] != 5) { seterr(x, "bad SOCKS5 reply version 0x%02x", h[0]); return -1; }
    if (h[1] != 0) { seterr(x, "SOCKS5 request failed: %s (code %u)", socks5_rep_str(h[1]), h[1]); return -1; }
    struct s5bnd tmp;
    if (!b) b = &tmp;
    memset(b, 0, sizeof *b);
    b->atyp = h[3];
    size_t al;
    if (h[3] == 1) al = 4;
    else if (h[3] == 4) al = 16;
    else if (h[3] == 3) {
        uint8_t l;
        if (io_recv_exact(x, &l, 1)) return -1;
        uint8_t skip[256];
        if (io_recv_exact(x, skip, l)) return -1;
        al = 0;
    } else { seterr(x, "SOCKS5 reply has unknown address type %u", h[3]); return -1; }
    if (al && io_recv_exact(x, b->addr, al)) return -1;
    uint8_t pt[2];
    if (io_recv_exact(x, pt, 2)) return -1;
    b->port = (uint16_t)(pt[0] << 8 | pt[1]);
    return 0;
}

static void b64(const char *in, size_t n, char *out)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = (uint8_t)in[i] << 16 | (uint8_t)in[i + 1] << 8 | (uint8_t)in[i + 2];
        out[o++] = t[v >> 18]; out[o++] = t[(v >> 12) & 63]; out[o++] = t[(v >> 6) & 63]; out[o++] = t[v & 63];
    }
    if (i < n) {
        uint32_t v = (uint8_t)in[i] << 16 | (i + 1 < n ? (uint8_t)in[i + 1] << 8 : 0);
        out[o++] = t[v >> 18]; out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < n ? t[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
}

static int http_connect(struct io *x, const struct pb_proxy *p, const char *host, uint16_t port, uint8_t *left, size_t *leftn)
{
    char hp[300];
    snprintf(hp, sizeof hp, strchr(host, ':') ? "[%s]:%u" : "%s:%u", host, port);
    char req[1024 + 700];
    int n = snprintf(req, sizeof req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hp, hp);
    if (p->user[0]) {
        char cred[520], enc[720];
        int cl = snprintf(cred, sizeof cred, "%s:%s", p->user, p->pass);
        if (cl < 0 || cl >= (int)sizeof cred) { seterr(x, "HTTP proxy credentials too long"); return -1; }
        b64(cred, (size_t)cl, enc);
        n += snprintf(req + n, sizeof req - (size_t)n, "Proxy-Authorization: Basic %s\r\n", enc);
        explicit_bzero(cred, sizeof cred);
        explicit_bzero(enc, sizeof enc);
    }
    n += snprintf(req + n, sizeof req - (size_t)n, "\r\n");
    int sent = io_send(x, req, (size_t)n);
    explicit_bzero(req, sizeof req);
    if (sent) return -1;

    uint8_t buf[HDR_MAX];
    size_t tot = 0, hend = 0;
    while (!hend) {
        if (tot >= sizeof buf) { seterr(x, "HTTP proxy response headers too large"); return -1; }
        ssize_t r = io_recv(x, buf + tot, sizeof buf - tot);
        if (r < 0) return -1;
        size_t from = tot >= 3 ? tot - 3 : 0;
        tot += (size_t)r;
        for (size_t i = from; i + 4 <= tot; i++)
            if (!memcmp(buf + i, "\r\n\r\n", 4)) { hend = i + 4; break; }
    }
    int code = 0;
    if (hend >= 12 && !memcmp(buf, "HTTP/", 5)) {
        const uint8_t *sp = memchr(buf, ' ', hend);
        if (sp && sp + 4 <= buf + hend) code = (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');
    }
    if (code < 200 || code > 299) {
        if (code == 0) seterr(x, "invalid HTTP proxy response");
        else if (code == 407) seterr(x, "HTTP proxy authentication required (407): check username/password");
        else if (code == 403) seterr(x, "HTTP proxy forbids this connection (403)");
        else if (code >= 500) seterr(x, "HTTP proxy or upstream error (%d)", code);
        else seterr(x, "HTTP proxy refused CONNECT (%d)", code);
        return -1;
    }
    *leftn = tot - hend;
    if (*leftn) memcpy(left, buf + hend, *leftn);
    return 0;
}

struct conn {
    struct conn *prev, *next;
    int      fd[2];
    size_t   off[2], len[2];        // pend[d]: unsent tail of bytes read from fd[d] (heap, freed once drained)
    uint8_t *pend[2];
    bool     dns;                   // original destination port 53: upstream->client is parsed as TCP-DNS
    bool     doff;                  // stopped observing (malformed stream)
    uint8_t *dbuf;
    size_t   dhave, dcap;
    uint32_t mask[2];
    bool     eof[2], shut[2], dead;
    int64_t  last;
    // what GetFlows reports
    uint64_t id, bytes[2];
    int64_t  t0;
    uint32_t pid;
    uint16_t port, proxy_id;
    uint8_t  family, addr[16];
};

static void conn_bufs_free(struct conn *c)
{
    free(c->pend[0]); free(c->pend[1]); free(c->dbuf);
    c->pend[0] = c->pend[1] = c->dbuf = NULL;
}

struct dthread {
    pthread_t       th;
    bool            started;
    int             ep, wake;
    pthread_mutex_t mu;
    struct conn    *inq_head, *inq_tail;
    struct conn    *conns;
    struct conn    *grave;
    uint8_t        *scratch;
    int             pfd[2];         // reusable splice pipe; always empty between connections
    bool            nosplice;
    atomic_int      load;
};

enum { J_TCP = 1, J_UDP };
struct sess;
struct job {
    struct job *next;
    int         kind;
    unsigned    key;                // upstream the handshake talks to (0 = not known before the decision)
    int         fd;
    struct pb_orig o;
    struct sess *s;
};

struct flowent { uint8_t addr[16]; uint16_t port; uint32_t ip_be; int64_t last; };
struct pkt { size_t len; uint8_t d[]; };

enum { SK_DIRECT = 1, SK_SOCKS5, SK_DROP };
enum { ST_SETUP = 1, ST_READY, ST_FAILED };
struct ref { struct sess *s; int which; };

struct sess {
    struct sess *hnext, *prev, *next, *dnext;
    struct sockaddr_in cli;
    uint32_t id, flow_be;            // id = proxy id or DIRECT_ID; flow_be only for DIRECT sessions
    uint64_t sid;
    int      kind, state;
    int      up_fd, ctl_fd;
    bool     connected;              // DIRECT: v6 sockets are connected; v4 are not (replies from any port of the host are accepted)
    struct sockaddr_storage dst;
    socklen_t dstlen;
    uint16_t dport;
    bool     dead, ok, warned;
    uint32_t pid;                    // process the session belongs to
    int64_t  last, fail_until;
    struct pb_proxy proxy;
    char     err[700];
    struct ref ref[2];
    int      nflows;
    struct flowent flows[MAX_FLOWS];
    struct pkt *q[UDP_QMAX];
    int      nq;
    size_t   qbytes;
};

struct dce {
    bool used;
    struct sockaddr_in cli;
    uint32_t flow_be, pid;
    struct pb_orig o;
    int action, fidx;
    int64_t looked, last, t0;
    uint64_t sid, id, sent, recv;
};

static struct {
    pthread_mutex_t life;
    bool       running;
    struct pb_relay_cfg cfg;
    int        lfd, ufd, stopfd, tmfd, uep, uwake;
    atomic_bool stopping;
    atomic_int nconn;
    atomic_uint rr;
    atomic_ullong flow_id;
    uint16_t   tcp_port, udp_port;

    pthread_t  acceptor; bool acc_started;
    int        nworkers, nidle;
    int        busy[256];                // handshakes in flight per upstream key
    pthread_cond_t wdone;
    struct dthread data[MAX_DATA];
    int        ndata;
    pthread_t  udpth; bool udp_started;

    pthread_mutex_t jmu;
    pthread_cond_t  jcv;
    struct job *jhead, *jtail;
    int         jcount;

    pthread_mutex_t dmu;
    struct sess *done;

    struct sess *sess_head;
    struct sess *buckets[SESS_BUCKETS];
    int          nsess;
    struct sess *sgrave;
    struct dce  *dc;
    pthread_mutex_t fmu;                  // guards uflows, the UDP side of GetFlows (published by the UDP thread once a second)
    struct pb_flow_info uflows[UFLOWS_MAX]; int nuflows;
    uint8_t     *rxbuf;
    int64_t      drop_count, drop_logged;
    uint64_t     next_sid;
    struct mmsghdr *mm;
    struct iovec    *mmiov;
    struct sockaddr_in *mmname;
    char         (*mmctl)[CMSG_SPACE(sizeof(struct in_pktinfo))];
} R = { .life = PTHREAD_MUTEX_INITIALIZER, .jmu = PTHREAD_MUTEX_INITIALIZER, .jcv = PTHREAD_COND_INITIALIZER, .wdone = PTHREAD_COND_INITIALIZER,
        .dmu = PTHREAD_MUTEX_INITIALIZER, .fmu = PTHREAD_MUTEX_INITIALIZER, .lfd = -1, .ufd = -1, .stopfd = -1, .tmfd = -1, .uep = -1, .uwake = -1 };

static void proxy_desc(const struct pb_proxy *p, char *out, size_t n)
{
    snprintf(out, n, "%s %s:%u", p->type == PROXY_TYPE_SOCKS5 ? "SOCKS5" : "HTTP", p->host, p->port);
}

static void *worker_main(void *arg);

// splice() has no MSG_NOSIGNAL: writing into a connection the peer already reset raises SIGPIPE, whose default action ends
// the whole process (the CLI or GUI that hosts this library). Every relay thread blocks the signal for its lifetime, so the
// write fails with EPIPE and the connection is closed by the ordinary error path. The embedding application's own signal
// handling is not touched. Returns false when the mask could not be set.
static bool block_sigpipe(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    return pthread_sigmask(SIG_BLOCK, &set, NULL) == 0;
}

// Caller holds R.jmu.
static void worker_spawn_locked(void)
{
    pthread_attr_t at;
    pthread_t th;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 512 * 1024);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    R.nworkers++;
    if (pthread_create(&th, &at, worker_main, NULL) != 0) R.nworkers--;
    pthread_attr_destroy(&at);
}

static int job_push(int kind, int fd, const struct pb_orig *o, struct sess *s)
{
    struct job *j = calloc(1, sizeof *j);
    if (!j) return -1;
    j->kind = kind; j->fd = fd; j->s = s;
    if (o) j->o = *o;
    if (kind == J_TCP && o && o->action == PB_ACT_PROXY) j->key = 1 + o->proxy_id % 255u;
    else if (kind != J_TCP && s) j->key = 1 + s->proxy.id % 255u;
    pthread_mutex_lock(&R.jmu);
    if (R.jcount >= JOBQ_MAX || atomic_load(&R.stopping)) {
        pthread_mutex_unlock(&R.jmu);
        free(j);
        return -1;
    }
    if (R.jtail) R.jtail->next = j; else R.jhead = j;
    R.jtail = j;
    R.jcount++;
    if (R.jcount > R.nidle && R.nworkers < WORKERS_MAX && R.busy[j->key] < UPSTREAM_CAP) worker_spawn_locked();
    pthread_cond_signal(&R.jcv);
    pthread_mutex_unlock(&R.jmu);
    return 0;
}

static void conn_handoff(int cfd, int ufd, const uint8_t *left, size_t leftn, bool dns, const struct pb_orig *o, uint32_t proxy_id)
{
    struct conn *c = calloc(1, sizeof *c);
    if (!c) { close(cfd); close(ufd); atomic_fetch_sub(&R.nconn, 1); return; }
    c->fd[0] = cfd; c->fd[1] = ufd;
    c->dns = dns;
    c->id = atomic_fetch_add(&R.flow_id, 1) + 1;
    c->t0 = now_ms();
    c->pid = o->pid; c->port = o->port; c->proxy_id = (uint16_t)proxy_id; c->family = o->family;
    memcpy(c->addr, o->addr, 16);
    if (leftn) {
        uint8_t *m = malloc(leftn);
        if (!m) { close(cfd); close(ufd); free(c); atomic_fetch_sub(&R.nconn, 1); return; }
        memcpy(m, left, leftn);
        if (dns) { c->dbuf = m; c->dhave = c->dcap = leftn; }     // must pass through the DNS parser
        else { c->pend[1] = m; c->len[1] = leftn; }
    }
    unsigned start = atomic_fetch_add(&R.rr, 1);
    struct dthread *t = &R.data[start % R.ndata];
    for (int i = 1; i < R.ndata; i++) {
        struct dthread *u = &R.data[(start + i) % R.ndata];
        if (atomic_load(&u->load) < atomic_load(&t->load)) t = u;
    }
    atomic_fetch_add(&t->load, 1);
    pthread_mutex_lock(&t->mu);
    if (atomic_load(&R.stopping)) {
        pthread_mutex_unlock(&t->mu);
        atomic_fetch_sub(&t->load, 1);
        close(cfd); close(ufd); conn_bufs_free(c); free(c);
        atomic_fetch_sub(&R.nconn, 1);
        return;
    }
    if (t->inq_tail) t->inq_tail->next = c; else t->inq_head = c;
    t->inq_tail = c;
    pthread_mutex_unlock(&t->mu);
    eventfd_write(t->wake, 1);
}

static void tcp_job_run(struct job *j)
{
    struct pb_orig *o = &j->o;
    int cfd = j->fd, up = -1, action = o->action;
    uint32_t pid = o->proxy_id;
    int64_t dl = now_ms() + (int64_t)R.cfg.handshake_timeout_s * 1000;
    char dst[80], err[1024] = "", desc[300];
    uint8_t left[HDR_MAX];
    size_t leftn = 0;
    orig_str(o, dst, sizeof dst);

    if (action == PB_ACT_DECIDE) {
        struct pb_decision d;
        pb_core_decide(o, &d);
        action = d.action; pid = d.proxy_id;
    }
    if (action == PB_ACT_PROXY && pb_core_is_proxy_process(o->pid, pid)) action = PB_ACT_DIRECT;     // a local proxy must not loop through itself
    if (action == PB_ACT_DIRECT) {
        pb_core_flow_event(o, PB_ACT_DIRECT);
        struct sockaddr_storage ss;
        socklen_t sl = orig_to_sa(o, &ss);
        int eno = 0;
        up = connect_addr((struct sockaddr *)&ss, sl, dl, R.stopfd, &eno);
        if (up < 0) snprintf(err, sizeof err, "direct connect to %s failed: %s", dst, strerror(eno));
    } else if (action == PB_ACT_PROXY) {
        struct pb_proxy px;
        if (pb_core_get_proxy(pid, &px) != 0) {
            pb_core_flow_event(o, PB_ACT_PROXY);
            snprintf(err, sizeof err, "no proxy configured (id %u) for %s", pid, dst);
        } else {
            proxy_desc(&px, desc, sizeof desc);
            pb_core_flow_event(o, PB_ACT_PROXY);
            char cerr[200];
            up = connect_host(px.host, px.port, dl, R.stopfd, cerr, sizeof cerr);
            if (up < 0) {
                snprintf(err, sizeof err, "proxy %s: %s", desc, cerr);
            } else {
                struct io x = { .fd = up, .dl = dl, .stopfd = R.stopfd };
                int rc;
                char hn[256];
                bool named = px.send_domain && pb_core_name_for(o, hn, sizeof hn) == 0;
                if (px.type == PROXY_TYPE_SOCKS5) {
                    struct s5dst d;
                    s5dst_from_orig(&d, o);
                    if (named) { d.atyp = 3; snprintf(d.host, sizeof d.host, "%s", hn); }
                    rc = socks5_request(&x, &px, 1, &d, NULL);
                } else {
                    char ip[INET6_ADDRSTRLEN];
                    fmt_ip(o->family, o->addr, ip, sizeof ip);
                    rc = http_connect(&x, &px, named ? hn : ip, o->port, left, &leftn);
                }
                if (rc) {
                    snprintf(err, sizeof err, "proxy %s -> %s: %s", desc, dst, x.err);
                    close(up); up = -1;
                }
            }
        }
    } else {
        pb_core_flow_event(o, PB_ACT_BLOCK);
        setsockopt(cfd, SOL_SOCKET, SO_LINGER, &(struct linger){ 1, 0 }, sizeof(struct linger));
        close(cfd);
        atomic_fetch_sub(&R.nconn, 1);
        return;
    }
    if (up < 0) {
        pb_core_log("relay: %s", err);
        close(cfd);
        atomic_fetch_sub(&R.nconn, 1);
        return;
    }
    conn_handoff(cfd, up, left, leftn, o->port == 53, o, action == PB_ACT_PROXY ? pid : 0);
}

static void udp_job_run(struct sess *s)
{
    int64_t dl = now_ms() + (int64_t)R.cfg.handshake_timeout_s * 1000;
    char cerr[200], desc[300];
    int ctl = -1, up = -1;
    proxy_desc(&s->proxy, desc, sizeof desc);
    s->ok = false;
    ctl = connect_host(s->proxy.host, s->proxy.port, dl, R.stopfd, cerr, sizeof cerr);
    if (ctl < 0) { snprintf(s->err, sizeof s->err, "%s: %s", desc, cerr); goto out; }
    struct io x = { .fd = ctl, .dl = dl, .stopfd = R.stopfd };
    struct s5dst d;
    struct s5bnd b;
    memset(&d, 0, sizeof d);
    d.atyp = 1;
    if (socks5_request(&x, &s->proxy, 3, &d, &b)) { snprintf(s->err, sizeof s->err, "%s UDP ASSOCIATE: %s", desc, x.err); goto out; }
    if (b.atyp == 3) { snprintf(s->err, sizeof s->err, "%s: UDP relay address is a domain name (unsupported)", desc); goto out; }
    struct sockaddr_storage ra;
    socklen_t rl;
    memset(&ra, 0, sizeof ra);
    static const uint8_t zero[16];
    bool unspec = !memcmp(b.addr, zero, b.atyp == 1 ? 4 : 16);
    if (unspec) {                       // use the address we reached the proxy at
        rl = sizeof ra;
        if (getpeername(ctl, (struct sockaddr *)&ra, &rl) < 0) { snprintf(s->err, sizeof s->err, "%s: getpeername: %s", desc, strerror(errno)); goto out; }
        if (ra.ss_family == AF_INET) ((struct sockaddr_in *)&ra)->sin_port = htons(b.port);
        else ((struct sockaddr_in6 *)&ra)->sin6_port = htons(b.port);
    } else {
        // A relay address inside this host is only plausible when the proxy itself is here; a remote proxy that names
        // 127.x or ::1 would turn the relay into a blind sender towards local services.
        struct sockaddr_storage pa;
        socklen_t pl = sizeof pa;
        bool peer_local = getpeername(ctl, (struct sockaddr *)&pa, &pl) == 0 &&
            ((pa.ss_family == AF_INET && (ntohl(((struct sockaddr_in *)&pa)->sin_addr.s_addr) >> 24) == 127) ||
             (pa.ss_family == AF_INET6 && IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)&pa)->sin6_addr)));
        bool bnd_local = b.atyp == 1 ? b.addr[0] == 127 : IN6_IS_ADDR_LOOPBACK((const struct in6_addr *)b.addr);
        if (bnd_local && !peer_local) { snprintf(s->err, sizeof s->err, "%s: UDP relay address points at this host", desc); goto out; }
        if (b.atyp == 1) {
            struct sockaddr_in *a = (struct sockaddr_in *)&ra;
            a->sin_family = AF_INET; a->sin_port = htons(b.port); memcpy(&a->sin_addr, b.addr, 4);
            rl = sizeof *a;
        } else {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ra;
            a->sin6_family = AF_INET6; a->sin6_port = htons(b.port); memcpy(&a->sin6_addr, b.addr, 16);
            rl = sizeof *a;
        }
    }
    up = socket(ra.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (up < 0 || connect(up, (struct sockaddr *)&ra, rl) < 0) {
        snprintf(s->err, sizeof s->err, "%s: UDP relay socket: %s", desc, strerror(errno));
        goto out;
    }
    s->ctl_fd = ctl; s->up_fd = up; s->ok = true;
    ctl = up = -1;
out:
    close_fd(&ctl);
    close_fd(&up);
    pthread_mutex_lock(&R.dmu);
    s->dnext = R.done;
    R.done = s;
    pthread_mutex_unlock(&R.dmu);
    eventfd_write(R.uwake, 1);
}

static void *worker_main(void *arg)
{
    (void)arg;
    block_sigpipe();
    pthread_mutex_lock(&R.jmu);
    while (!atomic_load(&R.stopping)) {
        struct job *prev = NULL, *j;
        for (j = R.jhead; j; prev = j, j = j->next)
            if (R.busy[j->key] < UPSTREAM_CAP) break;
        if (j) {
            if (prev) prev->next = j->next; else R.jhead = j->next;
            if (R.jtail == j) R.jtail = prev;
            R.jcount--;
            unsigned key = j->key;
            R.busy[key]++;
            pthread_mutex_unlock(&R.jmu);
            if (j->kind == J_TCP) tcp_job_run(j); else udp_job_run(j->s);
            free(j);
            pthread_mutex_lock(&R.jmu);
            R.busy[key]--;
            pthread_cond_signal(&R.jcv);            // a job held back by this upstream's cap may be able to run now
            continue;
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += WORKER_IDLE_S;
        R.nidle++;
        int rc = pthread_cond_timedwait(&R.jcv, &R.jmu, &ts);
        R.nidle--;
        if (rc == ETIMEDOUT && !R.jhead && R.nworkers > WORKERS_MIN) break;
    }
    R.nworkers--;
    pthread_cond_broadcast(&R.wdone);
    pthread_mutex_unlock(&R.jmu);
    return NULL;
}

static void *acceptor_main(void *arg)
{
    (void)arg;
    block_sigpipe();
    int64_t last_cap_log = 0;
    while (!atomic_load(&R.stopping)) {
        struct pollfd p[2] = { { .fd = R.lfd, .events = POLLIN }, { .fd = R.stopfd, .events = POLLIN } };
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        if (p[1].revents) break;
        for (int i = 0; i < 256; i++) {
            struct sockaddr_in pa;
            socklen_t pl = sizeof pa;
            int fd = accept4(R.lfd, (struct sockaddr *)&pa, &pl, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0) {
                if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
                    pb_core_log("relay: accept: %s, backing off", strerror(errno));
                    struct pollfd s = { .fd = R.stopfd, .events = POLLIN };
                    poll(&s, 1, 200);
                }
                break;
            }
            struct pb_orig o;
            if (pb_core_take_tcp_orig(pa.sin_addr.s_addr, ntohs(pa.sin_port), &o) != 0) {
                static int64_t last_log; static unsigned long unknown;    // anyone can connect to the port: one line per 5 s
                unknown++;
                int64_t t = now_ms();
                if (t - last_log > 5000) {
                    pb_core_log("relay: no original destination for client %s:%u, closing (%lu such connections)", inet_ntoa(pa.sin_addr), ntohs(pa.sin_port), unknown);
                    last_log = t;
                }
                close(fd);
                continue;
            }
            if (atomic_fetch_add(&R.nconn, 1) >= R.cfg.max_tcp_conns) {
                atomic_fetch_sub(&R.nconn, 1);
                int64_t t = now_ms();
                if (t - last_cap_log > 5000) { last_cap_log = t; pb_core_log("relay: connection limit (%d) reached, dropping new connections", R.cfg.max_tcp_conns); }
                close(fd);
                continue;
            }
            if (job_push(J_TCP, fd, &o, NULL) != 0) {
                atomic_fetch_sub(&R.nconn, 1);
                close(fd);
                int64_t t = now_ms();
                if (t - last_cap_log > 5000) { last_cap_log = t; pb_core_log("relay: handshake queue full (%d), shedding new connections", JOBQ_MAX); }
            }
        }
    }
    return NULL;
}

static void pipe_discard(int fd)
{
    char b[4096];
    while (read(fd, b, sizeof b) > 0) {}
}

static int spill_from_pipe(struct conn *c, int d, int pipe_rd, size_t n)
{
    c->pend[d] = malloc(n);
    if (!c->pend[d]) { pipe_discard(pipe_rd); return -1; }
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(pipe_rd, c->pend[d] + got, n - got);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; break; }
        got += (size_t)r;
    }
    pipe_discard(pipe_rd);
    c->off[d] = 0;
    c->len[d] = got;
    if (!got) { free(c->pend[d]); c->pend[d] = NULL; return -1; }
    return 0;
}

// Zero-copy forward of one chunk in direction d via the thread's pipe. Returns 1 progress, 0 nothing to do (EAGAIN),
// -1 fatal, -2 splice unsupported (use the copy path), 2 EOF.
static int pump_splice(struct dthread *t, struct conn *c, int d)
{
    int o = 1 - d;
    ssize_t n = splice(c->fd[d], NULL, t->pfd[1], NULL, PIPE_SZ, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
    if (n == 0) return 2;
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR) return 0;
        if (errno == EINVAL || errno == ENOSYS) return -2;
        return -1;
    }
    ssize_t w = splice(t->pfd[0], NULL, c->fd[o], NULL, (size_t)n, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
    if (w < 0) {
        if (errno != EAGAIN && errno != EINTR) { pipe_discard(t->pfd[0]); return -1; }
        w = 0;
    }
    c->bytes[d] += (uint64_t)n;
    if (w < n && spill_from_pipe(c, d, t->pfd[0], (size_t)(n - w)) != 0) return -1;
    return 1;
}

// Upstream->client for TCP-DNS: only whole messages (after pb_core_dns_observe returned) are forwarded.
static int dns_pump_up(struct conn *c, uint8_t *scratch)
{
    int progress = 0;
    ssize_t n = recv(c->fd[1], scratch, SCRATCH_SZ, 0);
    if (n < 0 && errno != EAGAIN && errno != EINTR) return -1;
    if (n > 0) {
        c->bytes[1] += (uint64_t)n;
        if (c->dhave + (size_t)n > c->dcap) {
            size_t nc = c->dhave + (size_t)n;
            uint8_t *nb = realloc(c->dbuf, nc);
            if (!nb) return -1;
            c->dbuf = nb; c->dcap = nc;
        }
        memcpy(c->dbuf + c->dhave, scratch, (size_t)n);
        c->dhave += (size_t)n;
        progress = 1;
    } else if (n == 0) {
        c->eof[1] = true;
        progress = 1;
    }
    size_t fwd = 0;
    if (c->doff) {
        fwd = c->dhave;
    } else {
        while (c->dhave - fwd >= 2) {
            size_t L = (size_t)(c->dbuf[fwd] << 8 | c->dbuf[fwd + 1]);
            if (L == 0) { c->doff = true; fwd = c->dhave; break; }     // malformed: relay raw from here on
            if (c->dhave - fwd < 2 + L) break;
            pb_core_dns_observe(c->dbuf + fwd + 2, L);
            fwd += 2 + L;
        }
        if (c->eof[1]) fwd = c->dhave;              // truncated trailing message: pass through unobserved
    }
    if (fwd) {
        ssize_t w = send(c->fd[0], c->dbuf, fwd, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno != EAGAIN && errno != EINTR) return -1;
            w = 0;
        }
        if ((size_t)w < fwd) {
            c->pend[1] = malloc(fwd - (size_t)w);
            if (!c->pend[1]) return -1;
            memcpy(c->pend[1], c->dbuf + w, fwd - (size_t)w);
            c->off[1] = 0; c->len[1] = fwd - (size_t)w;
        }
        memmove(c->dbuf, c->dbuf + fwd, c->dhave - fwd);
        c->dhave -= fwd;
        progress = 1;
    }
    return progress;
}

static int conn_pump(struct dthread *t, struct conn *c)
{
    uint8_t *scratch = t->scratch;
    for (int iter = 0; iter < 16; iter++) {
        bool progress = false;
        for (int d = 0; d < 2; d++) {
            int o = 1 - d;
            if (c->dns && d == 1 && c->len[1] == 0 && (!c->eof[1] || c->dhave)) {
                int r = dns_pump_up(c, scratch);
                if (r < 0) return -1;
                if (r) progress = true;
            } else if (c->len[d] == 0 && !c->eof[d]) {
                int sp = -2;
                if (!t->nosplice && !c->dns) {
                    sp = pump_splice(t, c, d);
                    if (sp == -1) return -1;
                    if (sp == -2) t->nosplice = true;
                    else if (sp == 2) { c->eof[d] = true; progress = true; }
                    else if (sp == 1) progress = true;
                }
                if (sp == -2) {
                    ssize_t n = recv(c->fd[d], scratch, SCRATCH_SZ, 0);
                    if (n > 0) {
                        progress = true;
                        c->bytes[d] += (uint64_t)n;
                        ssize_t w = send(c->fd[o], scratch, (size_t)n, MSG_NOSIGNAL);
                        if (w < 0) {
                            if (errno != EAGAIN && errno != EINTR) return -1;
                            w = 0;
                        }
                        if (w < n) {            // spill the unsent tail; no more reads in this direction until drained
                            c->pend[d] = malloc((size_t)(n - w));
                            if (!c->pend[d]) return -1;
                            memcpy(c->pend[d], scratch + w, (size_t)(n - w));
                            c->off[d] = 0;
                            c->len[d] = (size_t)(n - w);
                        }
                    }
                    else if (n == 0) { c->eof[d] = true; progress = true; }
                    else if (errno != EAGAIN && errno != EINTR) return -1;
                }
            } else if (c->len[d] > 0) {
                ssize_t n = send(c->fd[o], c->pend[d] + c->off[d], c->len[d], MSG_NOSIGNAL);
                if (n > 0) {
                    c->off[d] += (size_t)n; c->len[d] -= (size_t)n; progress = true;
                    if (!c->len[d]) { free(c->pend[d]); c->pend[d] = NULL; }
                }
                else if (errno != EAGAIN && errno != EINTR) return -1;
            }
            if (c->len[d] == 0 && c->eof[d] && !c->shut[d]) {
                shutdown(c->fd[o], SHUT_WR);
                c->shut[d] = true;
                progress = true;
            }
        }
        if (progress) c->last = now_ms();
        if (c->shut[0] && c->shut[1]) return 1;
        if (!progress) break;
    }
    return 0;
}

static int conn_update(struct dthread *t, struct conn *c)
{
    for (int i = 0; i < 2; i++) {
        uint32_t want = 0;
        if (!c->eof[i] && c->len[i] == 0) want |= EPOLLIN;
        if (c->len[1 - i] > 0) want |= EPOLLOUT;
        if (want == c->mask[i]) continue;
        struct epoll_event ev = { .events = want, .data.ptr = c };
        int rc;
        if (!want) rc = epoll_ctl(t->ep, EPOLL_CTL_DEL, c->fd[i], NULL);
        else rc = epoll_ctl(t->ep, c->mask[i] ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, c->fd[i], &ev);
        if (rc < 0) return -1;
        c->mask[i] = want;
    }
    return 0;
}

static void conn_close(struct dthread *t, struct conn *c)
{
    close(c->fd[0]);
    close(c->fd[1]);
    c->dead = true;
    conn_bufs_free(c);
    pthread_mutex_lock(&t->mu);                 // GetFlows walks this list from another thread
    if (c->prev) c->prev->next = c->next; else t->conns = c->next;
    if (c->next) c->next->prev = c->prev;
    pthread_mutex_unlock(&t->mu);
    c->next = t->grave;
    c->prev = NULL;
    t->grave = c;
    atomic_fetch_sub(&R.nconn, 1);
    atomic_fetch_sub(&t->load, 1);
}

static void conn_service(struct dthread *t, struct conn *c)
{
    int r = conn_pump(t, c);
    if (r == 0 && conn_update(t, c) != 0) r = -1;
    if (r != 0) conn_close(t, c);
}

static void dthread_adopt(struct dthread *t)
{
    pthread_mutex_lock(&t->mu);
    struct conn *c = t->inq_head;
    t->inq_head = t->inq_tail = NULL;
    pthread_mutex_unlock(&t->mu);
    while (c) {
        struct conn *n = c->next;
        pthread_mutex_lock(&t->mu);
        c->next = t->conns; c->prev = NULL;
        if (t->conns) t->conns->prev = c;
        t->conns = c;
        pthread_mutex_unlock(&t->mu);
        c->last = now_ms();
        if (c->len[1] || c->dhave) conn_service(t, c);
        else if (conn_update(t, c) != 0) conn_close(t, c);
        c = n;
    }
}

static void free_grave(struct dthread *t)
{
    while (t->grave) { struct conn *n = t->grave->next; free(t->grave); t->grave = n; }
}

static void *data_main(void *arg)
{
    struct dthread *t = arg;
    if (!block_sigpipe()) t->nosplice = true;         // the copy path sends with MSG_NOSIGNAL
    struct epoll_event evs[64];
    int64_t last_sweep = now_ms();
    int64_t sweep_every = (int64_t)R.cfg.tcp_idle_timeout_s * 250;      // idle/4, clamped to 1s..5s
    if (sweep_every < 1000) sweep_every = 1000;
    if (sweep_every > 5000) sweep_every = 5000;
    while (!atomic_load(&R.stopping)) {
        int n = epoll_wait(t->ep, evs, 64, 1000);
        if (n < 0 && errno != EINTR) break;
        for (int i = 0; i < n; i++) {
            void *p = evs[i].data.ptr;
            if (p == &TAG_STOP) goto done;
            if (p == &TAG_WAKE) {
                eventfd_t v;
                eventfd_read(t->wake, &v);
                dthread_adopt(t);
            } else if (!((struct conn *)p)->dead) {
                conn_service(t, p);
            }
        }
        free_grave(t);
        int64_t now = now_ms();
        if (now - last_sweep >= sweep_every) {
            last_sweep = now;
            int64_t lim = (int64_t)R.cfg.tcp_idle_timeout_s * 1000;
            for (struct conn *c = t->conns, *nx; c; c = nx) {
                nx = c->next;
                if (now - c->last > lim) conn_close(t, c);
            }
            free_grave(t);
        }
    }
done:
    return NULL;
}

static void udp_droplog(const char *why)
{
    R.drop_count++;
    int64_t t = now_ms();
    if (t - R.drop_logged > 5000) {
        pb_core_log("relay: UDP datagram dropped (%s); %lld dropped so far", why, (long long)R.drop_count);
        R.drop_logged = t;
    }
}

static uint32_t sess_hash(const struct sockaddr_in *c, uint32_t id, uint32_t flow)
{
    uint32_t h = 2166136261u;
    uint32_t v[4] = { c->sin_addr.s_addr, c->sin_port, id, flow };
    for (int i = 0; i < 4; i++) { h ^= v[i]; h *= 16777619u; h ^= h >> 15; }
    return h % SESS_BUCKETS;
}

static struct sess *sess_find(const struct sockaddr_in *c, uint32_t id, uint32_t flow)
{
    for (struct sess *s = R.buckets[sess_hash(c, id, flow)]; s; s = s->hnext)
        if (s->cli.sin_addr.s_addr == c->sin_addr.s_addr && s->cli.sin_port == c->sin_port && s->id == id && s->flow_be == flow)
            return s;
    return NULL;
}

static void sess_free_queue(struct sess *s)
{
    for (int i = 0; i < s->nq; i++) free(s->q[i]);
    s->nq = 0; s->qbytes = 0;
}

static void sess_destroy(struct sess *s)
{
    close_fd(&s->up_fd);       // closing removes from epoll
    close_fd(&s->ctl_fd);
    sess_free_queue(s);
    uint32_t h = sess_hash(&s->cli, s->id, s->flow_be);
    for (struct sess **pp = &R.buckets[h]; *pp; pp = &(*pp)->hnext)
        if (*pp == s) { *pp = s->hnext; break; }
    if (s->prev) s->prev->next = s->next; else R.sess_head = s->next;
    if (s->next) s->next->prev = s->prev;
    s->dead = true;
    s->next = R.sgrave;
    R.sgrave = s;
    R.nsess--;
}

static void sess_free_grave(void)
{
    while (R.sgrave) { struct sess *n = R.sgrave->next; free(R.sgrave); R.sgrave = n; }
}

// One process gets at most half of the session table: past that, its own least recently used session makes room, so a
// program that opens UDP sockets at a high rate only ever displaces itself and cannot starve every other one of UDP.
// A session whose setup is still running on a worker thread is never the one to go (the worker still writes into it): when
// every session of the process is in that state, the new one is refused instead.
#define MAX_UDP_SESS_PER_PID (MAX_UDP_SESS / 2)

static struct sess *sess_new(const struct sockaddr_in *cli, uint32_t id, uint32_t flow, int kind, uint32_t pid)
{
    int mine = 0;
    struct sess *oldest = NULL;
    for (struct sess *t = R.sess_head; t; t = t->next) {
        if (t->pid != pid) continue;
        mine++;
        if (t->state != ST_SETUP && (!oldest || t->last < oldest->last)) oldest = t;
    }
    if (mine >= MAX_UDP_SESS_PER_PID) {
        if (!oldest) return NULL;
        sess_destroy(oldest);
    }
    if (R.nsess >= MAX_UDP_SESS) return NULL;
    struct sess *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->cli = *cli; s->id = id; s->flow_be = flow; s->kind = kind; s->pid = pid;
    s->up_fd = s->ctl_fd = -1;
    s->ref[0].s = s->ref[1].s = s;
    s->ref[0].which = 0; s->ref[1].which = 1;
    s->last = now_ms();
    s->sid = ++R.next_sid;
    uint32_t h = sess_hash(cli, id, flow);
    s->hnext = R.buckets[h]; R.buckets[h] = s;
    s->next = R.sess_head;
    if (R.sess_head) R.sess_head->prev = s;
    R.sess_head = s;
    R.nsess++;
    return s;
}

static struct dce *dce_slot(const struct sockaddr_in *cli, uint32_t flow_be)
{
    uint32_t hv = (cli->sin_addr.s_addr * 2654435761u) ^ (cli->sin_port * 40503u) ^ (flow_be * 2246822519u);
    return &R.dc[hv % DC_SIZE];
}

static void udp_reply(const struct sockaddr_in *cli, uint32_t flow_be, const uint8_t *data, size_t n)
{
    struct dce *de = dce_slot(cli, flow_be);
    if (de->used && de->cli.sin_addr.s_addr == cli->sin_addr.s_addr && de->cli.sin_port == cli->sin_port && de->flow_be == flow_be) de->recv += n;
    struct iovec iov = { (void *)data, n };
    union { char b[CMSG_SPACE(sizeof(struct in_pktinfo))]; struct cmsghdr a; } cb;
    memset(&cb, 0, sizeof cb);
    struct msghdr mh = { .msg_name = (void *)cli, .msg_namelen = sizeof *cli, .msg_iov = &iov, .msg_iovlen = 1,
                         .msg_control = cb.b, .msg_controllen = sizeof cb.b };
    struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = IPPROTO_IP; cm->cmsg_type = IP_PKTINFO; cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo pi;
    memset(&pi, 0, sizeof pi);
    pi.ipi_spec_dst.s_addr = flow_be;
    memcpy(CMSG_DATA(cm), &pi, sizeof pi);
    sendmsg(R.ufd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static int sess_arm(struct sess *s, int which, uint32_t events)
{
    int fd = which ? s->ctl_fd : s->up_fd;
    struct epoll_event ev = { .events = events, .data.ptr = &s->ref[which] };
    return epoll_ctl(R.uep, EPOLL_CTL_ADD, fd, &ev);
}

static int flow_upsert(struct sess *s, const struct pb_orig *o, uint32_t flow_be, int64_t now)
{
    int victim = 0;
    for (int i = 0; i < s->nflows; i++) {
        if (s->flows[i].port == o->port && !memcmp(s->flows[i].addr, o->addr, 16)) {
            s->flows[i].ip_be = flow_be;
            s->flows[i].last = now;
            return i;
        }
        if (s->flows[i].last < s->flows[victim].last) victim = i;
    }
    if (s->nflows < MAX_FLOWS) victim = s->nflows++;
    memcpy(s->flows[victim].addr, o->addr, 16);
    s->flows[victim].port = o->port;
    s->flows[victim].ip_be = flow_be;
    s->flows[victim].last = now;
    return victim;
}

static size_t socks5_header(uint8_t *h, const struct pb_orig *o)
{
    h[0] = h[1] = h[2] = 0;
    size_t n;
    if (o->family == AF_INET) { h[3] = 1; memcpy(h + 4, o->addr + 12, 4); n = 10; }
    else { h[3] = 4; memcpy(h + 4, o->addr, 16); n = 22; }
    h[n - 2] = (uint8_t)(o->port >> 8);
    h[n - 1] = (uint8_t)o->port;
    return n;
}

static void udp_dgram(const struct sockaddr_in *cli, uint32_t flow_be, const uint8_t *pl, size_t n, int64_t now)
{
    struct dce *e = dce_slot(cli, flow_be);
    bool same = e->used && e->cli.sin_addr.s_addr == cli->sin_addr.s_addr && e->cli.sin_port == cli->sin_port && e->flow_be == flow_be;
    if (!same || now - e->looked >= FLOW_TTL_MS) {
        struct pb_orig o;
        if (pb_core_get_udp_flow(flow_be, &o) != 0) { e->used = false; udp_droplog("unknown flow address"); return; }
        bool keep = same && e->o.port == o.port && !memcmp(e->o.addr, o.addr, 16) && now - e->last <= (int64_t)R.cfg.udp_idle_timeout_s * 1000;
        if (!keep) {
            int act = o.action;
            uint32_t pid = o.proxy_id;
            if (!pb_core_udp_sender_ok(&o, ntohs(cli->sin_port))) {
                udp_droplog("datagram from a process other than the flow's");
                act = PB_ACT_BLOCK;
            } else if (act == PB_ACT_DECIDE) {
                struct pb_decision d;
                pb_core_decide(&o, &d);
                act = d.action;
                pid = d.proxy_id;
            }
            if (act == PB_ACT_PROXY) {
                struct pb_proxy px;
                if (pb_core_get_proxy(pid, &px) != 0) {
                    pb_core_log("relay: UDP: no proxy configured (id %u), dropping", pid);
                    act = PB_ACT_BLOCK;
                } else {
                    pid = px.id;
                    if (pb_core_is_proxy_process(o.pid, pid)) act = PB_ACT_DIRECT;
                }
            } else if (act != PB_ACT_DIRECT) {
                act = PB_ACT_BLOCK;
            }
            pb_core_flow_event(&o, act);
            e->action = act;
            e->pid = pid;
            e->sid = 0;
            e->t0 = now; e->sent = e->recv = 0;
            e->id = atomic_fetch_add(&R.flow_id, 1) + 1;
        }
        e->used = true;
        e->cli = *cli;
        e->flow_be = flow_be;
        e->o = o;
        e->looked = now;
    }
    e->last = now;
    e->sent += n;
    if (e->action == PB_ACT_BLOCK) return;

    const struct pb_orig *o = &e->o;
    struct sess *s;
    if (e->action == PB_ACT_DIRECT) {
        s = sess_find(cli, DIRECT_ID, flow_be);
        if (!s) {
            s = sess_new(cli, DIRECT_ID, flow_be, SK_DIRECT, o->pid);
            if (!s) { udp_droplog("UDP session limit reached"); return; }
            s->dstlen = orig_to_sa(o, &s->dst);
            s->dport = o->port;
            s->connected = o->family != AF_INET;
            s->up_fd = socket(s->dst.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (s->up_fd < 0 || (s->connected && connect(s->up_fd, (struct sockaddr *)&s->dst, s->dstlen) < 0) || sess_arm(s, 0, EPOLLIN) < 0) {
                pb_core_log("relay: UDP direct socket failed: %s", strerror(errno));
                sess_destroy(s);
                return;
            }
            s->state = ST_READY;
        }
        s->last = now;
        if (s->connected) send(s->up_fd, pl, n, MSG_DONTWAIT | MSG_NOSIGNAL);
        else sendto(s->up_fd, pl, n, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&s->dst, s->dstlen);
        return;
    }

    s = sess_find(cli, e->pid, 0);
    if (!s) {
        struct pb_proxy px;
        if (pb_core_get_proxy(e->pid, &px) != 0) { udp_droplog("proxy vanished"); return; }
        s = sess_new(cli, px.id, 0, px.type == PROXY_TYPE_SOCKS5 ? SK_SOCKS5 : SK_DROP, o->pid);
        if (!s) { udp_droplog("UDP session limit reached"); return; }
        s->proxy = px;
        if (s->kind == SK_DROP) {
            s->state = ST_READY;
        } else {
            s->state = ST_SETUP;
            if (job_push(J_UDP, -1, NULL, s) != 0) {
                s->state = ST_FAILED;
                s->fail_until = now + 5000;
                udp_droplog("setup queue full");
            }
        }
    }
    s->last = now;
    if (s->kind == SK_DROP) {
        if (!s->warned) {
            s->warned = true;
            pb_core_log("relay: UDP cannot be proxied through HTTP proxy '%s'; dropping UDP from %s:%u", s->proxy.name,
                        inet_ntoa(cli->sin_addr), ntohs(cli->sin_port));
        }
        return;
    }
    if (s->state == ST_FAILED) { udp_droplog("proxy UDP setup failed"); return; }

    if (e->sid == s->sid && e->fidx < s->nflows && s->flows[e->fidx].port == o->port && !memcmp(s->flows[e->fidx].addr, o->addr, 16)) {
        s->flows[e->fidx].last = now;
    } else {
        e->fidx = flow_upsert(s, o, flow_be, now);
        e->sid = s->sid;
    }

    uint8_t hdr[22];
    size_t hl = socks5_header(hdr, o);
    if (hl + n > UDP_MAXDG) { udp_droplog("datagram too large"); return; }
    if (s->state == ST_SETUP) {
        if (s->nq >= UDP_QMAX || s->qbytes + hl + n > UDP_QBYTES) { udp_droplog("setup queue full"); return; }
        struct pkt *p = malloc(sizeof *p + hl + n);
        if (!p) return;
        p->len = hl + n;
        memcpy(p->d, hdr, hl);
        memcpy(p->d + hl, pl, n);
        s->q[s->nq++] = p;
        s->qbytes += p->len;
        return;
    }
    struct iovec iov[2] = { { hdr, hl }, { (void *)pl, n } };
    struct msghdr mh = { .msg_iov = iov, .msg_iovlen = 2 };
    sendmsg(s->up_fd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
}

static void udp_recv_client(void)
{
    for (int round = 0; round < 8; round++) {
        for (int i = 0; i < UDP_BATCH; i++) {
            R.mmiov[i] = (struct iovec){ R.rxbuf + (size_t)i * UDP_MAXDG, UDP_MAXDG };
            R.mm[i].msg_hdr = (struct msghdr){ .msg_name = &R.mmname[i], .msg_namelen = sizeof(struct sockaddr_in), .msg_iov = &R.mmiov[i],
                                               .msg_iovlen = 1, .msg_control = R.mmctl[i], .msg_controllen = sizeof R.mmctl[i] };
        }
        int cnt = recvmmsg(R.ufd, R.mm, UDP_BATCH, MSG_DONTWAIT, NULL);
        if (cnt <= 0) return;
        int64_t now = now_ms();
        for (int i = 0; i < cnt; i++) {
            struct msghdr *mh = &R.mm[i].msg_hdr;
            if (mh->msg_flags & MSG_TRUNC) continue;
            struct in_pktinfo pi;
            bool have = false;
            for (struct cmsghdr *c = CMSG_FIRSTHDR(mh); c; c = CMSG_NXTHDR(mh, c))
                if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) { memcpy(&pi, CMSG_DATA(c), sizeof pi); have = true; }
            if (!have || (ntohl(pi.ipi_addr.s_addr) >> 24) != 127) { udp_droplog("destination not in 127.0.0.0/8"); continue; }
            udp_dgram(&R.mmname[i], pi.ipi_addr.s_addr, R.rxbuf + (size_t)i * UDP_MAXDG, R.mm[i].msg_len, now);
        }
        if (cnt < UDP_BATCH) return;
    }
}

static void udp_recv_upstream(struct sess *s)
{
    for (int i = 0; i < 64 && !s->dead; i++) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(s->up_fd, R.rxbuf, UDP_MAXDG, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (n < 0) return;                          // includes ECONNREFUSED from ICMP: ignore
        s->last = now_ms();
        if (s->kind == SK_DIRECT) {
            // unconnected v4 socket: accept replies from the destination host on any port (some servers answer from
            // another port); anything from another host is dropped.
            if (!s->connected && (fl < sizeof from || from.sin_addr.s_addr != ((struct sockaddr_in *)&s->dst)->sin_addr.s_addr)) {
                udp_droplog("reply from unexpected host");
                continue;
            }
            if (s->dport == 53) pb_core_dns_observe(R.rxbuf, (size_t)n);
            udp_reply(&s->cli, s->flow_be, R.rxbuf, (size_t)n);
            continue;
        }
        const uint8_t *b = R.rxbuf;
        if (n < 10 || b[2] != 0) continue;           // fragments unsupported
        size_t h;
        uint8_t addr[16] = { 0 };
        bool known = true;
        uint16_t port;
        if (b[3] == 1) { h = 10; memset(addr + 10, 0xff, 2); memcpy(addr + 12, b + 4, 4); }
        else if (b[3] == 4) { if (n < 22) continue; h = 22; memcpy(addr, b + 4, 16); }
        else if (b[3] == 3) { h = 7 + (size_t)b[4]; if ((size_t)n < h) continue; known = false; }
        else continue;
        port = (uint16_t)(b[h - 2] << 8 | b[h - 1]);
        // Source mapping: exact (ip,port) the client sent to; otherwise the same ip on another port is delivered from the
        // flow address of the most recently used destination with that ip; any other source is dropped (and counted).
        uint32_t flow = 0;
        uint16_t fport = 0;
        bool found = false;
        if (known) {
            int best = -1;
            for (int k = 0; k < s->nflows; k++) {
                if (memcmp(s->flows[k].addr, addr, 16)) continue;
                if (s->flows[k].port == port) { best = k; break; }
                if (best < 0 || s->flows[k].last > s->flows[best].last) best = k;
            }
            if (best >= 0) { flow = s->flows[best].ip_be; fport = s->flows[best].port; found = true; }
        } else if (s->nflows == 1) {
            flow = s->flows[0].ip_be; fport = s->flows[0].port; found = true;
        }
        if (!found) { udp_droplog("reply from unknown source"); continue; }
        if (fport == 53) pb_core_dns_observe(b + h, (size_t)n - h);
        udp_reply(&s->cli, flow, b + h, (size_t)n - h);
    }
}

static void udp_setup_done(void)
{
    pthread_mutex_lock(&R.dmu);
    struct sess *l = R.done;
    R.done = NULL;
    pthread_mutex_unlock(&R.dmu);
    while (l) {
        struct sess *s = l;
        l = s->dnext;
        if (s->ok && sess_arm(s, 0, EPOLLIN) == 0 && sess_arm(s, 1, EPOLLIN | EPOLLRDHUP) == 0) {
            s->state = ST_READY;
            s->last = now_ms();
            for (int i = 0; i < s->nq; i++) send(s->up_fd, s->q[i]->d, s->q[i]->len, MSG_DONTWAIT | MSG_NOSIGNAL);
            sess_free_queue(s);
        } else {
            if (s->ok) snprintf(s->err, sizeof s->err, "epoll_ctl: %s", strerror(errno));
            pb_core_log("relay: UDP associate failed: %s", s->err);
            close_fd(&s->up_fd);
            close_fd(&s->ctl_fd);
            sess_free_queue(s);
            s->state = ST_FAILED;
            s->fail_until = now_ms() + 5000;
        }
    }
}

static void udp_ctl_event(struct sess *s)
{
    char tmp[256];
    for (;;) {
        ssize_t n = recv(s->ctl_fd, tmp, sizeof tmp, MSG_DONTWAIT);
        if (n > 0) continue;
        if (n < 0 && errno == EAGAIN) return;
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    pb_core_log("relay: SOCKS5 UDP control connection closed, dropping session for %s:%u", inet_ntoa(s->cli.sin_addr), ntohs(s->cli.sin_port));
    sess_destroy(s);
}

// The UDP thread owns the flow table; GetFlows reads this copy, refreshed once a second.
static void udp_publish_flows(void)
{
    int64_t now = now_ms();
    pthread_mutex_lock(&R.fmu);
    int n = 0;
    for (int i = 0; i < DC_SIZE && n < UFLOWS_MAX; i++) {
        const struct dce *e = &R.dc[i];
        if (!e->used || e->action != PB_ACT_PROXY || now - e->last > UDP_LIVE_MS) continue;
        struct pb_flow_info *f = &R.uflows[n++];
        f->id = e->id; f->pid = e->o.pid; f->proxy_id = (uint16_t)e->pid; f->port = e->o.port;
        f->family = e->o.family; f->udp = 1; memcpy(f->addr, e->o.addr, 16);
        f->age_ms = (uint32_t)(now - e->t0); f->sent = e->sent; f->recv = e->recv;
    }
    R.nuflows = n;
    pthread_mutex_unlock(&R.fmu);
}

static void udp_sweep(void)
{
    int64_t now = now_ms(), lim = (int64_t)R.cfg.udp_idle_timeout_s * 1000;
    for (struct sess *s = R.sess_head, *n; s; s = n) {
        n = s->next;
        if (s->state == ST_SETUP) continue;
        if (s->state == ST_FAILED ? now >= s->fail_until : now - s->last > lim) sess_destroy(s);
    }
}

static void *udp_main(void *arg)
{
    (void)arg;
    block_sigpipe();
    struct epoll_event evs[64];
    while (!atomic_load(&R.stopping)) {
        int n = epoll_wait(R.uep, evs, 64, 1000);
        if (n < 0 && errno != EINTR) break;
        for (int i = 0; i < n; i++) {
            void *p = evs[i].data.ptr;
            if (p == &TAG_STOP) return NULL;
            if (p == &TAG_UDP) udp_recv_client();
            else if (p == &TAG_WAKE) { eventfd_t v; eventfd_read(R.uwake, &v); udp_setup_done(); }
            else if (p == &TAG_TIMER) { uint64_t v; if (read(R.tmfd, &v, sizeof v) > 0) { udp_sweep(); udp_publish_flows(); } }
            else {
                struct ref *r = p;
                struct sess *s = r->s;
                if (s->dead) continue;
                if (r->which == 1) udp_ctl_event(s); else udp_recv_upstream(s);
            }
        }
        sess_free_grave();
    }
    return NULL;
}

static void teardown(void)
{
    atomic_store(&R.stopping, true);
    pthread_mutex_lock(&R.fmu);
    R.nuflows = 0;
    pthread_mutex_unlock(&R.fmu);
    if (R.stopfd >= 0) eventfd_write(R.stopfd, 1);
    pthread_mutex_lock(&R.jmu);
    pthread_cond_broadcast(&R.jcv);
    pthread_mutex_unlock(&R.jmu);
    if (R.acc_started) pthread_join(R.acceptor, NULL);
    pthread_mutex_lock(&R.jmu);
    while (R.nworkers > 0) pthread_cond_wait(&R.wdone, &R.jmu);
    pthread_mutex_unlock(&R.jmu);
    for (int i = 0; i < R.ndata; i++) if (R.data[i].started) pthread_join(R.data[i].th, NULL);
    if (R.udp_started) pthread_join(R.udpth, NULL);
    R.acc_started = R.udp_started = false;

    while (R.jhead) {
        struct job *j = R.jhead;
        R.jhead = j->next;
        if (j->kind == J_TCP) { close(j->fd); atomic_fetch_sub(&R.nconn, 1); }
        free(j);
    }
    R.jtail = NULL; R.jcount = 0;
    for (int i = 0; i < R.ndata; i++) {
        struct dthread *t = &R.data[i];
        pthread_mutex_lock(&t->mu);                       // pb_relay_flows may still be walking the list
        for (struct conn *c = t->inq_head, *n; c; c = n) { n = c->next; close(c->fd[0]); close(c->fd[1]); conn_bufs_free(c); free(c); atomic_fetch_sub(&R.nconn, 1); }
        t->inq_head = t->inq_tail = NULL;
        for (struct conn *c = t->conns, *n; c; c = n) { n = c->next; close(c->fd[0]); close(c->fd[1]); conn_bufs_free(c); free(c); atomic_fetch_sub(&R.nconn, 1); }
        t->conns = NULL;
        pthread_mutex_unlock(&t->mu);
        free_grave(t);
        free(t->scratch); t->scratch = NULL;
        close_fd(&t->pfd[0]); close_fd(&t->pfd[1]);
        t->started = false;
        close_fd(&t->ep);
        close_fd(&t->wake);
    }
    while (R.sess_head) sess_destroy(R.sess_head);
    sess_free_grave();
    memset(R.buckets, 0, sizeof R.buckets);
    R.done = NULL;
    R.nsess = 0;
    free(R.dc); R.dc = NULL;
    free(R.rxbuf); R.rxbuf = NULL;
    free(R.mm); free(R.mmiov); free(R.mmname); free(R.mmctl);
    R.mm = NULL; R.mmiov = NULL; R.mmname = NULL; R.mmctl = NULL;
    close_fd(&R.lfd);
    close_fd(&R.ufd);
    close_fd(&R.tmfd);
    close_fd(&R.uep);
    close_fd(&R.uwake);
    close_fd(&R.stopfd);
}

static int add_ep(int ep, int fd, void *tag, uint32_t ev)
{
    struct epoll_event e = { .events = ev, .data.ptr = tag };
    return epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e);
}

// Every relayed TCP connection holds two descriptors and every UDP session two more, while the usual soft limit is 1024 (it is
// also the default of a systemd service): without this the relay would run out at about 500 connections. The hard limit is the
// ceiling the administrator chose; the soft limit may always be raised up to it.
static void raise_fd_limit(void)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return;
    rlim_t want = rl.rlim_max == RLIM_INFINITY || rl.rlim_max > 1048576 ? 1048576 : rl.rlim_max;
    if (rl.rlim_cur >= want) return;
    rl.rlim_cur = want;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) pb_core_log("relay: could not raise the open file limit: %s", strerror(errno));
}

int pb_relay_start(const struct pb_relay_cfg *cfg)
{
    pthread_mutex_lock(&R.life);
    if (R.running) { pthread_mutex_unlock(&R.life); return 0; }
    struct pb_relay_cfg c = { 0 };
    if (cfg) c = *cfg;
    if (!c.tcp_port) c.tcp_port = PB_TCP_RELAY_PORT_DEFAULT;
    if (!c.udp_port) c.udp_port = PB_UDP_RELAY_PORT_DEFAULT;
    if (c.max_tcp_conns <= 0) c.max_tcp_conns = 32768;
    if (c.tcp_idle_timeout_s <= 0) c.tcp_idle_timeout_s = 300;
    if (c.udp_idle_timeout_s <= 0) c.udp_idle_timeout_s = 60;
    if (c.handshake_timeout_s <= 0) c.handshake_timeout_s = 10;
    raise_fd_limit();
    R.cfg = c;
    atomic_store(&R.stopping, false);
    atomic_store(&R.nconn, 0);
    R.drop_count = 0; R.drop_logged = 0;
    const char *why = "";
    int one = 1;
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    R.ndata = ncpu < 2 ? 2 : (ncpu > MAX_DATA ? MAX_DATA : (int)ncpu);
    for (int i = 0; i < R.ndata; i++) {
        memset(&R.data[i], 0, sizeof R.data[i]);
        R.data[i].ep = R.data[i].wake = -1;
        R.data[i].pfd[0] = R.data[i].pfd[1] = -1;
        pthread_mutex_init(&R.data[i].mu, NULL);
    }

    R.stopfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    R.uwake = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (R.stopfd < 0 || R.uwake < 0) { why = "eventfd"; goto fail; }

    R.lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (R.lfd < 0) { why = "tcp socket"; goto fail; }
    setsockopt(R.lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    tune_sock(R.lfd);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(c.tcp_port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (bind(R.lfd, (struct sockaddr *)&a, sizeof a) < 0 || listen(R.lfd, 4096) < 0) {
        pb_core_log("relay: cannot listen on 127.0.0.1:%u: %s", c.tcp_port, strerror(errno));
        goto fail_quiet;
    }

    R.ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (R.ufd < 0) { why = "udp socket"; goto fail; }
    if (setsockopt(R.ufd, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) < 0)
        pb_core_log("relay: SO_BINDTODEVICE lo failed (%s); relying on destination address filtering", strerror(errno));
    int rb = 4 << 20;
    if (setsockopt(R.ufd, SOL_SOCKET, SO_RCVBUFFORCE, &rb, sizeof rb) < 0) setsockopt(R.ufd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    if (setsockopt(R.ufd, IPPROTO_IP, IP_PKTINFO, &one, sizeof one) < 0) { why = "IP_PKTINFO"; goto fail; }
    a.sin_port = htons(c.udp_port);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(R.ufd, (struct sockaddr *)&a, sizeof a) < 0) {
        pb_core_log("relay: cannot bind UDP port %u: %s", c.udp_port, strerror(errno));
        goto fail_quiet;
    }
    R.tcp_port = c.tcp_port; R.udp_port = c.udp_port;

    R.uep = epoll_create1(EPOLL_CLOEXEC);
    R.tmfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    R.dc = calloc(DC_SIZE, sizeof *R.dc);
    R.rxbuf = malloc((size_t)UDP_MAXDG * UDP_BATCH);
    R.mm = calloc(UDP_BATCH, sizeof *R.mm);
    R.mmiov = calloc(UDP_BATCH, sizeof *R.mmiov);
    R.mmname = calloc(UDP_BATCH, sizeof *R.mmname);
    R.mmctl = calloc(UDP_BATCH, sizeof *R.mmctl);
    if (R.uep < 0 || R.tmfd < 0 || !R.dc || !R.rxbuf || !R.mm || !R.mmiov || !R.mmname || !R.mmctl) { why = "udp resources"; goto fail; }
    struct itimerspec its = { .it_interval = { 1, 0 }, .it_value = { 1, 0 } };
    if (timerfd_settime(R.tmfd, 0, &its, NULL) < 0 ||
        add_ep(R.uep, R.ufd, &TAG_UDP, EPOLLIN) || add_ep(R.uep, R.stopfd, &TAG_STOP, EPOLLIN) ||
        add_ep(R.uep, R.uwake, &TAG_WAKE, EPOLLIN) || add_ep(R.uep, R.tmfd, &TAG_TIMER, EPOLLIN)) { why = "udp epoll"; goto fail; }

    for (int i = 0; i < R.ndata; i++) {
        struct dthread *t = &R.data[i];
        t->scratch = malloc(SCRATCH_SZ);
        if (pipe2(t->pfd, O_CLOEXEC | O_NONBLOCK) == 0) fcntl(t->pfd[0], F_SETPIPE_SZ, PIPE_SZ);
        else t->pfd[0] = t->pfd[1] = -1, t->nosplice = true;
        t->ep = epoll_create1(EPOLL_CLOEXEC);
        t->wake = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (!t->scratch || t->ep < 0 || t->wake < 0 || add_ep(t->ep, t->wake, &TAG_WAKE, EPOLLIN) || add_ep(t->ep, R.stopfd, &TAG_STOP, EPOLLIN)) {
            why = "tcp epoll"; goto fail;
        }
    }
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 512 * 1024);
    bool ok = true;
    for (int i = 0; i < R.ndata && ok; i++) {
        ok = pthread_create(&R.data[i].th, &at, data_main, &R.data[i]) == 0;
        R.data[i].started = ok;
    }
    pthread_mutex_lock(&R.jmu);
    memset(R.busy, 0, sizeof R.busy);
    for (int i = 0; i < WORKERS_MIN; i++) worker_spawn_locked();
    ok = R.nworkers == WORKERS_MIN;
    pthread_mutex_unlock(&R.jmu);
    if (ok) { ok = pthread_create(&R.udpth, &at, udp_main, NULL) == 0; R.udp_started = ok; }
    if (ok) { ok = pthread_create(&R.acceptor, &at, acceptor_main, NULL) == 0; R.acc_started = ok; }
    pthread_attr_destroy(&at);
    if (!ok) { why = "pthread_create"; goto fail; }
    R.running = true;
    pthread_mutex_unlock(&R.life);
    return 0;

fail:
    pb_core_log("relay: start failed (%s): %s", why, strerror(errno));
fail_quiet:
    teardown();
    pthread_mutex_unlock(&R.life);
    return -1;
}

void pb_relay_stop(void)
{
    pthread_mutex_lock(&R.life);
    if (R.running) {
        teardown();
        R.running = false;
    }
    pthread_mutex_unlock(&R.life);
}

uint16_t pb_relay_tcp_port(void) { return R.tcp_port; }
uint16_t pb_relay_udp_port(void) { return R.udp_port; }

int pb_relay_test_proxy(const struct pb_proxy *proxy, const char *host, uint16_t port, char *buf, size_t buflen)
{
    if (!buf || !buflen) return -1;
    int64_t dl = now_ms() + 10000;
    int fd = -1, rc = -1;
    char err[256] = "";
    uint8_t left[HDR_MAX];
    size_t leftn = 0;
    fd = connect_host(proxy->host, proxy->port, dl, -1, err, sizeof err);
    if (fd < 0) { snprintf(buf, buflen, "Cannot reach proxy: %s", err); return -1; }
    struct io x = { .fd = fd, .dl = dl, .stopfd = -1 };
    if (proxy->type == PROXY_TYPE_SOCKS5) {
        struct s5dst d;
        memset(&d, 0, sizeof d);
        d.port = port;
        struct in_addr a4; struct in6_addr a6;
        if (inet_pton(AF_INET, host, &a4) == 1) { d.atyp = 1; memcpy(d.addr, &a4, 4); }
        else if (inet_pton(AF_INET6, host, &a6) == 1) { d.atyp = 4; memcpy(d.addr, &a6, 16); }
        else { d.atyp = 3; snprintf(d.host, sizeof d.host, "%s", host); }
        rc = socks5_request(&x, proxy, 1, &d, NULL);
    } else {
        rc = http_connect(&x, proxy, host, port, left, &leftn);
    }
    if (rc) { snprintf(buf, buflen, "%s", x.err); close(fd); return -1; }
    if (port != 80) {
        snprintf(buf, buflen, "Tunnel established");
        close(fd);
        return 0;
    }
    char req[600];
    int n = snprintf(req, sizeof req, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
    if (n < 0 || (size_t)n >= sizeof req) {      // snprintf reports the length it wanted: sending that many bytes would read past the buffer
        snprintf(buf, buflen, "Target host name too long");
        close(fd);
        return -1;
    }
    char resp[1024];
    size_t got = 0;
    if (io_send(&x, req, (size_t)n)) { snprintf(buf, buflen, "%s", x.err); close(fd); return -1; }
    if (leftn) { got = leftn < sizeof resp ? leftn : sizeof resp - 1; memcpy(resp, left, got); }
    while (!memchr(resp, '\n', got) && got < sizeof resp - 1) {
        ssize_t r = io_recv(&x, resp + got, sizeof resp - 1 - got);
        if (r < 0) break;
        got += (size_t)r;
    }
    close(fd);
    resp[got] = 0;
    char *nl = strpbrk(resp, "\r\n");
    if (nl) *nl = 0;
    if (!resp[0]) { snprintf(buf, buflen, "No response through proxy: %s", x.err); return -1; }
    snprintf(buf, buflen, "%s", resp);
    return 0;
}

// ---- detailed proxy check -----------------------------------------------------------------------------------------------------

static void chk(pb_check_cb cb, void *user, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void chk(pb_check_cb cb, void *user, const char *fmt, ...)
{
    if (!cb) return;
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    cb(line, user);
}

static void s5dst_from_host(struct s5dst *d, const char *host, uint16_t port)
{
    memset(d, 0, sizeof *d);
    d->port = port;
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1) { d->atyp = 1; memcpy(d->addr, &a4, 4); }
    else if (inet_pton(AF_INET6, host, &a6) == 1) { d->atyp = 4; memcpy(d->addr, &a6, 16); }
    else { d->atyp = 3; snprintf(d->host, sizeof d->host, "%s", host); }
}

// Connects to the proxy and opens a tunnel to host:port. Returns the socket or -1 with the reason in err; *ms is the setup time.
static int check_open_tunnel(const struct pb_proxy *proxy, const char *host, uint16_t port, uint8_t *left, size_t *leftn,
                             char *err, size_t errn, int *stage, int64_t *ms)
{
    int64_t t0 = now_ms(), dl = t0 + 10000;
    char cerr[200];
    *stage = 1;
    int fd = connect_host(proxy->host, proxy->port, dl, -1, cerr, sizeof cerr);
    if (fd < 0) { snprintf(err, errn, "%s", cerr); return -1; }
    *stage = 2;
    struct io x = { .fd = fd, .dl = dl, .stopfd = -1 };
    int rc;
    *leftn = 0;
    if (proxy->type == PROXY_TYPE_SOCKS5) {
        struct s5dst d;
        s5dst_from_host(&d, host, port);
        rc = socks5_request(&x, proxy, 1, &d, NULL);
    } else {
        rc = http_connect(&x, proxy, host, port, left, leftn);
    }
    if (rc) { snprintf(err, errn, "%s", x.err); close(fd); return -1; }
    *ms = now_ms() - t0;
    return fd;
}

int pb_relay_check_proxy(const struct pb_proxy *proxy, const char *host, uint16_t port, pb_check_cb cb, void *user)
{
    char desc[300], err[256] = "";
    proxy_desc(proxy, desc, sizeof desc);
    chk(cb, user, "Proxy: %s (%s)%s", proxy->name, desc, proxy->user[0] ? ", with credentials" : ", no credentials");
    chk(cb, user, "Target: %s:%u", host, port);

    chk(cb, user, "[1/5] Connecting to the proxy ...");
    int64_t t0 = now_ms();
    char cerr[200];
    int probe = connect_host(proxy->host, proxy->port, t0 + 10000, -1, cerr, sizeof cerr);
    if (probe < 0) {
        chk(cb, user, "      FAILED: %s", cerr);
        chk(cb, user, "Result: FAILED - the proxy cannot be reached");
        return -1;
    }
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    char peer[INET6_ADDRSTRLEN] = "?";
    if (getpeername(probe, (struct sockaddr *)&ss, &sl) == 0)
        inet_ntop(ss.ss_family, ss.ss_family == AF_INET ? (void *)&((struct sockaddr_in *)&ss)->sin_addr : (void *)&((struct sockaddr_in6 *)&ss)->sin6_addr, peer, sizeof peer);
    close(probe);
    chk(cb, user, "      OK: connected to %s in %lld ms", peer, (long long)(now_ms() - t0));

    chk(cb, user, "[2/5] Opening a tunnel to the target ...");
    uint8_t left[HDR_MAX];
    size_t leftn = 0;
    int stage = 0;
    int64_t ms = 0;
    int fd = check_open_tunnel(proxy, host, port, left, &leftn, err, sizeof err, &stage, &ms);
    if (fd < 0) {
        chk(cb, user, "      FAILED: %s", err);
        chk(cb, user, "Result: FAILED - the proxy refused the tunnel or the login");
        return -2;
    }
    chk(cb, user, "      OK: %s tunnel established in %lld ms%s", proxy->type == PROXY_TYPE_SOCKS5 ? "SOCKS5" : "HTTP CONNECT", (long long)ms,
        proxy->user[0] ? " (login accepted)" : "");

    chk(cb, user, "[3/5] Loading a page through the tunnel ...");
    if (port != 80) {
        chk(cb, user, "      skipped: only port 80 is probed with a plain HTTP request");
    } else {
        struct io x = { .fd = fd, .dl = now_ms() + 8000, .stopfd = -1 };
        char req[600];
        int n = snprintf(req, sizeof req, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: ProxyBridge-check\r\n\r\n", host);
        if (n < 0 || (size_t)n >= sizeof req) { chk(cb, user, "      skipped: the target host name is too long for the request"); n = 0; }
        char resp[1024];
        size_t got = leftn < sizeof resp - 1 ? leftn : sizeof resp - 1;
        memcpy(resp, left, got);
        int64_t t1 = now_ms();
        if (n > 0 && io_send(&x, req, (size_t)n) == 0) {
            while (!memchr(resp, '\n', got) && got < sizeof resp - 1) {
                ssize_t r = io_recv(&x, resp + got, sizeof resp - 1 - got);
                if (r < 0) break;
                got += (size_t)r;
            }
        }
        resp[got] = 0;
        char *nl = strpbrk(resp, "\r\n");
        if (nl) *nl = 0;
        if (resp[0]) chk(cb, user, "      OK: %.120s (first byte after %lld ms)", resp, (long long)(now_ms() - t1));
        else chk(cb, user, "      WARNING: no HTTP answer through the tunnel (%s)", x.err[0] ? x.err : "empty reply");
    }
    close(fd);

    chk(cb, user, "[4/5] Measuring tunnel set-up time (3 tunnels) ...");
    int64_t lo = INT64_MAX, hi = 0, sum = 0;
    int okn = 0;
    for (int i = 0; i < 3; i++) {
        int fd2 = check_open_tunnel(proxy, host, port, left, &leftn, err, sizeof err, &stage, &ms);
        if (fd2 < 0) continue;
        close(fd2);
        okn++; sum += ms;
        if (ms < lo) lo = ms;
        if (ms > hi) hi = ms;
    }
    if (okn == 3) chk(cb, user, "      OK: min/avg/max = %lld/%lld/%lld ms", (long long)lo, (long long)(sum / 3), (long long)hi);
    else if (okn > 0) chk(cb, user, "      WARNING: only %d of 3 tunnels opened (min/avg/max = %lld/%lld/%lld ms)", okn, (long long)lo, (long long)(sum / okn), (long long)hi);
    else chk(cb, user, "      WARNING: none of the repeat tunnels opened: %s", err);

    chk(cb, user, "[5/5] UDP support ...");
    if (proxy->type != PROXY_TYPE_SOCKS5) {
        chk(cb, user, "      HTTP proxies cannot carry UDP: rules that send UDP here go direct");
    } else {
        int64_t dl = now_ms() + 8000;
        int cfd = connect_host(proxy->host, proxy->port, dl, -1, cerr, sizeof cerr);
        if (cfd < 0) {
            chk(cb, user, "      WARNING: %s", cerr);
        } else {
            struct io x = { .fd = cfd, .dl = dl, .stopfd = -1 };
            struct s5dst d;
            struct s5bnd b;
            memset(&d, 0, sizeof d);
            d.atyp = 1;
            if (socks5_request(&x, proxy, 3, &d, &b) == 0) {
                char a[INET6_ADDRSTRLEN] = "?";
                if (b.atyp == 1) inet_ntop(AF_INET, b.addr, a, sizeof a);
                else if (b.atyp == 4) inet_ntop(AF_INET6, b.addr, a, sizeof a);
                else snprintf(a, sizeof a, "(host name)");
                chk(cb, user, "      OK: UDP ASSOCIATE accepted, the proxy relays UDP at %s:%u", a, b.port);
            } else {
                chk(cb, user, "      WARNING: UDP ASSOCIATE refused: %s (UDP rules for this proxy will not work)", x.err);
            }
            close(cfd);
        }
    }
    chk(cb, user, "Result: PASSED");
    return 0;
}

// ---- live flows ---------------------------------------------------------------------------------------------------------------

static int flow_newest_first(const void *a, const void *b)
{
    const struct pb_flow_info *x = a, *y = b;
    return x->age_ms < y->age_ms ? -1 : x->age_ms > y->age_ms;
}

int pb_relay_flows(struct pb_flow_info *out, int max)
{
    int n = 0;
    if (!out || max <= 0 || !R.running || atomic_load(&R.stopping)) return 0;
    int64_t now = now_ms();
    for (int i = 0; i < R.ndata && n < max; i++) {
        struct dthread *t = &R.data[i];
        pthread_mutex_lock(&t->mu);
        for (struct conn *c = t->conns; c && n < max; c = c->next) {
            if (!c->proxy_id) continue;                   // direct flows are not the engine's business
            struct pb_flow_info *f = &out[n++];
            f->id = c->id; f->pid = c->pid; f->proxy_id = c->proxy_id; f->port = c->port; f->family = c->family; f->udp = 0;
            memcpy(f->addr, c->addr, 16);
            f->age_ms = (uint32_t)(now - c->t0);
            f->sent = __atomic_load_n(&c->bytes[0], __ATOMIC_RELAXED);
            f->recv = __atomic_load_n(&c->bytes[1], __ATOMIC_RELAXED);
        }
        pthread_mutex_unlock(&t->mu);
    }
    pthread_mutex_lock(&R.fmu);
    for (int i = 0; i < R.nuflows && n < max; i++) out[n++] = R.uflows[i];
    pthread_mutex_unlock(&R.fmu);
    qsort(out, (size_t)n, sizeof *out, flow_newest_first);
    return n;
}
