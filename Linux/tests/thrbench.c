// Throughput benchmark: compares an application talking to a SOCKS5 proxy itself ("socks") against the same application being
// transparently redirected by ProxyBridge ("transparent"). The bundled proxy accepts any CONNECT and forwards to the local sink.
//   thrbench proxy <port> <sink_port>      SOCKS5 (no auth) forwarder, splice() based
//   thrbench sink <port>                   discards data, replies with the byte count at EOF
//   thrbench socks <proxy_port> <ip> <port> <MB> [conns]   client doing the SOCKS5 handshake itself
//   thrbench direct <ip> <port> <MB> [conns]               client connecting straight to the sink
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
static double now_s(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static struct sockaddr_in addr_of(const char *ip, int port) { struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) }; inet_pton(AF_INET, ip, &a.sin_addr); return a; }
static int listener(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = addr_of("127.0.0.1", port);
    if (bind(s, (void *)&a, sizeof a) || listen(s, 1024)) { perror("listen"); exit(1); }
    return s;
}
static int read_full(int fd, void *b, size_t n) { size_t o = 0; while (o < n) { ssize_t r = read(fd, (char *)b + o, n - o); if (r <= 0) return -1; o += (size_t)r; } return 0; }

static void *sink_conn(void *a)
{
    int c = (int)(long)a; static __thread char b[1 << 20]; unsigned long long total = 0; ssize_t n;
    while ((n = read(c, b, sizeof b)) > 0) total += (unsigned long long)n;
    write(c, &total, sizeof total); close(c); return NULL;
}
static void run_sink(int port) { int l = listener(port); for (;;) { int c = accept(l, 0, 0); pthread_t t; pthread_create(&t, 0, sink_conn, (void *)(long)c); pthread_detach(t); } }

struct pair { int a, b; };
static void *pipe_dir(void *arg)
{
    struct pair *p = arg; int pp[2]; pipe(pp); fcntl(pp[0], F_SETPIPE_SZ, 1 << 20);
    for (;;) {
        ssize_t n = splice(p->a, 0, pp[1], 0, 1 << 20, SPLICE_F_MOVE);
        if (n <= 0) break;
        while (n > 0) { ssize_t w = splice(pp[0], 0, p->b, 0, (size_t)n, SPLICE_F_MOVE); if (w <= 0) goto out; n -= w; }
    }
out: shutdown(p->b, SHUT_WR); close(pp[0]); close(pp[1]); return NULL;
}
static void *proxy_conn(void *arg)
{
    int c = (int)(long)arg; unsigned char b[512];
    if (read_full(c, b, 2) || read_full(c, b + 2, b[1])) goto done;
    write(c, "\x05\x00", 2);
    if (read_full(c, b, 4)) goto done;
    if (b[3] == 1) read_full(c, b, 6); else if (b[3] == 4) read_full(c, b, 18); else { unsigned char l; read_full(c, &l, 1); read_full(c, b, l + 2u); }
    extern int g_sink; int u = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in a = addr_of("127.0.0.1", g_sink);
    if (connect(u, (void *)&a, sizeof a)) goto done;
    write(c, "\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00", 10);
    struct pair p1 = { c, u }, p2 = { u, c }; pthread_t t1, t2;
    pthread_create(&t1, 0, pipe_dir, &p1); pthread_create(&t2, 0, pipe_dir, &p2); pthread_join(t1, 0); pthread_join(t2, 0); close(u);
done: close(c); return NULL;
}
int g_sink;
static void run_proxy(int port, int sink) { g_sink = sink; int l = listener(port); for (;;) { int c = accept(l, 0, 0); pthread_t t; pthread_create(&t, 0, proxy_conn, (void *)(long)c); pthread_detach(t); } }

struct cl { const char *ip; int port, proxy_port; long mb; double secs; int ok; };
static void *client(void *arg)
{
    struct cl *c = arg; int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = c->proxy_port ? addr_of("127.0.0.1", c->proxy_port) : addr_of(c->ip, c->port);
    if (connect(s, (void *)&a, sizeof a)) { perror("connect"); return NULL; }
    if (c->proxy_port) {                                   // SOCKS5 CONNECT done by the application itself
        unsigned char b[32] = { 5, 1, 0 }; write(s, b, 3); read_full(s, b, 2);
        unsigned char req[10] = { 5, 1, 0, 1 }; inet_pton(AF_INET, c->ip, req + 4); req[8] = (unsigned char)(c->port >> 8); req[9] = (unsigned char)c->port;
        write(s, req, 10); if (read_full(s, b, 10)) return NULL;
    }
    static __thread char buf[1 << 20]; memset(buf, 'x', sizeof buf);
    double t0 = now_s();
    for (long i = 0; i < c->mb; i++) if (write(s, buf, sizeof buf) <= 0) return NULL;
    shutdown(s, SHUT_WR);
    unsigned long long total = 0; read_full(s, &total, sizeof total);
    c->secs = now_s() - t0; c->ok = total == (unsigned long long)c->mb << 20; close(s); return NULL;
}
int main(int argc, char **argv)
{
    if (!strcmp(argv[1], "sink")) run_sink(atoi(argv[2]));
    if (!strcmp(argv[1], "proxy")) run_proxy(atoi(argv[2]), atoi(argv[3]));
    int socks = !strcmp(argv[1], "socks"), ai = socks ? 3 : 2;
    int pp = socks ? atoi(argv[2]) : 0; const char *ip = argv[ai]; int port = atoi(argv[ai + 1]); long mb = atol(argv[ai + 2]); int n = argc > ai + 3 ? atoi(argv[ai + 3]) : 1;
    struct cl *c = calloc((size_t)n, sizeof *c); pthread_t *t = calloc((size_t)n, sizeof *t); double t0 = now_s();
    for (int i = 0; i < n; i++) { c[i] = (struct cl){ ip, port, pp, mb }; pthread_create(&t[i], 0, client, &c[i]); }
    int ok = 0; for (int i = 0; i < n; i++) { pthread_join(t[i], 0); ok += c[i].ok; }
    double dt = now_s() - t0; printf("%-11s conns=%d ok=%d  %ld MB each  total %.0f MB in %.2fs = %.0f MB/s\n", argv[1], n, ok, mb, (double)n * (double)mb, dt, (double)n * (double)mb / dt);
    return 0;
}
