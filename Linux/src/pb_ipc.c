#include "pb_ipc.h"

#include <errno.h>
#include <poll.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void put32(unsigned char *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = (unsigned char)v; }
static uint32_t get32(const unsigned char *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

void pb_msg_free(pb_msg *m)
{
    if (!m) return;
    free(m->f);
    free(m->len);
    free(m->pool);
    memset(m, 0, sizeof *m);
}

unsigned char *pb_ipc_encode(unsigned n, const char *const *f, const size_t *len, size_t *out_len)
{
    if (n > PB_IPC_MAX_FIELDS) return NULL;
    size_t total = 2;
    for (unsigned i = 0; i < n; i++) {
        size_t l = len ? len[i] : strlen(f[i]);
        if (l > PB_IPC_MAX_FRAME) return NULL;
        total += 4 + l;
        if (total > PB_IPC_MAX_FRAME) return NULL;
    }
    unsigned char *out = malloc(4 + total);
    if (!out) return NULL;
    put32(out, (uint32_t)total);
    out[4] = (unsigned char)(n >> 8);
    out[5] = (unsigned char)n;
    size_t pos = 6;
    for (unsigned i = 0; i < n; i++) {
        size_t l = len ? len[i] : strlen(f[i]);
        put32(out + pos, (uint32_t)l);
        pos += 4;
        if (l) memcpy(out + pos, f[i], l);
        pos += l;
    }
    *out_len = 4 + total;
    return out;
}

int pb_ipc_decode(const unsigned char *p, size_t plen, pb_msg *m)
{
    memset(m, 0, sizeof *m);
    if (plen < 2 || plen > PB_IPC_MAX_FRAME) return -2;
    unsigned n = ((unsigned)p[0] << 8) | p[1];
    if (n > PB_IPC_MAX_FIELDS) return -2;
    // First pass: the lengths must add up exactly, before anything is allocated
    size_t pos = 2, data = 0;
    for (unsigned i = 0; i < n; i++) {
        if (plen - pos < 4) return -2;
        uint32_t l = get32(p + pos);
        pos += 4;
        if (l > plen - pos) return -2;
        pos += l;
        data += l;
    }
    if (pos != plen) return -2;

    m->f = calloc(n ? n : 1, sizeof *m->f);
    m->len = calloc(n ? n : 1, sizeof *m->len);
    m->pool = malloc(data + n + 1);
    if (!m->f || !m->len || !m->pool) { pb_msg_free(m); return -1; }
    m->n = n;
    pos = 2;
    size_t out = 0;
    for (unsigned i = 0; i < n; i++) {
        uint32_t l = get32(p + pos);
        pos += 4;
        m->f[i] = m->pool + out;
        m->len[i] = l;
        if (l) memcpy(m->pool + out, p + pos, l);
        m->pool[out + l] = '\0';
        out += (size_t)l + 1;
        pos += l;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t n)
{
    unsigned char *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r > 0) { p += r; n -= (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w > 0) { p += w; n -= (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// body_ms < 0: no limit
static int read_full_by(int fd, void *buf, size_t n, int body_ms)
{
    if (body_ms < 0) return read_full(fd, buf, n);
    int64_t end = now_ms() + body_ms;
    unsigned char *p = buf;
    while (n) {
        int64_t left = end - now_ms();
        if (left <= 0) return -1;
        struct pollfd pf = { .fd = fd, .events = POLLIN };
        int r = poll(&pf, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        ssize_t got = read(fd, p, n);
        if (got > 0) { p += got; n -= (size_t)got; continue; }
        if (got < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return -1;
    }
    return 0;
}

int pb_ipc_recv_timeout(int fd, pb_msg *m, int body_ms)
{
    memset(m, 0, sizeof *m);
    unsigned char hdr[4];
    if (read_full(fd, hdr, 4) != 0) return -1;
    uint32_t l = get32(hdr);
    if (l < 2 || l > PB_IPC_MAX_FRAME) return -2;
    unsigned char *buf = malloc(l);
    if (!buf) return -1;
    if (read_full_by(fd, buf, l, body_ms) != 0) { free(buf); return -1; }
    int rc = pb_ipc_decode(buf, l, m);
    free(buf);
    return rc;
}

int pb_ipc_recv(int fd, pb_msg *m)
{
    return pb_ipc_recv_timeout(fd, m, -1);
}

int pb_ipc_send(int fd, unsigned n, const char *const *f, const size_t *len)
{
    size_t out_len;
    unsigned char *frame = pb_ipc_encode(n, f, len, &out_len);
    if (!frame) return -1;
    int rc = write_full(fd, frame, out_len);
    free(frame);
    return rc;
}

int pb_ipc_sendv(int fd, ...)
{
    const char *f[64];
    unsigned n = 0;
    va_list ap;
    va_start(ap, fd);
    const char *s;
    while (n < 64 && (s = va_arg(ap, const char *)) != NULL) f[n++] = s;
    va_end(ap);
    return pb_ipc_send(fd, n, f, NULL);
}
