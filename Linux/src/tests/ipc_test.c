// Unit test of the service protocol framing (pb_ipc.c): round trips, every kind of malformed input, a fuzz run. Needs no root.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include "../pb_ipc.h"

static int checks, fails;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static void roundtrip(void)
{
    const char *f[] = { "q", "7", "proxy.add", "", "with space", "ünïcode", "tab\there" };
    size_t len;
    unsigned char *frame = pb_ipc_encode(7, f, NULL, &len);
    CHECK(frame && len > 4);
    CHECK(((size_t)frame[0] << 24 | frame[1] << 16 | frame[2] << 8 | frame[3]) == len - 4);
    pb_msg m;
    CHECK(pb_ipc_decode(frame + 4, len - 4, &m) == 0 && m.n == 7);
    for (unsigned i = 0; i < 7 && m.n == 7; i++) CHECK(strcmp(m.f[i], f[i]) == 0 && m.len[i] == strlen(f[i]));
    pb_msg_free(&m);
    free(frame);

    // binary data with NULs and an empty message
    const char blob[] = { 'a', 0, 'b', 0, 0, 'c' };
    const char *g[] = { blob };
    size_t gl[] = { sizeof blob };
    frame = pb_ipc_encode(1, g, gl, &len);
    CHECK(pb_ipc_decode(frame + 4, len - 4, &m) == 0 && m.n == 1 && m.len[0] == sizeof blob && memcmp(m.f[0], blob, sizeof blob) == 0 && m.f[0][sizeof blob] == '\0');
    pb_msg_free(&m);
    free(frame);
    frame = pb_ipc_encode(0, NULL, NULL, &len);
    CHECK(frame && pb_ipc_decode(frame + 4, len - 4, &m) == 0 && m.n == 0);
    pb_msg_free(&m);
    free(frame);
}

static void limits(void)
{
    size_t len;
    const char *f[1] = { "x" };
    CHECK(pb_ipc_encode(PB_IPC_MAX_FIELDS + 1, f, NULL, &len) == NULL);
    const char **many = calloc(PB_IPC_MAX_FIELDS, sizeof *many);
    for (int i = 0; i < PB_IPC_MAX_FIELDS; i++) many[i] = "";
    unsigned char *frame = pb_ipc_encode(PB_IPC_MAX_FIELDS, many, NULL, &len);
    pb_msg m;
    CHECK(frame && pb_ipc_decode(frame + 4, len - 4, &m) == 0 && m.n == PB_IPC_MAX_FIELDS);
    pb_msg_free(&m);
    free(frame);
    free(many);
    size_t big = PB_IPC_MAX_FRAME;
    char *huge = malloc(big);
    memset(huge, 'a', big);
    const char *h[] = { huge };
    size_t hl[] = { big };
    CHECK(pb_ipc_encode(1, h, hl, &len) == NULL);             // frame limit includes the headers
    free(huge);

    // decode refuses: a field count above the limit, a length past the end, trailing bytes, too short
    unsigned char bad1[] = { 0xff, 0xff };
    CHECK(pb_ipc_decode(bad1, sizeof bad1, &m) == -2);
    unsigned char bad2[] = { 0, 1, 0, 0, 0, 9, 'a' };
    CHECK(pb_ipc_decode(bad2, sizeof bad2, &m) == -2);
    unsigned char bad3[] = { 0, 1, 0, 0, 0, 1, 'a', 'x' };
    CHECK(pb_ipc_decode(bad3, sizeof bad3, &m) == -2);
    unsigned char bad4[] = { 0 };
    CHECK(pb_ipc_decode(bad4, sizeof bad4, &m) == -2);
    unsigned char bad5[] = { 0, 2, 0, 0, 0, 1, 'a' };           // announces two fields, holds one
    CHECK(pb_ipc_decode(bad5, sizeof bad5, &m) == -2);
    unsigned char bad6[] = { 0, 1, 0xff, 0xff, 0xff, 0xff, 'a' }; // length that would overflow an addition
    CHECK(pb_ipc_decode(bad6, sizeof bad6, &m) == -2);
}

static void every_truncation(void)
{
    const char *f[] = { "q", "1", "store.put", "name", "{\"a\":1}" };
    size_t len;
    unsigned char *frame = pb_ipc_encode(5, f, NULL, &len);
    pb_msg m;
    for (size_t cut = 0; cut < len - 4; cut++) CHECK(pb_ipc_decode(frame + 4, cut, &m) == -2);
    CHECK(pb_ipc_decode(frame + 4, len - 4, &m) == 0);
    pb_msg_free(&m);
    free(frame);
}

static void fuzz(void)
{
    srand(12345);
    unsigned char buf[400];
    int accepted = 0;
    for (int i = 0; i < 300000; i++) {
        size_t n = (size_t)(rand() % (int)sizeof buf);
        for (size_t k = 0; k < n; k++) buf[k] = (unsigned char)(rand() % 4 == 0 ? rand() : (rand() % 3));    // many small numbers: plausible counts and lengths
        pb_msg m;
        int rc = pb_ipc_decode(buf, n, &m);
        if (rc == 0) { accepted++; pb_msg_free(&m); }
    }
    CHECK(accepted > 0);
}

static void sockets(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    CHECK(pb_ipc_sendv(sv[0], "e", "log", "hello", (char *)NULL) == 0);
    pb_msg m;
    CHECK(pb_ipc_recv(sv[1], &m) == 0 && m.n == 3 && strcmp(m.f[2], "hello") == 0);
    pb_msg_free(&m);
    // two frames in one write, then a frame split across writes
    size_t l1, l2;
    const char *a[] = { "a" }, *b[] = { "bb", "cc" };
    unsigned char *f1 = pb_ipc_encode(1, a, NULL, &l1), *f2 = pb_ipc_encode(2, b, NULL, &l2);
    unsigned char *both = malloc(l1 + l2);
    memcpy(both, f1, l1); memcpy(both + l1, f2, l2);
    CHECK(write(sv[0], both, l1 + l2) == (ssize_t)(l1 + l2));
    CHECK(pb_ipc_recv(sv[1], &m) == 0 && m.n == 1); pb_msg_free(&m);
    CHECK(pb_ipc_recv(sv[1], &m) == 0 && m.n == 2 && strcmp(m.f[1], "cc") == 0); pb_msg_free(&m);
    CHECK(write(sv[0], f2, 3) == 3);
    CHECK(write(sv[0], f2 + 3, l2 - 3) == (ssize_t)(l2 - 3));
    CHECK(pb_ipc_recv(sv[1], &m) == 0 && m.n == 2); pb_msg_free(&m);
    // a header announcing more than the limit is refused before anything is read or allocated
    unsigned char hdr[4] = { 0x7f, 0xff, 0xff, 0xff };
    CHECK(write(sv[0], hdr, 4) == 4);
    CHECK(pb_ipc_recv(sv[1], &m) == -2);
    // an announced length shorter than the minimum
    unsigned char tiny[4] = { 0, 0, 0, 1 };
    CHECK(write(sv[0], tiny, 4) == 4);
    CHECK(pb_ipc_recv(sv[1], &m) == -2);
    // the peer vanishes in the middle of a frame
    CHECK(write(sv[0], f2, 6) == 6);
    close(sv[0]);
    CHECK(pb_ipc_recv(sv[1], &m) == -1);
    // writing to a closed peer fails (no SIGPIPE)
    int sv2[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
    close(sv2[1]);
    CHECK(pb_ipc_sendv(sv2[0], "e", "x", (char *)NULL) == -1);
    close(sv2[0]); close(sv[1]);
    free(f1); free(f2); free(both);
}

static void stalled_frame(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    unsigned char hdr[4] = { 0, 0, 0, 100 };                    // announces 100 bytes, sends 3
    CHECK(write(sv[0], hdr, 4) == 4 && write(sv[0], "abc", 3) == 3);
    pb_msg m;
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    CHECK(pb_ipc_recv_timeout(sv[1], &m, 300) == -1);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    CHECK(ms >= 250 && ms < 1500);                              // gave up after about the limit, not at once and not for ever
    // a frame that does arrive, slowly, inside the limit
    const char *f[] = { "slow" };
    size_t len;
    unsigned char *frame = pb_ipc_encode(1, f, NULL, &len);
    CHECK(write(sv[0], frame, 5) == 5);
    pid_t pid = fork();
    if (pid == 0) { usleep(100000); (void)!write(sv[0], frame + 5, len - 5); _exit(0); }
    CHECK(pb_ipc_recv_timeout(sv[1], &m, 2000) == 0 && m.n == 1 && strcmp(m.f[0], "slow") == 0);
    pb_msg_free(&m);
    free(frame);
    close(sv[0]); close(sv[1]);
}

int main(void)
{
    roundtrip();
    limits();
    every_truncation();
    fuzz();
    sockets();
    stalled_frame();
    printf("ipc_test: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
