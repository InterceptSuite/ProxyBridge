// hookbench tcp|udp <ip> <port> <n> : measures connect() latency (tcp) or sendto() rate + loopback delivery (udp) to a local server it starts itself.
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
static double now_us(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e6 + t.tv_nsec / 1e3; }
static const char *ip; static int port, tcp;
static void *srv(void *a)
{
    (void)a;
    int s = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0), one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) }; inet_pton(AF_INET, ip, &sa.sin_addr);
    if (bind(s, (void *)&sa, sizeof sa)) { perror("bind"); exit(1); }
    if (tcp) { listen(s, 4096); for (;;) { int c = accept(s, 0, 0); if (c >= 0) close(c); } }
    char b[2048]; for (;;) recv(s, b, sizeof b, 0);
}
int main(int argc, char **argv)
{
    tcp = !strcmp(argv[1], "tcp"); ip = argv[2]; port = atoi(argv[3]); int n = atoi(argv[4]);
    pthread_t t; pthread_create(&t, 0, srv, 0); usleep(200000);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port) }; inet_pton(AF_INET, ip, &sa.sin_addr);
    if (tcp) {
        double sum = 0; int ok = 0;
        for (int i = 0; i < n; i++) { int s = socket(AF_INET, SOCK_STREAM, 0); double a = now_us(); int r = connect(s, (void *)&sa, sizeof sa); sum += now_us() - a; ok += !r; close(s); }
        printf("tcp connect %s:%d  ok=%d/%d  avg=%.2f us\n", ip, port, ok, n, sum / n);
    } else {
        int s = socket(AF_INET, SOCK_DGRAM, 0); char buf[64] = "x"; double a = now_us();
        for (int i = 0; i < n; i++) sendto(s, buf, 32, 0, (void *)&sa, sizeof sa);
        double d = now_us() - a;
        printf("udp sendto %s:%d  n=%d  %.3f us/call  %.0f kpps\n", ip, port, n, d / n, n / d * 1e3);
    }
    return 0;
}
