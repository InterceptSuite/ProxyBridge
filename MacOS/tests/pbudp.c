// Small UDP client for the ProxyBridge macOS tests. The test rules match it by process name
// ("pbudp"), which keeps it apart from the Python test proxies (rules match on process only).
//
//   pbudp ntp <ip>             one NTP exchange, prints the reply size (48 = answered)
//   pbudp flood <n> <hold_s>   n UDP sockets, one packet each to 192.0.2.1:40000 (a documentation
//                              address, nothing answers), sockets held open for hold_s seconds
//
// build: cc -O2 -o pbudp pbudp.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "ntp")) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct timeval tv = {6, 0};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(123);
        inet_pton(AF_INET, argv[2], &a.sin_addr);
        unsigned char q[48] = {0x1b};
        sendto(s, q, 48, 0, (struct sockaddr *)&a, sizeof a);
        unsigned char r[512];
        ssize_t n = recv(s, r, sizeof r, 0);
        printf("%zd\n", n);
        return n == 48 ? 0 : 1;
    }
    if (argc >= 4 && !strcmp(argv[1], "flood")) {
        int n = atoi(argv[2]), hold = atoi(argv[3]);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(40000);
        inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
        for (int i = 0; i < n; i++) {
            int s = socket(AF_INET, SOCK_DGRAM, 0);
            sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a);
            usleep(10000);
        }
        printf("opened %d\n", n);
        fflush(stdout);
        sleep(hold);
        return 0;
    }
    fprintf(stderr, "usage: pbudp ntp <ip> | pbudp flood <n> <hold_seconds>\n");
    return 2;
}
