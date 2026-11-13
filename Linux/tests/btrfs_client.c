// Tiny client for e2e_btrfs.sh, copied onto a Btrfs subvolume so that it is the program whose identity is tested.
//   btrfs_client udp <ip> <port>        send "ping", print the reply (waits 3 s)
//   btrfs_client tcp <ip> <port> <ms>   connect, hold the connection open for <ms>, exit
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 4) return 2;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(argv[3])) };
    inet_pton(AF_INET, argv[2], &a.sin_addr);
    if (!strcmp(argv[1], "udp")) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) return 1;
        send(s, "ping", 4, 0);
        struct pollfd p = { .fd = s, .events = POLLIN };
        if (poll(&p, 1, 3000) == 1) {
            char b[256];
            ssize_t n = recv(s, b, sizeof b - 1, 0);
            if (n > 0) { b[n] = 0; printf("%s\n", b); }
        }
        return 0;
    }
    if (!strcmp(argv[1], "tcp") && argc >= 5) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        connect(s, (struct sockaddr *)&a, sizeof a);        // may never complete (an unroutable test address); the socket exists while we wait
        usleep((useconds_t)atoi(argv[4]) * 1000);
        return 0;
    }
    return 2;
}
