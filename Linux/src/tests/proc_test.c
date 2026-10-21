// Unit test of pb_proc.c: which processes listen on a TCP port, and which addresses are local. Needs no root (own sockets only).
#include "../pb_proc.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int checks, fails;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static int listener(const char *ip, uint16_t *port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET };
    inet_pton(AF_INET, ip, &a.sin_addr);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 8) != 0) { close(s); return -1; }
    socklen_t l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    *port = ntohs(a.sin_port);
    return s;
}

static uint32_t be(const char *ip) { struct in_addr a; inet_pton(AF_INET, ip, &a); return a.s_addr; }

int main(void)
{
    uint32_t t[8];
    uint16_t port = 0;

    int s = listener("127.0.0.1", &port);
    CHECK(s >= 0);
    CHECK(pb_proc_listeners(be("127.0.0.1"), port, t, 8) == 1 && t[0] == (uint32_t)getpid());
    CHECK(pb_proc_listeners(be("127.0.0.2"), port, t, 8) == 0);                  // bound to another address
    CHECK(pb_proc_listeners(be("127.0.0.1"), (uint16_t)(port + 1), t, 8) == 0);  // nothing on that port
    CHECK(pb_proc_listeners(be("127.0.0.1"), 0, t, 8) == 0);
    CHECK(pb_proc_listeners(be("127.0.0.1"), port, t, 0) == 0);                  // no room

    // a connected (not listening) socket on the same port is not a listener
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    a.sin_addr.s_addr = be("127.0.0.1");
    CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0);
    CHECK(pb_proc_listeners(be("127.0.0.1"), port, t, 8) == 1);

    // a wildcard listener answers for every local address
    uint16_t wport = 0;
    int w = listener("0.0.0.0", &wport);
    CHECK(w >= 0 && pb_proc_listeners(be("127.0.0.1"), wport, t, 8) == 1 && t[0] == (uint32_t)getpid());
    CHECK(pb_proc_listeners(be("127.0.0.5"), wport, t, 8) == 1);

    // a child that inherits the socket is a listener too; both are reported, max limits the answer
    pid_t kid = fork();
    if (kid == 0) { sleep(5); _exit(0); }
    usleep(100000);
    size_t n = pb_proc_listeners(be("127.0.0.1"), port, t, 8);
    CHECK(n == 2);
    bool me = false, child = false;
    for (size_t i = 0; i < n; i++) { me |= t[i] == (uint32_t)getpid(); child |= t[i] == (uint32_t)kid; }
    CHECK(me && child);
    CHECK(pb_proc_listeners(be("127.0.0.1"), port, t, 1) == 1);

    // only the child holds it once we close our copy
    close(s);
    CHECK(pb_proc_listeners(be("127.0.0.1"), port, t, 8) == 1 && t[0] == (uint32_t)kid);
    kill(kid, SIGKILL);
    waitpid(kid, NULL, 0);
    CHECK(pb_proc_listeners(be("127.0.0.1"), port, t, 8) == 0);                  // gone with the process

    close(c);
    close(w);

    // local addresses
    CHECK(pb_proc_is_local_ip(be("127.0.0.1")) && pb_proc_is_local_ip(be("127.200.3.4")));
    CHECK(!pb_proc_is_local_ip(be("192.0.2.1")) && !pb_proc_is_local_ip(be("198.51.100.7")) && !pb_proc_is_local_ip(be("8.8.8.8")));
    struct ifaddrs *list, *i;
    int found = 0, ok = 0;
    if (getifaddrs(&list) == 0) {
        for (i = list; i; i = i->ifa_next)
            if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET) {
                found++;
                ok += pb_proc_is_local_ip(((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr);
            }
        freeifaddrs(list);
    }
    CHECK(found > 0 && ok == found);                                              // every configured address is local

    // who owns the UDP sockets bound to a port (the relay compares the owners' uid with the flow's owner)
    {
        uint32_t uids[8];
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in ua = { .sin_family = AF_INET };
        inet_pton(AF_INET, "127.0.0.1", &ua.sin_addr);
        bind(u, (struct sockaddr *)&ua, sizeof ua);
        socklen_t ul = sizeof ua;
        getsockname(u, (struct sockaddr *)&ua, &ul);
        uint16_t up = ntohs(ua.sin_port);
        CHECK(pb_proc_udp_port_uids(up, uids, 8) == 1 && uids[0] == (uint32_t)getuid());      // our own socket, with our uid
        CHECK(pb_proc_udp_port_uids((uint16_t)(up == 65535 ? 1 : up + 1), uids, 8) == 0);     // a port nobody holds
        int u6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (u6 >= 0) {
            struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
            bind(u6, (struct sockaddr *)&a6, sizeof a6);
            socklen_t l6 = sizeof a6;
            getsockname(u6, (struct sockaddr *)&a6, &l6);
            CHECK(pb_proc_udp_port_uids(ntohs(a6.sin6_port), uids, 8) == 1 && uids[0] == (uint32_t)getuid());   // IPv6 sockets are listed too
            close(u6);
        }
        // two sockets on one port (SO_REUSEPORT): both owners are listed, the limit is honoured
        int r1 = socket(AF_INET, SOCK_DGRAM, 0), r2 = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
        setsockopt(r1, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
        setsockopt(r2, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
        struct sockaddr_in ra = { .sin_family = AF_INET };
        inet_pton(AF_INET, "127.0.0.1", &ra.sin_addr);
        bind(r1, (struct sockaddr *)&ra, sizeof ra);
        socklen_t rl = sizeof ra;
        getsockname(r1, (struct sockaddr *)&ra, &rl);
        CHECK(bind(r2, (struct sockaddr *)&ra, sizeof ra) == 0);
        CHECK(pb_proc_udp_port_uids(ntohs(ra.sin_port), uids, 8) == 2 && pb_proc_udp_port_uids(ntohs(ra.sin_port), uids, 1) == 1);
        close(r1);
        close(r2);
        CHECK(pb_proc_udp_port_uids(ntohs(ra.sin_port), uids, 8) == 0);                         // gone with the sockets
        close(u);
    }

    printf("proc_test: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
