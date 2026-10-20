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

    // which process owns a UDP socket bound to a port (the relay uses it to tell a flow's own datagrams from an impostor's)
    {
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in ua = { .sin_family = AF_INET };
        inet_pton(AF_INET, "127.0.0.1", &ua.sin_addr);
        bind(u, (struct sockaddr *)&ua, sizeof ua);
        socklen_t ul = sizeof ua;
        getsockname(u, (struct sockaddr *)&ua, &ul);
        uint16_t up = ntohs(ua.sin_port);
        CHECK(pb_proc_pid_owns_udp((uint32_t)getpid(), up));                          // our own socket
        CHECK(!pb_proc_pid_owns_udp((uint32_t)getppid(), up));                        // not the parent's
        CHECK(!pb_proc_pid_owns_udp((uint32_t)getpid(), (uint16_t)(up == 65535 ? 1 : up + 1)));   // a port nobody here owns
        CHECK(!pb_proc_pid_owns_udp(4194000u, up));                                   // a process that does not exist
        int u6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (u6 >= 0) {
            struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
            bind(u6, (struct sockaddr *)&a6, sizeof a6);
            socklen_t l6 = sizeof a6;
            getsockname(u6, (struct sockaddr *)&a6, &l6);
            CHECK(pb_proc_pid_owns_udp((uint32_t)getpid(), ntohs(a6.sin6_port)));     // IPv6 sockets are found too
            close(u6);
        }
        int pp[2];
        pipe(pp);
        pid_t kid2 = fork();
        if (kid2 == 0) {                                                              // the child owns a socket, we do not
            int k = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in ka = { .sin_family = AF_INET };
            inet_pton(AF_INET, "127.0.0.1", &ka.sin_addr);
            bind(k, (struct sockaddr *)&ka, sizeof ka);
            socklen_t kl = sizeof ka;
            getsockname(k, (struct sockaddr *)&ka, &kl);
            uint16_t kp = ntohs(ka.sin_port);
            write(pp[1], &kp, sizeof kp);
            pause();
            _exit(0);
        }
        uint16_t kport = 0;
        CHECK(read(pp[0], &kport, sizeof kport) == (ssize_t)sizeof kport && kport != 0);
        CHECK(pb_proc_pid_owns_udp((uint32_t)kid2, kport));                           // the child owns it ...
        CHECK(!pb_proc_pid_owns_udp((uint32_t)getpid(), kport));                      // ... and we do not
        kill(kid2, SIGKILL);
        waitpid(kid2, NULL, 0);
        CHECK(!pb_proc_pid_owns_udp((uint32_t)kid2, kport));                          // gone with the process
        close(pp[0]);
        close(pp[1]);
        close(u);
    }

    printf("proc_test: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
