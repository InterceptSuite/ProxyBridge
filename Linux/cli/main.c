#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <proxybridge.h>

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    keep_running = 0;
    ProxyBridge_Stop();
}

static void event_handler(const struct net_event *event)
{
    char daddr_str[INET_ADDRSTRLEN];
    struct in_addr addr;

    addr.s_addr = event->daddr;
    if (!inet_ntop(AF_INET, &addr, daddr_str, INET_ADDRSTRLEN))
        return;

    printf("%-16s --> %s:%-5d - %s\n",
           event->comm,
           daddr_str,
           event->dport,
           (event->protocol == PROTO_TCP) ? "TCP" : "UDP");
}

int main(void)
{
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = ProxyBridge_Start();
    if (err) {
        fprintf(stderr, "Failed to start proxybridge: %d\n", err);
        return 1;
    }

    ProxyBridge_SetConnectionCallback(event_handler);

    printf("ProxyBridge started. Monitoring network connections...\n");
    printf("Press Ctrl+C to stop.\n");
    printf("%-16s    %-21s   %s\n", "PROCESS", "DESTINATION", "PROTOCOL");
    printf("%-16s    %-21s   %s\n", "-------", "-----------", "--------");

    while (keep_running) {
        err = ProxyBridge_Poll(100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling: %d\n", err);
            break;
        }
    }

    ProxyBridge_Stop();
    printf("\nProxyBridge stopped.\n");
    return 0;
}
