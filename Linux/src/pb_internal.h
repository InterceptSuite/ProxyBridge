// Interfaces between the ProxyBridge modules: core (ProxyBridge.c, pb_bpf.c), kernel program, relay (pb_relay.c).
#ifndef PB_INTERNAL_H
#define PB_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include "ProxyBridge.h"

#define PB_TCP_RELAY_PORT_DEFAULT 24010   // outside the default ephemeral port range
#define PB_UDP_RELAY_PORT_DEFAULT 24011

#define PB_ACT_PROXY   0   // same values as RuleAction
#define PB_ACT_DIRECT  1
#define PB_ACT_BLOCK   2
#define PB_ACT_DECIDE  3   // the kernel could not decide: the relay calls pb_core_decide()

// Original destination of a redirected flow; layout shared with proxybridge.bpf.c.
struct pb_orig {
    uint8_t  addr[16];     // network order; IPv4 as ::ffff:a.b.c.d
    uint16_t port;         // host order
    uint16_t proxy_id;
    uint32_t pid;          // tgid of the process that opened the flow
    uint8_t  family;       // AF_INET or AF_INET6 of the original destination
    uint8_t  proto;        // IPPROTO_TCP or IPPROTO_UDP
    uint8_t  action;       // PB_ACT_PROXY or PB_ACT_DECIDE
    uint8_t  pad;
    uint32_t exe_dev;      // kernel-side identity of the executable (PB_ACT_DECIDE flows)
    uint32_t exe_pad;
    uint64_t exe_ino;
};

struct pb_decision {
    int      action;       // PB_ACT_PROXY, PB_ACT_DIRECT or PB_ACT_BLOCK
    uint32_t proxy_id;
};

struct pb_proxy {
    uint32_t  id;
    ProxyType type;
    char      name[64];
    char      host[256];   // IP literal or host name
    uint16_t  port;
    char      user[256];   // empty = no authentication
    char      pass[256];
};

// ---- provided by the core ----

// Original destination of a relayed TCP connection, keyed by the client's source address and port as accept() reports them.
// Consumes the entry; 0 on success.
int  pb_core_take_tcp_orig(uint32_t client_ip_be, uint16_t client_port, struct pb_orig *out);

// Original destination behind a UDP flow address (the IP_PKTINFO destination of a datagram). Does not consume.
int  pb_core_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out);

// Full rule evaluation for a PB_ACT_DECIDE flow.
void pb_core_decide(const struct pb_orig *o, struct pb_decision *out);

// Copy of the proxy with this id, or of the default proxy for id 0. 0 on success.
int  pb_core_get_proxy(uint32_t id, struct pb_proxy *out);

void pb_core_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

// Reports a relayed flow once its final action is known.
void pb_core_flow_event(const struct pb_orig *o, int action);

// DNS tap: called for every DNS message travelling server-to-client on a flow whose original port is 53 (UDP payload, or one
// complete TCP message without its length prefix), before the client receives it.
void pb_core_dns_observe(const uint8_t *msg, size_t len);

// ---- provided by the relay ----

struct pb_relay_cfg {
    uint16_t tcp_port;            // 0 = default
    uint16_t udp_port;            // 0 = default
    int      max_tcp_conns;       // 0 = 32768
    int      tcp_idle_timeout_s;  // 0 = 300
    int      udp_idle_timeout_s;  // 0 = 60
    int      handshake_timeout_s; // 0 = 10
};

// Returns -1 (after logging) and leaves nothing running on failure.
int  pb_relay_start(const struct pb_relay_cfg *cfg);
// Stops every thread and closes every fd; safe to call twice and to start again afterwards.
void pb_relay_stop(void);
uint16_t pb_relay_tcp_port(void);
uint16_t pb_relay_udp_port(void);

// Blocking test of a proxy: tunnels to target_host:target_port and writes a one-line result (or the error) to buf. 0 on success.
int  pb_relay_test_proxy(const struct pb_proxy *proxy, const char *target_host, uint16_t target_port, char *buf, size_t buflen);

#endif
