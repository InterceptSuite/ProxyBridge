// Internal interfaces shared by the ProxyBridge Linux modules (eBPF backend).
//
//   proxybridge.bpf.c  kernel side: rewrites connect()/sendmsg() destinations to the relay
//   pb_rules.c         rule store, validation, full userspace matcher
//   pb_bpf.c           loads/attaches BPF, compiles rules into BPF maps, reads events
//   pb_relay.c         userspace relay: TCP (SOCKS5 / HTTP CONNECT), UDP (SOCKS5 UDP ASSOCIATE), DIRECT
//   ProxyBridge.c      public API glue
#ifndef PB_INTERNAL_H
#define PB_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include "ProxyBridge.h"

#define PB_TCP_RELAY_PORT_DEFAULT 24010   // outside the default ephemeral range 32768-60999
#define PB_UDP_RELAY_PORT_DEFAULT 24011

// ---------------------------------------------------------------------------------------------
// Decision values
// ---------------------------------------------------------------------------------------------
#define PB_ACT_PROXY   0   // matches RuleAction
#define PB_ACT_DIRECT  1
#define PB_ACT_BLOCK   2
#define PB_ACT_DECIDE  3   // kernel could not decide: relay must call pb_core_decide()

// ---------------------------------------------------------------------------------------------
// Original destination record. Produced by the BPF programs, looked up by the relay.
// Layout is shared with the BPF object: keep in sync with proxybridge.bpf.c (struct pb_orig).
// ---------------------------------------------------------------------------------------------
struct pb_orig {
    uint8_t  addr[16];     // original destination, network order. IPv4 is stored as ::ffff:a.b.c.d
    uint16_t port;         // original destination port, host order
    uint16_t proxy_id;     // valid when action == PB_ACT_PROXY
    uint32_t pid;          // tgid of the process that opened the flow
    uint8_t  family;       // AF_INET or AF_INET6 (of the ORIGINAL destination)
    uint8_t  proto;        // IPPROTO_TCP or IPPROTO_UDP
    uint8_t  action;       // PB_ACT_PROXY or PB_ACT_DECIDE (DIRECT/BLOCK never reach the relay from the kernel)
    uint8_t  pad;
    uint32_t exe_dev;      // kernel-side (dev, inode) of the process's executable (valid for PB_ACT_DECIDE flows)
    uint32_t exe_pad;
    uint64_t exe_ino;
};

// Result of a userspace decision (slow path).
struct pb_decision {
    int      action;       // PB_ACT_PROXY / PB_ACT_DIRECT / PB_ACT_BLOCK
    uint32_t proxy_id;     // for PB_ACT_PROXY
};

// A configured upstream proxy (snapshot copy handed to the relay; the relay owns the copy).
struct pb_proxy {
    uint32_t  id;
    ProxyType type;        // PROXY_TYPE_HTTP / PROXY_TYPE_SOCKS5
    char      name[64];
    char      host[256];   // IP literal or hostname (relay must resolve it, with a timeout, outside the epoll loop)
    uint16_t  port;
    char      user[256];   // empty string = no auth
    char      pass[256];
};

// ---------------------------------------------------------------------------------------------
// Services the CORE provides to the relay (implemented in pb_bpf.c / ProxyBridge.c)
// ---------------------------------------------------------------------------------------------

// TCP: original destination for a relayed connection, keyed by the *client's* source port as seen by the relay
// (accept() peer port; peer address is 127.0.0.1). Consumes (deletes) the entry. Returns 0 on success.
int  pb_core_take_tcp_orig(uint16_t client_port, struct pb_orig *out);

// UDP: original destination for a datagram, keyed by the loopback address it was sent to (IP_PKTINFO ipi_addr, network
// order). Does not delete (flows are shared and LRU-evicted). Returns 0 on success.
int  pb_core_get_udp_flow(uint32_t flow_ip_be, struct pb_orig *out);

// Slow-path decision for a pb_orig with action == PB_ACT_DECIDE (evaluates the full rule set for o->pid).
void pb_core_decide(const struct pb_orig *o, struct pb_decision *out);

// Copies the proxy config with this id (or the default proxy when id == 0). Returns 0 on success, -1 if unknown.
int  pb_core_get_proxy(uint32_t id, struct pb_proxy *out);

// Logging / events. Both thread-safe, may be called from any relay thread.
void pb_core_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
// One event per relayed flow after the final action is known (proxy_desc e.g. "SOCKS5 127.0.0.1:1080" / "DIRECT" / "BLOCK").
void pb_core_flow_event(const struct pb_orig *o, int action, const char *proxy_desc);

// DNS tap. The relay calls this for every DNS message travelling server->client on a flow whose ORIGINAL destination port is 53:
// the payload of each UDP reply datagram, or each complete TCP-DNS message (2-byte length prefix already stripped). It must be
// called BEFORE the message is delivered to the client, because the core uses it to arm kernel rules for the addresses in the
// answer. Thread-safe and cheap when no domain rules exist (returns immediately).
void pb_core_dns_observe(const uint8_t *msg, size_t len);

// Whether DNS (UDP/TCP port 53) should be sent through the proxy even if rules say DIRECT is not set. Informational.
bool pb_core_dns_via_proxy(void);

// ---------------------------------------------------------------------------------------------
// Services the RELAY provides to the core (implemented in pb_relay.c)
// ---------------------------------------------------------------------------------------------
struct pb_relay_cfg {
    uint16_t tcp_port;            // listen port on 127.0.0.1 (0 = PB_TCP_RELAY_PORT_DEFAULT)
    uint16_t udp_port;            // UDP listen port, bound with SO_BINDTODEVICE "lo" (0 = default)
    int      max_tcp_conns;       // hard cap on concurrent relayed TCP connections (0 = 32768)
    int      tcp_idle_timeout_s;  // 0 = 300
    int      udp_idle_timeout_s;  // 0 = 60
    int      handshake_timeout_s; // proxy connect + handshake budget (0 = 10)
};

// Binds the sockets (returns -1 and logs via pb_core_log on failure, leaving nothing running), starts the worker threads.
int  pb_relay_start(const struct pb_relay_cfg *cfg);
// Stops all threads, closes every fd (listeners, client/upstream sockets, epoll, eventfds). Safe to call twice. After it
// returns, pb_relay_start() must work again (no leaked listeners).
void pb_relay_stop(void);
// Actual ports in use (valid after a successful start).
uint16_t pb_relay_tcp_port(void);
uint16_t pb_relay_udp_port(void);

// Synchronous proxy test used by ProxyBridge_TestConnection: connects to `target_host:target_port` THROUGH `proxy` and sends
// an HTTP HEAD/GET if port is 80/443-ish (caller decides); returns bytes of response in buf (NUL-terminated) or -1 on error with
// a human readable reason in buf. Must not depend on relay_start(). 10 second budget.
int  pb_relay_test_proxy(const struct pb_proxy *proxy, const char *target_host, uint16_t target_port, char *buf, size_t buflen);

#endif
