// Types shared between the BPF object and userspace (pb_bpf.c). Plain C, no kernel headers needed.
#ifndef PB_BPF_SHARED_H
#define PB_BPF_SHARED_H

#ifdef __BPF__
typedef __u8 pb_u8; typedef __u16 pb_u16; typedef __u32 pb_u32; typedef __u64 pb_u64;
#else
#include <stdint.h>
typedef uint8_t pb_u8; typedef uint16_t pb_u16; typedef uint32_t pb_u32; typedef uint64_t pb_u64;
#endif

#define PB_MAX_RULES        512
#define PB_MAX_CLASSES      2048
#define PB_RULES_PER_CLASS  16
#define PB_BPF_MAX_V4       4
#define PB_BPF_MAX_PORT     4

// cfg array slots
#define PB_CFG_ENABLED      0   // 1 when at least one rule is loaded
#define PB_CFG_SELF_TGID    1   // process that hosts the relay (never redirected)
#define PB_CFG_LOG          2   // 1 = emit events
#define PB_CFG_TCP_PORT     3
#define PB_CFG_UDP_PORT     4
#define PB_CFG_DNS_VIA_PROXY 5
#define PB_CFG_DNS_TAP      6   // 1 when a domain rule exists: port-53 flows of covered processes go through the relay
#define PB_CFG_NETNS_LO     7   // cookie of the network namespace the relay lives in; sockets in other namespaces are ignored
#define PB_CFG_NETNS_HI     8
#define PB_CFG_SLOTS        12

// brule flags
#define PB_RF_ANY_HOST      0x01
#define PB_RF_ANY_PORT      0x02
#define PB_RF_HOST_COMPLEX  0x04   // host pattern not representable: "maybe" for every destination
#define PB_RF_PORT_COMPLEX  0x08   // more port ranges than fit: "maybe" when the ports in the table do not match
#define PB_RF_HAS_V6        0x10   // rule has IPv6 patterns: "maybe" for IPv6 destinations
#define PB_RF_DOMAINS       0x40   // host list also contains domain patterns: answered by the dom_hit map (filled by the DNS tap)
#define PB_RF_UDP_DIRECT    0x20   // PROXY rule whose proxy cannot carry UDP (HTTP): UDP flows go direct

#define PB_CLASS_DECIDE     0xffffffffu   // pb_bclass.n value: always take the slow path for this binary

struct pb_exe_key { pb_u32 dev; pb_u32 pad; pb_u64 ino; };

struct pb_brule {
    pb_u16 proxy_id;
    pb_u8  action;       // 0 proxy, 1 direct, 2 block
    pb_u8  proto_mask;   // 1 tcp, 2 udp
    pb_u8  flags;
    pb_u8  n_v4;
    pb_u8  n_port;
    pb_u8  pad;
    struct { pb_u32 lo, hi; } v4[PB_BPF_MAX_V4];      // host order
    struct { pb_u16 lo, hi; } port[PB_BPF_MAX_PORT];  // host order
};

struct pb_dom_key { pb_u32 rule; pb_u32 ip; };   // ip in host order

struct pb_bclass {
    pb_u32 n;
    pb_u32 tap;          // 1: this binary is covered by a domain rule, so its DNS must be observed
    pb_u32 rule[PB_RULES_PER_CLASS];
};

struct pb_event {
    pb_u32 pid;
    pb_u8  comm[16];
    pb_u8  addr[16];
    pb_u16 port;
    pb_u16 proxy_id;
    pb_u8  family;
    pb_u8  proto;
    pb_u8  action;       // PB_ACT_*
    pb_u8  pad;
};

#endif
