// DNS awareness: learns IPv4 -> domain-name mappings from DNS answers that pass through the relay (the "DNS tap") so that
// domain rules can be applied to connections the kernel only sees as IP addresses.
#ifndef PB_DNS_H
#define PB_DNS_H

#include <stddef.h>
#include <stdint.h>

#define PB_DNS_MAX_NAMES   8
#define PB_DNS_MAX_ENTRIES 32768     // bounded: oldest mappings are evicted first

struct pb_dns_result {
    uint32_t ips[32]; int nips;              // addresses (host order) whose mapping was added or refreshed
    uint32_t evicted[32]; int nevicted;      // addresses dropped to stay within PB_DNS_MAX_ENTRIES
};

// Parses a DNS response message (no TCP length prefix). Returns the number of A records learned (0 if the message is not a
// successful response or has no A records). Safe on arbitrary/malicious input.
int  pb_dns_observe(const uint8_t *msg, size_t len, struct pb_dns_result *res);

// Copies up to max names known for ip (host order) into out; returns the count.
int  pb_dns_lookup(uint32_t ip, char out[][256], int max);

// Adds static mappings from /etc/hosts. Returns the number of addresses added.
int  pb_dns_load_hosts(const char *path, struct pb_dns_result *res);

// Visits every mapping (used to re-arm kernel state after a rule change). cb must not call back into pb_dns_*.
void pb_dns_for_each(void (*cb)(uint32_t ip, const char *const *names, int n, void *ctx), void *ctx);

void pb_dns_clear(void);
size_t pb_dns_count(void);

#endif
