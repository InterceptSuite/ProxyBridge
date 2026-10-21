// /proc helpers: which processes listen on a local TCP port, and which addresses belong to this host.
#ifndef PB_PROC_H
#define PB_PROC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// tgids of processes with a TCP socket in LISTEN state on `port` bound to `ip_be` or to 0.0.0.0. Returns the count (<= max).
size_t pb_proc_listeners(uint32_t ip_be, uint16_t port, uint32_t *tgids, size_t max);

// True if the process `pid` (a tgid) holds a LISTEN socket on `port` bound to `ip_be` or to 0.0.0.0. Looks at that one process only.
bool pb_proc_pid_listens(uint32_t pid, uint32_t ip_be, uint16_t port);

// Owners (uids) of the UDP sockets, v4 and v6, that are bound to local `port`; returns how many were found (<= max). Reads only
// /proc/net/udp and /proc/net/udp6, so it costs the same however many descriptors the owning process has.
size_t pb_proc_udp_port_uids(uint16_t port, uint32_t *uids, size_t max);

// True for 127.0.0.0/8 and for any IPv4 address configured on a local interface.
bool pb_proc_is_local_ip(uint32_t ip_be);

#endif
