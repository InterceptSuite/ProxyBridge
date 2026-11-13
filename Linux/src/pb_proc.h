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

// Identity of the executable of process `pid`, in the form the BPF program records it: *dev is the device number of the file system
// (the superblock's, major << 20 | minor) and *ino the inode. stat() cannot be used for this: on Btrfs it reports a different, per-subvolume
// device number than the superblock's, so the same file would never match the kernel's record. Returns 0, or -1 if the process or its
// executable is gone or unreadable.
int pb_proc_exe_identity(uint32_t pid, uint32_t *dev, uint64_t *ino);

// The device (major << 20 | minor) of the mount with id `mnt_id` in a mountinfo text (the numbers /proc/PID/mountinfo prints for the
// file system's superblock). Pure; exposed for the tests. True if the mount is listed.
bool pb_mountinfo_dev(const char *text, unsigned mnt_id, uint32_t *dev);

#endif
