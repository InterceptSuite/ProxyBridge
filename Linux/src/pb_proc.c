#include <arpa/inet.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pb_proc.h"

#define MAX_INODES 8

static bool parse_number(const char *s, unsigned base, unsigned long long *out, const char **end)
{
    unsigned long long v = 0;
    const char *p = s;
    for (;; p++) {
        unsigned d;
        if (*p >= '0' && *p <= '9') d = (unsigned)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') d = (unsigned)(*p - 'a') + 10;
        else if (*p >= 'A' && *p <= 'F') d = (unsigned)(*p - 'A') + 10;
        else break;
        if (d >= base) break;
        v = v * base + d;
    }
    if (p == s) return false;
    *out = v;
    if (end) *end = p;
    return true;
}

// Fields of a /proc/net/tcp row: sl, local, remote, state, queues, timer, retrans, uid, timeout, inode.
static bool parse_tcp_row(char *line, uint32_t *addr, uint32_t *port, unsigned *state, unsigned long long *inode)
{
    char *fields[10], *save = NULL;
    size_t n = 0;
    for (char *t = strtok_r(line, " \t\n", &save); t && n < 10; t = strtok_r(NULL, " \t\n", &save)) fields[n++] = t;
    if (n < 10) return false;
    unsigned long long a, p, st;
    const char *colon;
    if (!parse_number(fields[1], 16, &a, &colon) || *colon != ':' || !parse_number(colon + 1, 16, &p, NULL)) return false;
    if (!parse_number(fields[3], 16, &st, NULL) || !parse_number(fields[9], 10, inode, NULL)) return false;
    *addr = (uint32_t)a;
    *port = (uint32_t)p;
    *state = (unsigned)st;
    return true;
}

static size_t listen_inodes(uint32_t ip_be, uint16_t port, uint64_t *inodes)
{
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return 0;
    char line[512];
    size_t n = 0;
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0; }
    while (n < MAX_INODES && fgets(line, sizeof line, f)) {
        uint32_t addr, lport;
        unsigned state;
        unsigned long long inode;
        if (!parse_tcp_row(line, &addr, &lport, &state, &inode)) continue;
        if (state == 0x0A && lport == port && inode && (addr == ip_be || addr == 0)) inodes[n++] = inode;
    }
    fclose(f);
    return n;
}

// Owners (uids) of the UDP sockets (v4 and v6, any local address) that are bound to `port`: the uid column of /proc/net/udp. The
// v6 address column is 32 hex digits, which parse_number wraps; only the port is used here.
static size_t udp_uids(const char *file, uint16_t port, uint32_t *uids, size_t n, size_t max)
{
    FILE *f = fopen(file, "r");
    if (!f) return n;
    char line[512];
    if (!fgets(line, sizeof line, f)) { fclose(f); return n; }
    while (n < max && fgets(line, sizeof line, f)) {
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
        char *fields[10], *save = NULL;
        size_t k = 0;
        for (char *t = strtok_r(line, " \t\n", &save); t && k < 10; t = strtok_r(NULL, " \t\n", &save)) fields[k++] = t;
        if (k < 10) continue;
        unsigned long long a, p, uid;
        const char *colon;
        if (!parse_number(fields[1], 16, &a, &colon) || *colon != ':' || !parse_number(colon + 1, 16, &p, NULL)) continue;
        if (p != port || !parse_number(fields[7], 10, &uid, NULL)) continue;
        uids[n++] = (uint32_t)uid;
    }
    fclose(f);
    return n;
}

static bool pid_has_socket(const char *pid, uint64_t inode)
{
    char dir[300], link[400], want[40], got[64];
    snprintf(dir, sizeof dir, "/proc/%.200s/fd", pid);
    snprintf(want, sizeof want, "socket:[%llu]", (unsigned long long)inode);
    DIR *d = opendir(dir);
    if (!d) return false;
    struct dirent *de;
    bool found = false;
    while (!found && (de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        snprintf(link, sizeof link, "%s/%.40s", dir, de->d_name);
        ssize_t r = readlink(link, got, sizeof got - 1);
        if (r > 0) { got[r] = 0; found = !strcmp(got, want); }
    }
    closedir(d);
    return found;
}

size_t pb_proc_listeners(uint32_t ip_be, uint16_t port, uint32_t *tgids, size_t max)
{
    uint64_t inodes[MAX_INODES];
    size_t ni = listen_inodes(ip_be, port, inodes), n = 0;
    if (!ni) return 0;
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    while (n < max && (de = readdir(d))) {
        if (de->d_name[0] < '1' || de->d_name[0] > '9') continue;
        for (size_t i = 0; i < ni; i++)
            if (pid_has_socket(de->d_name, inodes[i])) {
                unsigned long long pid;
                if (parse_number(de->d_name, 10, &pid, NULL)) tgids[n++] = (uint32_t)pid;
                break;
            }
    }
    closedir(d);
    return n;
}

bool pb_proc_pid_listens(uint32_t pid, uint32_t ip_be, uint16_t port)
{
    uint64_t inodes[MAX_INODES];
    size_t ni = listen_inodes(ip_be, port, inodes);
    char name[24];
    snprintf(name, sizeof name, "%u", pid);
    for (size_t i = 0; i < ni; i++)
        if (pid_has_socket(name, inodes[i])) return true;
    return false;
}

size_t pb_proc_udp_port_uids(uint16_t port, uint32_t *uids, size_t max)
{
    size_t n = udp_uids("/proc/net/udp", port, uids, 0, max);
    return udp_uids("/proc/net/udp6", port, uids, n, max);
}

bool pb_proc_is_local_ip(uint32_t ip_be)
{
    if ((ntohl(ip_be) >> 24) == 127) return true;
    struct ifaddrs *list, *a;
    if (getifaddrs(&list) != 0) return false;
    bool local = false;
    for (a = list; a && !local; a = a->ifa_next)
        local = a->ifa_addr && a->ifa_addr->sa_family == AF_INET && ((struct sockaddr_in *)a->ifa_addr)->sin_addr.s_addr == ip_be;
    freeifaddrs(list);
    return local;
}
