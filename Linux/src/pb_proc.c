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

static size_t listen_inodes(uint32_t ip_be, uint16_t port, uint64_t *inodes)
{
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return 0;
    char line[512];
    size_t n = 0;
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0; }
    while (n < MAX_INODES && fgets(line, sizeof line, f)) {
        unsigned addr, lport, state;
        unsigned long long inode;
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
        if (sscanf(line, " %*d: %x:%x %*x:%*x %x %*x:%*x %*x:%*x %*x %*d %*d %llu", &addr, &lport, &state, &inode) != 4) continue;
        if (state == 0x0A && lport == port && inode && (addr == ip_be || addr == 0)) inodes[n++] = inode;
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
            if (pid_has_socket(de->d_name, inodes[i])) { tgids[n++] = (uint32_t)strtoul(de->d_name, NULL, 10); break; }
    }
    closedir(d);
    return n;
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
