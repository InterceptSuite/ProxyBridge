#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "pb_unit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// systemd's own quoting for one ExecStart word: backslash, double quote, % (specifier) and $ (variable) are escaped
static void quote_word(char *out, const char *s)
{
    *out++ = '"';
    for (; *s; s++) {
        if (*s == '\\' || *s == '"') *out++ = '\\';
        else if (*s == '%') *out++ = '%';
        else if (*s == '$') *out++ = '$';
        *out++ = *s;
    }
    *out++ = '"';
    *out = '\0';
}

char *pb_unit_text(const char *exe, const char **error)
{
    if (!exe || exe[0] != '/') { if (error) *error = "the program must be given as an absolute path"; return NULL; }
    for (const char *p = exe; *p; p++)
        if ((unsigned char)*p < 0x20 || *p == 0x7f) { if (error) *error = "the program path contains control characters"; return NULL; }
    size_t n = strlen(exe) * 2 + 8;
    char *quoted = malloc(n);
    if (!quoted) { if (error) *error = "out of memory"; return NULL; }
    quote_word(quoted, exe);
    char *text = NULL;
    // The service needs root for eBPF and /proc and nothing else: no new privileges, nothing writable but its own configuration
    // folder, no home directories, no other users' temporary files.
    int rc = asprintf(&text,
        "[Unit]\n"
        "Description=ProxyBridge\n"
        "Documentation=https://proxybridge.interceptsuite.com/docs/linux-settings/\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s --daemon\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "RuntimeDirectory=proxybridge\n"
        "RuntimeDirectoryMode=0755\n"
        "LimitNOFILE=1048576\n"
        "NoNewPrivileges=yes\n"
        "ProtectSystem=strict\n"
        "ReadWritePaths=/etc/proxybridge\n"
        "ProtectHome=yes\n"
        "PrivateTmp=yes\n"
        "ProtectKernelModules=yes\n"
        "ProtectKernelLogs=yes\n"
        "ProtectKernelTunables=yes\n"
        "ProtectControlGroups=yes\n"
        "ProtectClock=yes\n"
        "ProtectHostname=yes\n"
        "PrivateDevices=yes\n"
        "RestrictSUIDSGID=yes\n"
        "LockPersonality=yes\n"
        "RestrictRealtime=yes\n"
        "RestrictNamespaces=yes\n"
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
        "SystemCallArchitectures=native\n"
        "MemoryDenyWriteExecute=yes\n"
        "UMask=0077\n"
        "MemoryMax=1G\n"
        "TasksMax=512\n"
        // eBPF programs and their maps, attaching to the cgroup, raising limits, and reading what other users' processes run; no
        // chown, kill, setuid, module loading, raw I/O, mount or time changes
        "CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n", quoted);
    free(quoted);
    if (rc < 0) { if (error) *error = "out of memory"; return NULL; }
    return text;
}
