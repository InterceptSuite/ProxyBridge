#include "SystemDNS.h"

#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>

int system_dns_servers(char *buffer, size_t size) {
    struct __res_state state;
    memset(&state, 0, sizeof(state));
    if (res_ninit(&state) != 0) {
        return 0;
    }

    union res_sockaddr_union servers[MAXNS];
    int count = res_getservers(&state, servers, MAXNS);
    size_t used = 0;
    int written = 0;

    for (int i = 0; i < count; i++) {
        struct sockaddr *address = (struct sockaddr *)&servers[i];
        socklen_t length;
        if (address->sa_family == AF_INET) {
            length = sizeof(struct sockaddr_in);
        } else if (address->sa_family == AF_INET6) {
            length = sizeof(struct sockaddr_in6);
        } else {
            continue;
        }

        char host[NI_MAXHOST];
        if (getnameinfo(address, length, host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0) {
            continue;
        }
        size_t needed = strlen(host) + 1;
        if (used + needed + 1 > size) {
            break;
        }
        memcpy(buffer + used, host, needed - 1);
        buffer[used + needed - 1] = '\n';
        used += needed;
        written++;
    }

    if (size > 0) {
        buffer[used < size ? used : size - 1] = '\0';
    }
    res_nclose(&state);
    return written;
}
