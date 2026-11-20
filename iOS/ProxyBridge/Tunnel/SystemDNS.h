#ifndef SystemDNS_h
#define SystemDNS_h

#include <stddef.h>

/// Writes the numeric addresses of the system's DNS servers into `buffer`, one per line.
/// Returns how many were written.
int system_dns_servers(char *buffer, size_t size);

#endif
