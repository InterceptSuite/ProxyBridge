#include "pb_internal.h"

// Address/port pattern matching for rules (IPv4/IPv6 addresses + ports).

BOOL is_ipv6_multicast_or_linklocal(const UINT8 ip6[16])
{
    // Multicast: FF00::/8  (IPv6 has no broadcast; multicast replaces it)
    if (ip6[0] == 0xFF) return TRUE;
    // Link-local: FE80::/10  (equivalent to IPv4 APIPA 169.254.0.0/16)
    if (ip6[0] == 0xFE && (ip6[1] & 0xC0) == 0x80) return TRUE;
    // Site-local (deprecated RFC 3879): FEC0::/10 - still seen on old equipment
    if (ip6[0] == 0xFE && (ip6[1] & 0xC0) == 0xC0) return TRUE;
    // Unspecified address: :: (all-zeros) - equivalent to IPv4 0.0.0.0
    {
        static const UINT8 unspec[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        if (memcmp(ip6, unspec, 16) == 0) return TRUE;
    }
    return FALSE;
}

// Match IP pattern against IP address
// Supports: "*" (all), "192.168.1.1" (exact), "192.168.*.*" (wildcard)
BOOL match_ip_pattern(const char *pattern, UINT32 ip)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // check for IP range
    char *dash = strchr(pattern, '-');
    if (dash != NULL)
    {
        char start_ip_str[64], end_ip_str[64];
        size_t start_len = dash - pattern;
        if (start_len >= sizeof(start_ip_str))
            return FALSE;

        strncpy_s(start_ip_str, sizeof(start_ip_str), pattern, start_len);
        start_ip_str[start_len] = '\0';
        strncpy_s(end_ip_str, sizeof(end_ip_str), dash + 1, _TRUNCATE);

        // parse start and end IPs
        UINT32 start_ip = 0, end_ip = 0;
        int s1, s2, s3, s4, e1, e2, e3, e4;

        if (sscanf_s(start_ip_str, "%d.%d.%d.%d", &s1, &s2, &s3, &s4) == 4 &&
            sscanf_s(end_ip_str, "%d.%d.%d.%d", &e1, &e2, &e3, &e4) == 4)
        {
            // Reject out-of-range octets (<0 or >255): sscanf_s("%d") happily accepts e.g. 999
            // or -1, which would shift junk into the high bits and yield a bogus range match.
            if ((unsigned)s1 > 255 || (unsigned)s2 > 255 || (unsigned)s3 > 255 || (unsigned)s4 > 255 ||
                (unsigned)e1 > 255 || (unsigned)e2 > 255 || (unsigned)e3 > 255 || (unsigned)e4 > 255)
                return FALSE;

            start_ip = (s1 << 0) | (s2 << 8) | (s3 << 16) | (s4 << 24);
            end_ip = (e1 << 0) | (e2 << 8) | (e3 << 16) | (e4 << 24);

            // checking as network byte order would be wrong, compare as little-endian UINT32
            // change to big-endian for proper comparison
            UINT32 ip_be = ((ip & 0xFF) << 24) | ((ip & 0xFF00) << 8) | ((ip & 0xFF0000) >> 8) | ((ip & 0xFF000000) >> 24);
            UINT32 start_be = ((start_ip & 0xFF) << 24) | ((start_ip & 0xFF00) << 8) | ((start_ip & 0xFF0000) >> 8) | ((start_ip & 0xFF000000) >> 24);
            UINT32 end_be = ((end_ip & 0xFF) << 24) | ((end_ip & 0xFF00) << 8) | ((end_ip & 0xFF0000) >> 8) | ((end_ip & 0xFF000000) >> 24);

            return (ip_be >= start_be && ip_be <= end_be);
        }
        return FALSE;
    }

    // Extract 4 octets from IP (little-endian)
    unsigned char ip_octets[4];
    ip_octets[0] = (ip >> 0) & 0xFF;
    ip_octets[1] = (ip >> 8) & 0xFF;
    ip_octets[2] = (ip >> 16) & 0xFF;
    ip_octets[3] = (ip >> 24) & 0xFF;

    // Parse pattern manually
    char pattern_copy[256];
    strncpy_s(pattern_copy, sizeof(pattern_copy), pattern, _TRUNCATE);

    char pattern_octets[4][16];
    int octet_count = 0;
    int char_idx = 0;

    size_t pat_len = strnlen_s(pattern_copy, sizeof(pattern_copy));
    for (int i = 0; i <= (int)pat_len && octet_count < 4; i++)
    {
        if (pattern_copy[i] == '.' || pattern_copy[i] == '\0')
        {
            pattern_octets[octet_count][char_idx] = '\0';
            octet_count++;
            char_idx = 0;
            if (pattern_copy[i] == '\0')
                break;
        }
        else
        {
            if (char_idx < 15)
                pattern_octets[octet_count][char_idx++] = pattern_copy[i];
        }
    }

    if (octet_count != 4)
        return FALSE;

    for (int i = 0; i < 4; i++)
    {
        if (strcmp(pattern_octets[i], "*") == 0)
            continue;
        int pattern_val = atoi(pattern_octets[i]);
        if (pattern_val != ip_octets[i])
            return FALSE;
    }
    return TRUE;
}

// Match port pattern: "*", "80", "8000-9000"
BOOL match_port_pattern(const char *pattern, UINT16 port)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    char *dash = strchr(pattern, '-');
    if (dash != NULL)
    {
        int start_port = atoi(pattern);
        int end_port = atoi(dash + 1);
        return (port >= start_port && port <= end_port);
    }

    return (port == atoi(pattern));
}

BOOL ip_match_wrapper(const char *token, const void *data)
{
    return match_ip_pattern(token, *(const UINT32*)data);
}

// Match IP list: "192.168.*.*;10.0.0.1"
BOOL match_ip_list(const char *ip_list, UINT32 ip)
{
    return parse_token_list(ip_list, ";", ip_match_wrapper, &ip);
}

// Match IPv6 pattern against a 16-byte address.
// Supports: "*" (all), exact ("::1", "2001:db8::1"),
//           CIDR  ("2001:db8::/32", "fe80::/10"),
//           range ("2001:db8::1-2001:db8::ff").
// IPv4 patterns (no ':') never match an IPv6 address.
BOOL match_ip_pattern_v6(const char *pattern, const UINT8 ip6[16])
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // IPv4-only pattern: cannot match IPv6
    if (strchr(pattern, ':') == NULL)
        return FALSE;

    char pat_copy[128];
    strncpy_s(pat_copy, sizeof(pat_copy), pattern, _TRUNCATE);

    // CIDR notation, e.g. "2001:db8::/32"
    char *slash = strchr(pat_copy, '/');
    if (slash != NULL)
    {
        *slash = '\0';
        int prefix_len = atoi(slash + 1);
        if (prefix_len < 0 || prefix_len > 128)
            return FALSE;

        UINT8 network[16];
        if (inet_pton(AF_INET6, pat_copy, network) != 1)
            return FALSE;

        int full_bytes = prefix_len / 8;
        int rem_bits   = prefix_len % 8;

        if (full_bytes > 0 && memcmp(ip6, network, full_bytes) != 0)
            return FALSE;

        if (rem_bits > 0)
        {
            UINT8 mask = (UINT8)(0xFF << (8 - rem_bits));
            if ((ip6[full_bytes] & mask) != (network[full_bytes] & mask))
                return FALSE;
        }
        return TRUE;
    }

    // Range notation: "2001:db8::1-2001:db8::ff"
    // IPv6 addresses contain no '-', so the first '-' is unambiguously the separator.
    char *dash = strchr(pat_copy, '-');
    if (dash != NULL)
    {
        *dash = '\0';
        const char *end_str = dash + 1;

        UINT8 start6[16], end6[16];
        if (inet_pton(AF_INET6, pat_copy, start6) != 1 ||
            inet_pton(AF_INET6, end_str,   end6)   != 1)
            return FALSE;

        // inet_pton produces network byte order (big-endian), so memcmp
        // gives correct numeric ordering for IPv6 addresses.
        return (memcmp(ip6, start6, 16) >= 0 &&
                memcmp(ip6, end6,   16) <= 0);
    }

    // Exact IPv6 address match
    UINT8 addr6[16];
    if (inet_pton(AF_INET6, pattern, addr6) != 1)
        return FALSE;
    return memcmp(ip6, addr6, 16) == 0;
}

BOOL ip_match_wrapper_v6(const char *token, const void *data)
{
    return match_ip_pattern_v6(token, (const UINT8*)data);
}

// Match IPv6 address against a semicolon-separated host list
BOOL match_ip_list_v6(const char *ip_list, const UINT8 ip6[16])
{
    return parse_token_list(ip_list, ";", ip_match_wrapper_v6, ip6);
}

BOOL port_match_wrapper(const char *token, const void *data)
{
    return match_port_pattern(token, *(const UINT16*)data);
}

// Match port list: "80;443;8000-9000"
BOOL match_port_list(const char *port_list, UINT16 port)
{
    return parse_token_list(port_list, ",;", port_match_wrapper, &port);
}

// Match process name with wildcard support
// Supports: "*" (all),
// "chrome.exe" (exact), "fire*.exe" (wildcard), "*.bin" (extension wildcard)
// added support for full paths - C:\Program Files\Google\Chrome\Application\chrome.exe
