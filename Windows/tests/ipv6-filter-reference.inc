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

