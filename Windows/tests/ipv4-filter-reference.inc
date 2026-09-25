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

BOOL ip_match_wrapper(const char *token, const void *data)
{
    return match_ip_pattern(token, *(const UINT32*)data);
}

// Match IP list: "192.168.*.*;10.0.0.1"
BOOL match_ip_list(const char *ip_list, UINT32 ip)
{
    return parse_token_list(ip_list, ";", ip_match_wrapper, &ip);
}

