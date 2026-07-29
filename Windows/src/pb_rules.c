#include "pb_internal.h"

// Rules: IP/port/domain/process matching and the rule-management API.

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

RuleAction check_process_rule_v6(const UINT8 src_ip6[16], UINT16 src_port, const UINT8 dest_ip6[16], UINT16 dest_port, BOOL is_udp, DWORD *out_pid, UINT32 *out_proxy_config_id)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];

    pid = is_udp ? get_process_id_from_udp_connection_v6(src_ip6, src_port)
                 : get_process_id_from_connection_v6(src_ip6, src_port);
    if (out_pid) *out_pid = pid;
    if (pid == 0) return RULE_ACTION_DIRECT;
    if (pid == g_current_process_id) return RULE_ACTION_DIRECT;
    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
        return RULE_ACTION_DIRECT;

    UINT32 proxy_config_id = 0;
    RuleAction action = match_rule_v6(process_name, dest_ip6, dest_port, is_udp, &proxy_config_id);

    if (action == RULE_ACTION_PROXY)
    {
        PROXY_CONFIG *cfg = find_proxy_config(proxy_config_id);
        if (cfg == NULL || cfg->host[0] == '\0' || cfg->port == 0)
            return RULE_ACTION_DIRECT;
        if (is_udp && cfg->type == PROXY_TYPE_HTTP)
            return RULE_ACTION_DIRECT;
    }
    if (out_proxy_config_id) *out_proxy_config_id = proxy_config_id;
    return action;
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
// Nedd to Test all combination at sanme time
// Case-insensitive wildcard match; '*' matches any sequence (including empty).
// Handles multiple wildcards anywhere in the pattern, e.g. "*steam*", "fire*.exe".
BOOL wildcard_match(const char *pattern, const char *text)
{
    while (*text != '\0')
    {
        if (*pattern == '*')
        {
            while (*pattern == '*') pattern++;   // collapse consecutive *
            if (*pattern == '\0') return TRUE;   // trailing * matches rest
            while (*text != '\0')
            {
                if (wildcard_match(pattern, text))
                    return TRUE;
                text++;
            }
            return FALSE;
        }
        else
        {
            if (tolower((unsigned char)*pattern) != tolower((unsigned char)*text))
                return FALSE;
            pattern++;
            text++;
        }
    }
    while (*pattern == '*') pattern++;
    return *pattern == '\0';
}

BOOL match_process_pattern(const char *pattern, const char *process_full_path)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // Extract just the filename from the full path for comparison
    // Windows path sucks
    const char *filename = strrchr(process_full_path, '\\');
    if (filename != NULL)
        filename++; // Skip the backslash
    else
        filename = process_full_path; // No path separator, use as-is

    // Check if pattern contains path separators (backslash or forward slash)
    BOOL is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);

    // match against full path if pattern has a path separator, otherwise filename only
    const char *match_target = is_full_path_pattern ? process_full_path : filename;

    // Wildcard pattern: use full wildcard matcher (handles *, *x*, x*y, etc.)
    if (strchr(pattern, '*') != NULL)
        return wildcard_match(pattern, match_target);

    // No wildcard, plain case-insensitive comparison
    return _stricmp(pattern, match_target) == 0;
}

// Match process list: "chrome.exe;firefox.exe;*.bin"
BOOL match_process_list(const char *process_list, const char *process_name)
{
    if (process_list == NULL || process_list[0] == '\0' || strcmp(process_list, "*") == 0)
        return TRUE;

    // Stack buffer for the common short case; malloc only for unusually long lists.
    char   stackbuf[256];
    size_t len   = strnlen_s(process_list, MAX_LIST_SIZE) + 1;
    size_t dstsz = len;
    char  *list_copy;
    BOOL   on_heap = FALSE;
    if (len <= sizeof(stackbuf))
    {
        list_copy = stackbuf;
        dstsz     = sizeof(stackbuf);
    }
    else
    {
        list_copy = (char *)malloc(len);
        if (list_copy == NULL)
            return FALSE;
        on_heap = TRUE;
    }

    strncpy_s(list_copy, dstsz, process_list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;

    // Support both semicolon and comma as separators - Need to figure complex rules in CLI parsing
    char *token = strtok_s(list_copy, ",;", &context);
    while (token != NULL)
    {
        // Skip leading whitespace
        while (*token == ' ' || *token == '\t')
            token++;

        // Remove trailing whitespace   // this shit cause error in CLI parsing
        char *end = token + strnlen_s(token, MAX_LIST_SIZE) - 1;
        while (end > token && (*end == ' ' || *end == '\t'))
        {
            *end = '\0';
            end--;
        }

        // Remove quotes if present: "C:\some app.exe"  - Need to carefully handle this in CLI app
        if (*token == '"' && strnlen_s(token, MAX_LIST_SIZE) > 1)
        {
            token++;
            char *quote = strchr(token, '"');
            if (quote != NULL)
                *quote = '\0';
        }

        if (match_process_pattern(token, process_name))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, ",;", &context);
    }
    if (on_heap)
        free(list_copy);
    return matched;
}

// Match a single domain pattern against a resolved hostname (case-insensitive).
//   "*"              -> matches anything (no restriction)
//   "google.com"     -> exact match only
//   "*.google.com"   -> any subdomain AND the apex "google.com" itself
//   "*google*"       -> generic wildcard (handled by wildcard_match)
BOOL match_domain_pattern(const char *pattern, const char *domain)
{
    if (pattern == NULL || pattern[0] == '\0' || strcmp(pattern, "*") == 0)
        return TRUE;
    if (domain == NULL || domain[0] == '\0')
        return FALSE;

    // "*.example.com" should also match the bare apex "example.com" (Proxifier/Clash convention).
    if (pattern[0] == '*' && pattern[1] == '.' && pattern[2] != '\0')
    {
        if (_stricmp(pattern + 2, domain) == 0)
            return TRUE;
    }

    if (strchr(pattern, '*') != NULL)
        return wildcard_match(pattern, domain);

    return _stricmp(pattern, domain) == 0;
}

// Match a resolved hostname against a semicolon/comma separated domain list.
// Empty list or "*" means no restriction (matches anything, including unknown domain).
BOOL match_domain_list(const char *domain_list, const char *domain)
{
    if (domain_list == NULL || domain_list[0] == '\0' || strcmp(domain_list, "*") == 0)
        return TRUE;
    if (domain == NULL || domain[0] == '\0')
        return FALSE;

    // Stack buffer for the common short case; malloc only for unusually long lists.
    char   stackbuf[256];
    size_t len   = strnlen_s(domain_list, MAX_LIST_SIZE) + 1;
    size_t dstsz = len;
    char  *list_copy;
    BOOL   on_heap = FALSE;
    if (len <= sizeof(stackbuf))
    {
        list_copy = stackbuf;
        dstsz     = sizeof(stackbuf);
    }
    else
    {
        list_copy = (char *)malloc(len);
        if (list_copy == NULL)
            return FALSE;
        on_heap = TRUE;
    }

    strncpy_s(list_copy, dstsz, domain_list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;
    char *token = strtok_s(list_copy, ",;", &context);
    while (token != NULL)
    {
        while (*token == ' ' || *token == '\t')
            token++;
        char *end = token + strnlen_s(token, MAX_LIST_SIZE);
        while (end > token && (end[-1] == ' ' || end[-1] == '\t'))
            *(--end) = '\0';

        if (token[0] != '\0' && match_domain_pattern(token, domain))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, ",;", &context);
    }
    if (on_heap)
        free(list_copy);
    return matched;
}

// TRUE if the rule actually restricts by domain (non-empty and not "*").
BOOL rule_has_domain_filter(const PROCESS_RULE *rule)
{
    return rule->target_domains != NULL &&
           rule->target_domains[0] != '\0' &&
           strcmp(rule->target_domains, "*") != 0;
}

// Domain-filter gate used inside rule matching.
//   - rule has no domain restriction  -> always TRUE (preserves pre-domain behaviour)
//   - rule restricts by domain, IP has no resolved hostname -> FALSE (cache-miss: don't match)
//   - otherwise -> match the resolved hostname against the rule's domain list
BOOL match_domain_filter(const PROCESS_RULE *rule, const char *domain)
{
    if (!rule_has_domain_filter(rule))
        return TRUE;
    if (domain == NULL || domain[0] == '\0')
        return FALSE;
    return match_domain_list(rule->target_domains, domain);
}

BOOL is_broadcast_or_multicast(UINT32 ip)
{
    // note: Localhost (127.x.x.x) is now supported for proxying
    // This allows intercepting localhost connections for MITM scenarios

    BYTE first_octet = (ip >> 0) & 0xFF;
    BYTE second_octet = (ip >> 8) & 0xFF;

    // APIPA (Link-Local): 169.254.0.0/16 (169.254.x.x)
    if (first_octet == 169 && second_octet == 254)
        return TRUE;

    // Broadcast: 255.255.255.255
    if (ip == 0xFFFFFFFF)
        return TRUE;

    // x.x.x.255
    if ((ip & 0xFF000000) == 0xFF000000)
        return TRUE;

    // Multicast: 224.0.0.0 - 239.255.255.255 (first octet 224-239)
    if (first_octet >= 224 && first_octet <= 239)
        return TRUE;

    return FALSE;
}

// Unified rule matching function for both TCP and UDP
// Matches rules by process name, IP, port, and protocol
// Inner matcher - caller MUST hold g_rules_lock (shared) for the whole traversal so
// rules_list and the strings it points to cannot be freed/edited mid-match.
RuleAction match_rule_inner(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
{
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *wildcard_rule = NULL;  // Save fully wildcard rule for last

    // Resolve the destination hostname once (only when domain rules exist) from the
    // DNS-snoop cache. Reused for every rule's domain filter below. Cache miss -> unknown.
    char domain[256];
    const char *dst_domain = NULL;
    if (g_has_domain_rules && dns_cache_lookup(dest_ip, domain, sizeof(domain)))
        dst_domain = domain;

    while (rule != NULL)
    {
        if (!rule->enabled)
        {
            rule = rule->next;
            continue;
        }

        // Check protocol compatibility
        // RULE_PROTOCOL_BOTH (0x03) matches both TCP and UDP
        if (rule->protocol != RULE_PROTOCOL_BOTH)
        {
            if (rule->protocol == RULE_PROTOCOL_TCP && is_udp)
            {
                rule = rule->next;
                continue;
            }
            if (rule->protocol == RULE_PROTOCOL_UDP && !is_udp)
            {
                rule = rule->next;
                continue;
            }
        }

        // Check if this is a wildcard process rule
        BOOL is_wildcard_process = (strcmp(rule->process_name, "*") == 0 || strcmp(rule->process_name, "ANY") == 0);

        if (is_wildcard_process)
        {
            // Check if wildcard has specific filters
            BOOL has_ip_filter = (strcmp(rule->target_hosts, "*") != 0);
            BOOL has_port_filter = (strcmp(rule->target_ports, "*") != 0);
            BOOL has_domain_filter = rule_has_domain_filter(rule);

            if (has_ip_filter || has_port_filter || has_domain_filter)
            {
                // Filtered wildcard - check if it matches
                if (match_ip_list(rule->target_hosts, dest_ip) &&
                    match_port_list(rule->target_ports, dest_port) &&
                    match_domain_filter(rule, dst_domain))
                {
                    // Matched! Return this rule's action
                    if (out_proxy_config_id != NULL) *out_proxy_config_id = rule->proxy_config_id;
                    return rule->action;
                }
                // Didn't match, continue
                rule = rule->next;
                continue;
            }

            // Fully wildcard rule (no filters) - save for later
            if (wildcard_rule == NULL)
            {
                wildcard_rule = rule;
            }
            rule = rule->next;
            continue;
        }

        // Check if process name matches
        if (match_process_list(rule->process_name, process_name))
        {
            // Process matched! Check IP, port and domain filters
            if (match_ip_list(rule->target_hosts, dest_ip) &&
                match_port_list(rule->target_ports, dest_port) &&
                match_domain_filter(rule, dst_domain))
            {
                // All filters matched! Return this rule's action
                if (out_proxy_config_id != NULL) *out_proxy_config_id = rule->proxy_config_id;
                return rule->action;
            }
        }

        rule = rule->next;
    }

    // No specific rule matched, use wildcard if available
    if (wildcard_rule != NULL)
    {
        if (out_proxy_config_id != NULL) *out_proxy_config_id = wildcard_rule->proxy_config_id;
        return wildcard_rule->action;
    }

    // No rule matched at all
    if (out_proxy_config_id != NULL) *out_proxy_config_id = 0;
    return RULE_ACTION_DIRECT;
}

// Public matcher - takes the shared rules lock so a concurrent AddRule/EditRule/
// DeleteRule/MoveRule from the GUI thread cannot free a node/string mid-match.
RuleAction match_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
{
    AcquireSRWLockShared(&g_rules_lock);
    RuleAction action = match_rule_inner(process_name, dest_ip, dest_port, is_udp, out_proxy_config_id);
    ReleaseSRWLockShared(&g_rules_lock);
    return action;
}

// IPv6 variant of match_rule - uses match_ip_list_v6 for host patterns.
// Supports exact addresses ("::1"), CIDR ("2001:db8::/32"), and wildcards ("*").
// IPv4-format patterns in target_hosts are silently skipped for IPv6 traffic.
// Caller MUST hold g_rules_lock (shared) - see match_rule_v6 wrapper below.
RuleAction match_rule_v6_inner(const char *process_name, const UINT8 dest_ip6[16], UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
{
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *wildcard_rule = NULL;

    // Resolve the destination hostname once (only when domain rules exist) from the
    // IPv6 DNS-snoop cache. Reused for every rule's domain filter below.
    char domain[256];
    const char *dst_domain = NULL;
    if (g_has_domain_rules && dns_cache_lookup_v6(dest_ip6, domain, sizeof(domain)))
        dst_domain = domain;

    while (rule != NULL)
    {
        if (!rule->enabled)
        {
            rule = rule->next;
            continue;
        }

        if (rule->protocol != RULE_PROTOCOL_BOTH)
        {
            if (rule->protocol == RULE_PROTOCOL_TCP && is_udp) { rule = rule->next; continue; }
            if (rule->protocol == RULE_PROTOCOL_UDP && !is_udp) { rule = rule->next; continue; }
        }

        BOOL is_wildcard_process = (strcmp(rule->process_name, "*") == 0 || strcmp(rule->process_name, "ANY") == 0);

        if (is_wildcard_process)
        {
            BOOL has_ip_filter   = (strcmp(rule->target_hosts, "*") != 0);
            BOOL has_port_filter = (strcmp(rule->target_ports, "*") != 0);
            BOOL has_domain_filter = rule_has_domain_filter(rule);

            if (has_ip_filter || has_port_filter || has_domain_filter)
            {
                if (match_ip_list_v6(rule->target_hosts, dest_ip6) &&
                    match_port_list(rule->target_ports, dest_port) &&
                    match_domain_filter(rule, dst_domain))
                {
                    if (out_proxy_config_id != NULL) *out_proxy_config_id = rule->proxy_config_id;
                    return rule->action;
                }
                rule = rule->next;
                continue;
            }

            if (wildcard_rule == NULL)
                wildcard_rule = rule;
            rule = rule->next;
            continue;
        }

        if (match_process_list(rule->process_name, process_name))
        {
            if (match_ip_list_v6(rule->target_hosts, dest_ip6) &&
                match_port_list(rule->target_ports, dest_port) &&
                match_domain_filter(rule, dst_domain))
            {
                if (out_proxy_config_id != NULL) *out_proxy_config_id = rule->proxy_config_id;
                return rule->action;
            }
        }

        rule = rule->next;
    }

    if (wildcard_rule != NULL)
    {
        if (out_proxy_config_id != NULL) *out_proxy_config_id = wildcard_rule->proxy_config_id;
        return wildcard_rule->action;
    }

    if (out_proxy_config_id != NULL) *out_proxy_config_id = 0;
    return RULE_ACTION_DIRECT;
}

RuleAction match_rule_v6(const char *process_name, const UINT8 dest_ip6[16], UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
{
    AcquireSRWLockShared(&g_rules_lock);
    RuleAction action = match_rule_v6_inner(process_name, dest_ip6, dest_port, is_udp, out_proxy_config_id);
    ReleaseSRWLockShared(&g_rules_lock);
    return action;
}

RuleAction check_process_rule(UINT32 src_ip, UINT16 src_port, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, DWORD *out_pid, UINT32 *out_proxy_config_id)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];

    pid = is_udp ? get_process_id_from_udp_connection(src_ip, src_port) : get_process_id_from_connection(src_ip, src_port);
    if (pid == 0 && is_udp)
        pid = get_process_id_from_connection(src_ip, src_port);

        // this may cause issues - need to find alternative
    if (out_pid != NULL)
        *out_pid = pid;

    if (pid == 0)
        return RULE_ACTION_DIRECT;

    // Auto-exclude: Always bypass the process that loaded this DLL (prevents loops)
    if (pid == g_current_process_id)
        return RULE_ACTION_DIRECT;

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name)))
        return RULE_ACTION_DIRECT;

    // Use unified rule matching function
    UINT32 proxy_config_id = 0;
    RuleAction action = match_rule(process_name, dest_ip, dest_port, is_udp, &proxy_config_id);

    // Additional checks for proxy configuration
    if (action == RULE_ACTION_PROXY)
    {
        PROXY_CONFIG *cfg = find_proxy_config(proxy_config_id);
        if (cfg == NULL || cfg->host[0] == '\0' || cfg->port == 0)
            return RULE_ACTION_DIRECT;  // No proxy configured

        // UDP: HTTP proxy doesn't support UDP - use per-rule proxy config type
        if (is_udp && cfg->type == PROXY_TYPE_HTTP)
            return RULE_ACTION_DIRECT;
    }

    if (out_proxy_config_id != NULL)
        *out_proxy_config_id = proxy_config_id;

    return action;
}

PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, const char* target_domains, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id)
{
    if (process_name == NULL || process_name[0] == '\0')
        return 0;

    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (rule == NULL)
        return 0;

    rule->rule_id = g_next_rule_id++;
    strncpy_s(rule->process_name, MAX_PROCESS_NAME, process_name, _TRUNCATE);
    rule->protocol = protocol;
    rule->proxy_config_id = proxy_config_id;
    rule->target_hosts = NULL;
    rule->target_ports = NULL;
    rule->target_domains = NULL;

    if (target_hosts != NULL && target_hosts[0] != '\0')
    {
        size_t len = strnlen_s(target_hosts, MAX_LIST_SIZE) + 1;
        rule->target_hosts = (char *)malloc(len);
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
        strncpy_s(rule->target_hosts, len, target_hosts, _TRUNCATE);
    }
    else
    {
        // Default to "*" ll IPs
        rule->target_hosts = (char *)malloc(2);
        if (rule->target_hosts == NULL)
        {
            free(rule);
            return 0;
        }
        strcpy_s(rule->target_hosts, 2, "*");
    }

    // Dynamically allocate memory for target_ports no size limit!
    if (target_ports != NULL && target_ports[0] != '\0')
    {
        size_t len = strnlen_s(target_ports, MAX_LIST_SIZE) + 1;
        rule->target_ports = (char *)malloc(len);
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strncpy_s(rule->target_ports, len, target_ports, _TRUNCATE);
    }
    else
    {
        // Default to "*" - all ports
        rule->target_ports = (char *)malloc(2);
        if (rule->target_ports == NULL)
        {
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strcpy_s(rule->target_ports, 2, "*");
    }

    // target_domains: "" or NULL means no domain restriction (stored as "*")
    if (target_domains != NULL && target_domains[0] != '\0')
    {
        size_t len = strnlen_s(target_domains, MAX_LIST_SIZE) + 1;
        rule->target_domains = (char *)malloc(len);
        if (rule->target_domains == NULL)
        {
            free(rule->target_ports);
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strncpy_s(rule->target_domains, len, target_domains, _TRUNCATE);
    }
    else
    {
        rule->target_domains = (char *)malloc(2);
        if (rule->target_domains == NULL)
        {
            free(rule->target_ports);
            free(rule->target_hosts);
            free(rule);
            return 0;
        }
        strcpy_s(rule->target_domains, 2, "*");
    }

    rule->action = action;
    rule->enabled = TRUE;
    rule->next = NULL;

    // Append to tail so rules are evaluated in the order they were added,
    // matching the visual top-to-bottom order in the GUI (fixes issue #93).
    AcquireSRWLockExclusive(&g_rules_lock);
    if (rules_list == NULL)
    {
        rules_list = rule;
    }
    else
    {
        PROCESS_RULE *tail = rules_list;
        while (tail->next != NULL)
            tail = tail->next;
        tail->next = rule;
    }
    UINT32 new_id = rule->rule_id;
    ReleaseSRWLockExclusive(&g_rules_lock);

    update_has_active_rules();
    log_message("Added rule ID: %u for process '%s' (Protocol: %d, Action: %d, ProxyConfigId: %u, Domains: %s)", new_id, process_name, protocol, action, proxy_config_id, target_domains ? target_domains : "*");

    return new_id;
}

PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

    BOOL found = FALSE;
    AcquireSRWLockExclusive(&g_rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = TRUE;
            found = TRUE;
            break;
        }
        rule = rule->next;
    }
    ReleaseSRWLockExclusive(&g_rules_lock);

    if (found)
    {
        update_has_active_rules();
        log_message("Enabled rule ID: %u", rule_id);
    }
    return found;
}

PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

    BOOL found = FALSE;
    AcquireSRWLockExclusive(&g_rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            rule->enabled = FALSE;
            found = TRUE;
            break;
        }
        rule = rule->next;
    }
    ReleaseSRWLockExclusive(&g_rules_lock);

    if (found)
    {
        update_has_active_rules();  // Phase 1: Update fast-path flag
        log_message("Disabled rule ID: %u", rule_id);
    }
    return found;
}

PROXYBRIDGE_API BOOL ProxyBridge_DeleteRule(UINT32 rule_id)
{
    if (rule_id == 0)
        return FALSE;

    BOOL found = FALSE;
    AcquireSRWLockExclusive(&g_rules_lock);
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *prev = NULL;

    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            if (prev == NULL)
                rules_list = rule->next;
            else
                prev->next = rule->next;

            // Unlink + free under the exclusive lock so no reader can be mid-traversal
            // on this node (readers hold the shared lock; exclusive waits them out).
            if (rule->target_hosts != NULL)
                free(rule->target_hosts);
            if (rule->target_ports != NULL)
                free(rule->target_ports);
            if (rule->target_domains != NULL)
                free(rule->target_domains);
            free(rule);
            found = TRUE;
            break;
        }
        prev = rule;
        rule = rule->next;
    }
    ReleaseSRWLockExclusive(&g_rules_lock);

    if (found)
    {
        update_has_active_rules();
        log_message("Deleted rule ID: %u", rule_id);
    }
    return found;
}

PROXYBRIDGE_API BOOL ProxyBridge_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, const char* target_domains, RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id)
{
    if (rule_id == 0 || process_name == NULL || target_hosts == NULL || target_ports == NULL)
        return FALSE;

    // NULL/"" domains means "no restriction" -> stored as "*"
    const char *domains_in = (target_domains != NULL && target_domains[0] != '\0') ? target_domains : "*";

    // Allocate the three replacements up front (outside the lock) so a failure leaves the
    // rule untouched and the lock is held only for the pointer swap.
    char *new_hosts   = _strdup(target_hosts);
    char *new_ports   = _strdup(target_ports);
    char *new_domains = _strdup(domains_in);
    if (new_hosts == NULL || new_ports == NULL || new_domains == NULL)
    {
        free(new_hosts);
        free(new_ports);
        free(new_domains);
        return FALSE;
    }

    BOOL found = FALSE;
    AcquireSRWLockExclusive(&g_rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            strncpy_s(rule->process_name, MAX_PROCESS_NAME, process_name, _TRUNCATE);

            free(rule->target_hosts);
            free(rule->target_ports);
            free(rule->target_domains);
            rule->target_hosts   = new_hosts;
            rule->target_ports   = new_ports;
            rule->target_domains = new_domains;

            rule->protocol = protocol;
            rule->action = action;
            rule->proxy_config_id = proxy_config_id;
            found = TRUE;
            break;
        }
        rule = rule->next;
    }
    ReleaseSRWLockExclusive(&g_rules_lock);

    if (!found)
    {
        // rule_id not found - the pre-allocated strings were never installed, free them.
        free(new_hosts);
        free(new_ports);
        free(new_domains);
        return FALSE;
    }

    update_has_active_rules();
    log_message("Updated rule ID: %u (ProxyConfigId: %u, Domains: %s)", rule_id, proxy_config_id, domains_in);
    return TRUE;
}

PROXYBRIDGE_API UINT32 ProxyBridge_GetRulePosition(UINT32 rule_id)
{
    if (rule_id == 0)
        return 0;

    UINT32 position = 1;
    UINT32 result = 0;
    AcquireSRWLockShared(&g_rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
        {
            result = position;
            break;
        }
        position++;
        rule = rule->next;
    }
    ReleaseSRWLockShared(&g_rules_lock);
    return result;
}

PROXYBRIDGE_API BOOL ProxyBridge_MoveRuleToPosition(UINT32 rule_id, UINT32 new_position)
{
    if (rule_id == 0 || new_position == 0)
        return FALSE;

    // Relink under the exclusive lock so packet-path readers never see a half-moved list.
    AcquireSRWLockExclusive(&g_rules_lock);

    // first rule and remove it from current position
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *prev = NULL;

    while (rule != NULL)
    {
        if (rule->rule_id == rule_id)
            break;
        prev = rule;
        rule = rule->next;
    }

    if (rule == NULL)
    {
        ReleaseSRWLockExclusive(&g_rules_lock);
        return FALSE;
    }

    // Remove from current position
    if (prev == NULL)
    {
        rules_list = rule->next;
    }
    else
    {
        prev->next = rule->next;
    }

    // Insert at new position
    if (new_position == 1)
    {
        // Insert at head
        rule->next = rules_list;
        rules_list = rule;
    }
    else
    {
        // taken from stackflow
        PROCESS_RULE *current = rules_list;
        UINT32 pos = 1;

        while (current != NULL && pos < new_position - 1)
        {
            current = current->next;
            pos++;
        }

        if (current == NULL)
        {
            // position is beyond list end we can append to tail
            current = rules_list;
            while (current->next != NULL)
                current = current->next;
            current->next = rule;
            rule->next = NULL;
        }
        else
        {
            rule->next = current->next;
            current->next = rule;
        }
    }

    ReleaseSRWLockExclusive(&g_rules_lock);

    log_message("Moved rule ID %u to position %u", rule_id, new_position);
    return TRUE;
}

// Recomputes the fast-path flags. Takes the shared rules lock itself, so callers must
// NOT already hold g_rules_lock exclusive (SRW locks are non-recursive) - the rule API
// functions below release their exclusive lock before calling this.
void update_has_active_rules(void)
{
    BOOL has_active = FALSE;
    BOOL has_domain = FALSE;

    AcquireSRWLockShared(&g_rules_lock);
    PROCESS_RULE *rule = rules_list;
    while (rule != NULL)
    {
        if (rule->enabled)
        {
            has_active = TRUE;
            if (rule_has_domain_filter(rule))
            {
                has_domain = TRUE;
                break;  // both flags are now known
            }
        }
        rule = rule->next;
    }
    ReleaseSRWLockShared(&g_rules_lock);

    g_has_active_rules = has_active;

    // Edge trigger: when domain rules first become active, flush the OS DNS cache so
    // subsequent connections re-resolve and populate our snoop cache.
    if (has_domain && !g_has_domain_rules && running)
        flush_dns_resolver_cache();
    g_has_domain_rules = has_domain;
}

