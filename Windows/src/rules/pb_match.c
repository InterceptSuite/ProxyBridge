#include "pb_internal.h"

// Rule matching engine: process/domain/wildcard matching and the match_rule decision.

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

        // Trim trailing whitespace (matters for CLI-parsed lists)
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
