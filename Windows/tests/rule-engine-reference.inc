RuleAction reference_rule_inner(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
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
                    match_domain_list(rule->target_domains, dst_domain))
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
                match_domain_list(rule->target_domains, dst_domain))
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
RuleAction reference_rule(const char *process_name, UINT32 dest_ip, UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
{
    AcquireSRWLockShared(&g_rules_lock);
    RuleAction action = reference_rule_inner(process_name, dest_ip, dest_port, is_udp, out_proxy_config_id);
    ReleaseSRWLockShared(&g_rules_lock);
    return action;
}

// IPv6 variant of reference_rule - uses match_ip_list_v6 for host patterns.
// Supports exact addresses ("::1"), CIDR ("2001:db8::/32"), and wildcards ("*").
// IPv4-format patterns in target_hosts are silently skipped for IPv6 traffic.
// Caller MUST hold g_rules_lock (shared) - see reference_rule_v6 wrapper below.
RuleAction reference_rule_v6_inner(const char *process_name, const UINT8 dest_ip6[16], UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
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
                    match_domain_list(rule->target_domains, dst_domain))
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
                match_domain_list(rule->target_domains, dst_domain))
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

RuleAction reference_rule_v6(const char *process_name, const UINT8 dest_ip6[16], UINT16 dest_port, BOOL is_udp, UINT32 *out_proxy_config_id)
{
    AcquireSRWLockShared(&g_rules_lock);
    RuleAction action = reference_rule_v6_inner(process_name, dest_ip6, dest_port, is_udp, out_proxy_config_id);
    ReleaseSRWLockShared(&g_rules_lock);
    return action;
}
