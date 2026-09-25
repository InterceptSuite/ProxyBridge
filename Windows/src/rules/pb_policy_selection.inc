// Keep profile publication excluded until the selected definition is copied.
// Lock order matches commit_policy: rules, then proxy. No callbacks or I/O here.
RuleAction pb_select_proxy(const char *process_name, BOOL v6, UINT32 ip,
                           const UINT8 ip6[16], UINT16 port, BOOL udp,
                           UINT32 *id, PROXY_CONFIG *config, BOOL *available)
{
    *id = 0;
    *available = FALSE;
    AcquireSRWLockShared(&g_rules_lock);
    RuleAction action = RULE_ACTION_PROXY;
    if (process_name != NULL)
        action = v6 ? match_rule_v6_inner(process_name, ip6, port, udp, id)
                    : match_rule_inner(process_name, ip, port, udp, id);
    if (action != RULE_ACTION_BLOCK)
        *available = find_proxy_config_copy(*id, config);
    ReleaseSRWLockShared(&g_rules_lock);
    return action;
}
