typedef struct PB_PREPARED_PROFILE {
    PROXY_CONFIG configs[MAX_PROXY_CONFIGS];
    PROCESS_RULE *rules;
    struct _PBDRV_WATCHLIST *watch;
    UINT32 configCount, ruleCount;
    UINT64 rulesGeneration;
    LONG64 proxyRevision;
    BOOL loopback;
} PB_PREPARED_PROFILE;

PROXYBRIDGE_API void ProxyBridge_DiscardProfile(void *handle)
{
    PB_PREPARED_PROFILE *profile = handle;
    if (!profile) return;
    free_rules(profile->rules); free(profile->watch);
    SecureZeroMemory(profile, sizeof(*profile)); free(profile);
}

PROXYBRIDGE_API void *ProxyBridge_PrepareProfile(const ProxyBridgeProxySpec *configs, UINT32 config_count,
    const ProxyBridgeRuleSpec *rules, UINT32 rule_count, BOOL loopback)
{
    if (config_count > MAX_PROXY_CONFIGS || (config_count && !configs) || (rule_count && !rules)) {
        SetLastError(ERROR_INVALID_PARAMETER); return NULL;
    }
    PB_PREPARED_PROFILE *profile = calloc(1, sizeof(*profile));
    if (!profile) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    profile->configCount = config_count; profile->ruleCount = rule_count; profile->loopback = !!loopback;
    AcquireSRWLockShared(&g_rules_lock);
    profile->rulesGeneration = g_rules_generation;
    profile->proxyRevision = InterlockedCompareExchange64(&g_proxy_revision, 0, 0);
    ReleaseSRWLockShared(&g_rules_lock);
    BOOL ok = TRUE;
    for (UINT32 i = 0; i < config_count && ok; ++i)
        ok = pb_proxy_prepare_definition(&configs[i], &profile->configs[i]);
    PROCESS_RULE **tail = &profile->rules;
    for (UINT32 i = 0; i < rule_count && ok; ++i) {
        const ProxyBridgeRuleSpec *input = &rules[i];
        if (input->proxy_config_id > config_count) { SetLastError(ERROR_NOT_FOUND); ok = FALSE; break; }
        PROCESS_RULE *rule = make_rule(input->process_name, input->target_hosts, input->target_ports,
            input->target_domains, input->protocol, input->action, input->proxy_config_id);
        if (!rule) { ok = FALSE; break; }
        rule->enabled = !!input->enabled;
        *tail = rule; tail = &rule->next;
    }
    if (ok) { profile->watch = pb_driver_prepare_rules(profile->rules); ok = profile->watch != NULL; }
    if (!ok) {
        DWORD error = GetLastError(); ProxyBridge_DiscardProfile(profile); SetLastError(error); return NULL;
    }
    return profile;
}

PROXYBRIDGE_API BOOL ProxyBridge_CommitProfile(void *handle, UINT32 *config_ids, UINT32 *rule_ids)
{
    PB_PREPARED_PROFILE *profile = handle;
    if (!profile) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    DWORD error = ERROR_SUCCESS;
    BOOL ok = FALSE, flush = FALSE;
    if ((profile->configCount && !config_ids) || (profile->ruleCount && !rule_ids)) error = ERROR_INVALID_PARAMETER;
    else if (!pb_rules_begin_update()) error = GetLastError();
    else {
        UINT32 count = profile->ruleCount;
        if (count && (g_next_rule_id == 0 || count - 1 > ~(UINT32)0 - g_next_rule_id))
            error = ERROR_ARITHMETIC_OVERFLOW;
        else {
            UINT32 id = g_next_rule_id;
            for (PROCESS_RULE *rule = profile->rules; rule; rule = rule->next) rule->rule_id = id++;
            struct _PBDRV_WATCHLIST *watch = profile->watch; profile->watch = NULL;
            ok = commit_prepared_policy(profile->rules, &flush, profile->configs, profile->configCount,
                config_ids, &profile->loopback, watch, &profile->rulesGeneration, &profile->proxyRevision);
            error = ok ? ERROR_SUCCESS : GetLastError();
            if (ok) {
                profile->rules = NULL; // Published list now owns them.
                for (UINT32 i = 0; i < count; ++i) rule_ids[i] = g_next_rule_id + i;
                g_next_rule_id += count;
            }
        }
        pb_rules_end_update();
    }
    ProxyBridge_DiscardProfile(profile);
    if (flush) flush_dns_resolver_cache();
    SetLastError(error); return ok;
}
