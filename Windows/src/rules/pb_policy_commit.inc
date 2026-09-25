#include "pb_profile_configs.inc"

static BOOL commit_prepared_policy(PROCESS_RULE *candidate, BOOL *flush, PROXY_CONFIG *configs, UINT32 count,
    UINT32 *config_ids, const BOOL *loopback, struct _PBDRV_WATCHLIST *watch,
    const UINT64 *expectedRules, const LONG64 *expectedProxy)
{
    if (watch == NULL) return FALSE;
    BOOL active = FALSE, domain = FALSE;
    for (const PROCESS_RULE *r = candidate; r != NULL; r = r->next) {
        if (r->enabled) {
            active = TRUE;
            if (rule_has_domain_filter(r)) domain = TRUE;
        }
    }
    AcquireSRWLockExclusive(&g_rules_lock);
    BOOL ok = TRUE;
    UINT32 next_config_id = 0;
    BOOL configs_changed = FALSE;
    if (configs != NULL) {
        AcquireSRWLockExclusive(&g_proxy_lock);
        if ((expectedRules && *expectedRules != g_rules_generation) ||
            (expectedProxy && *expectedProxy != InterlockedCompareExchange64(&g_proxy_revision, 0, 0))) {
            SetLastError(ERROR_REVISION_MISMATCH); ok = FALSE;
        }
        if (ok) ok = stage_profile_configs(configs, count, &next_config_id, &configs_changed);
        if (ok) for (PROCESS_RULE *r = candidate; r != NULL; r = r->next)
            if (r->proxy_config_id != 0) r->proxy_config_id = configs[r->proxy_config_id - 1].config_id;
    }
    if (ok) ok = loopback != NULL ? pb_driver_apply_profile_rules(watch, *loopback) : pb_driver_apply_rules(watch);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    PROCESS_RULE *old = NULL;
    if (ok) {
        if (loopback != NULL) g_localhost_via_proxy = !!*loopback;
        if (configs != NULL) {
            LONG64 revision = configs_changed ? InterlockedIncrement64(&g_proxy_revision)
                : InterlockedCompareExchange64(&g_proxy_revision, 0, 0);
            memset(g_proxy_configs, 0, sizeof(g_proxy_configs));
            for (UINT32 i = 0; i < count; ++i) {
                if (configs[i].revision == 0) configs[i].revision = revision;
                g_proxy_configs[i] = configs[i];
                config_ids[i] = configs[i].config_id;
            }
            g_proxy_config_count = (int)count;
            g_next_config_id = next_config_id;
        }
        old = rules_list;
        rules_list = candidate;
        ++g_rules_generation;
        *flush = domain && !g_has_domain_rules && running;
        g_has_active_rules = active;
        g_has_domain_rules = domain;
    }
    if (configs != NULL) ReleaseSRWLockExclusive(&g_proxy_lock);
    ReleaseSRWLockExclusive(&g_rules_lock);
    free(watch);
    free_rules(old);
    if (!ok) SetLastError(error);
    return ok;
}

static BOOL commit_policy(PROCESS_RULE *candidate, BOOL *flush, PROXY_CONFIG *configs, UINT32 count, UINT32 *config_ids, const BOOL *loopback)
{
    return commit_prepared_policy(candidate, flush, configs, count, config_ids, loopback,
        pb_driver_prepare_rules(candidate), NULL, NULL);
}

