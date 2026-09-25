static BOOL same_proxy_definition(const PROXY_CONFIG *a, const PROXY_CONFIG *b)
{
    return a->type == b->type && a->port == b->port && a->resolved_ip == b->resolved_ip &&
        !!a->send_domain_to_proxy == !!b->send_domain_to_proxy &&
        !strcmp(a->host, b->host) && !strcmp(a->username, b->username) && !strcmp(a->password, b->password);
}

// Called with rules/proxy locks held. Mutates only unpublished definitions.
// Equal duplicates consume different old slots; no two entries acquire one ID.
static BOOL stage_profile_configs(PROXY_CONFIG *configs, UINT32 count, UINT32 *next, BOOL *changed)
{
    BOOL used[MAX_PROXY_CONFIGS] = {0};
    *next = g_next_config_id;
    *changed = count != (UINT32)g_proxy_config_count;
    for (UINT32 i = 0; i < count; ++i) {
        configs[i].config_id = 0; configs[i].revision = 0;
        for (int j = 0; j < g_proxy_config_count; ++j) {
            if (!used[j] && g_proxy_configs[j].config_id != 0 && same_proxy_definition(&configs[i], &g_proxy_configs[j])) {
                used[j] = TRUE;
                configs[i].config_id = g_proxy_configs[j].config_id;
                configs[i].revision = g_proxy_configs[j].revision;
                break;
            }
        }
        if (configs[i].config_id == 0) {
            if (*next == 0) { SetLastError(ERROR_ARITHMETIC_OVERFLOW); return FALSE; }
            configs[i].config_id = (*next)++;
            *changed = TRUE;
        }
        if (i < (UINT32)g_proxy_config_count && configs[i].config_id != g_proxy_configs[i].config_id)
            *changed = TRUE;
    }
    return TRUE;
}
