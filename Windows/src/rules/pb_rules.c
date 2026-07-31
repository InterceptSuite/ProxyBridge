#include "pb_internal.h"

// Rule-management API: add / edit / delete / enable / disable / reorder rules.

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
        // Default to "*" = all IPs
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

    // Rules changed -> refresh the kernel driver's watch list so live Add/Edit/Delete/Enable
    // of proxy & block rules take effect immediately (no-op until the driver is started).
    pb_driver_sync_rules();
}
