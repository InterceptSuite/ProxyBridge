#include "pb_internal.h"

// One writer prepares a complete candidate; readers keep using the old list.
// Activation/reconnect uses this same gate through publication of its handle.
static SRWLOCK g_rules_writer = SRWLOCK_INIT;

BOOL pb_rules_begin_update(void)
{
    if (TryAcquireSRWLockExclusive(&g_rules_writer)) return TRUE;
    SetLastError(ERROR_BUSY); // includes reentrant edits from log callbacks
    return FALSE;
}

void pb_rules_end_update(void)
{
    ReleaseSRWLockExclusive(&g_rules_writer);
}

#include "pb_rule_storage.inc"

static BOOL snapshot_rules(PROCESS_RULE **out)
{
    *out = NULL;
    PROCESS_RULE **tail = out;
    AcquireSRWLockShared(&g_rules_lock);
    for (const PROCESS_RULE *r = rules_list; r != NULL; r = r->next) {
        *tail = copy_rule(r);
        if (*tail == NULL) {
            ReleaseSRWLockShared(&g_rules_lock);
            free_rules(*out);
            *out = NULL;
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        tail = &(*tail)->next;
    }
    ReleaseSRWLockShared(&g_rules_lock);
    return TRUE;
}

static PROCESS_RULE *make_rule(const char *process, const char *hosts, const char *ports,
                               const char *domains, RuleProtocol protocol,
                               RuleAction action, UINT32 proxy)
{
    if (!process || !*process || strnlen_s(process, MAX_PROCESS_NAME) >= MAX_PROCESS_NAME ||
        (hosts && strnlen_s(hosts, MAX_LIST_SIZE) >= MAX_LIST_SIZE) ||
        (ports && strnlen_s(ports, MAX_LIST_SIZE) >= MAX_LIST_SIZE) ||
        (domains && strnlen_s(domains, MAX_LIST_SIZE) >= MAX_LIST_SIZE) ||
        (protocol != RULE_PROTOCOL_TCP && protocol != RULE_PROTOCOL_UDP && protocol != RULE_PROTOCOL_BOTH) ||
        (action != RULE_ACTION_DIRECT && action != RULE_ACTION_PROXY && action != RULE_ACTION_BLOCK)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    PROCESS_RULE source = {0};
    strcpy_s(source.process_name, MAX_PROCESS_NAME, process);
    source.target_hosts = (char *)(hosts && *hosts ? hosts : "*");
    source.target_ports = (char *)(ports && *ports ? ports : "*");
    source.target_domains = (char *)(domains && *domains ? domains : "*");
    source.protocol = protocol;
    source.action = action;
    source.proxy_config_id = proxy;
    source.enabled = TRUE;
    PROCESS_RULE *result = copy_rule(&source);
    if (result == NULL) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return result;
}

// Consumes candidate only on success. Preparation and callbacks occur outside
// the readers' lock. The IOCTL and list/flag publication exclude rule matching:
// a reader cannot observe the new user policy before the kernel accepts it.
#include "pb_policy_commit.inc"

static BOOL commit_rules(PROCESS_RULE *candidate, BOOL *flush)
{
    return commit_policy(candidate, flush, NULL, 0, NULL, NULL);
}

PROXYBRIDGE_API UINT32 ProxyBridge_AddRuleEx(const char *process_name, const char *target_hosts,
    const char *target_ports, const char *target_domains, RuleProtocol protocol,
    RuleAction action, UINT32 proxy_config_id, BOOL enabled, UINT32 position)
{
    PROCESS_RULE *added = make_rule(process_name, target_hosts, target_ports, target_domains,
                                    protocol, action, proxy_config_id);
    if (added == NULL) return 0;
    if (!pb_rules_begin_update()) { free_rules(added); SetLastError(ERROR_BUSY); return 0; }
    PROCESS_RULE *candidate = NULL;
    BOOL ok = snapshot_rules(&candidate), flush = FALSE;
    UINT32 id = 0;
    if (ok && g_next_rule_id == 0) { SetLastError(ERROR_ARITHMETIC_OVERFLOW); ok = FALSE; }
    if (ok) {
        added->rule_id = g_next_rule_id;
        added->enabled = !!enabled;
        PROCESS_RULE **tail = &candidate;
        for (UINT32 i = 1; *tail != NULL && (position == 0 || i < position); ++i) tail = &(*tail)->next;
        added->next = *tail;
        *tail = added;
        added = NULL;
        ok = commit_rules(candidate, &flush);
        if (ok) id = g_next_rule_id++;
    }
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) free_rules(candidate);
    free_rules(added);
    pb_rules_end_update();
    if (flush) flush_dns_resolver_cache(); // preserve existing domain-rule edge trigger
    if (ok) log_message("Added rule ID: %u", id);
    SetLastError(error);
    return id;
}

enum PB_RULE_CHANGE { PB_RULE_ENABLE, PB_RULE_DISABLE, PB_RULE_DELETE, PB_RULE_EDIT, PB_RULE_EDIT_STATE, PB_RULE_MOVE };

static BOOL change_rule(UINT32 id, enum PB_RULE_CHANGE change, PROCESS_RULE *replacement, UINT32 position)
{
    if (id == 0 || (change == PB_RULE_MOVE && position == 0)) {
        free_rules(replacement);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!pb_rules_begin_update()) { free_rules(replacement); SetLastError(ERROR_BUSY); return FALSE; }
    PROCESS_RULE *candidate = NULL;
    BOOL ok = snapshot_rules(&candidate), flush = FALSE;
    if (ok) {
        PROCESS_RULE **link = &candidate;
        while (*link != NULL && (*link)->rule_id != id) link = &(*link)->next;
        if (*link == NULL) { SetLastError(ERROR_NOT_FOUND); ok = FALSE; }
        else {
            PROCESS_RULE *r = *link;
            switch (change) {
            case PB_RULE_ENABLE: r->enabled = TRUE; break;
            case PB_RULE_DISABLE: r->enabled = FALSE; break;
            case PB_RULE_DELETE:
                *link = r->next;
                r->next = NULL;
                free_rules(r);
                break;
            case PB_RULE_EDIT:
            case PB_RULE_EDIT_STATE:
                replacement->rule_id = id;
                if (change == PB_RULE_EDIT) replacement->enabled = r->enabled;
                replacement->next = r->next;
                *link = replacement;
                replacement = NULL;
                r->next = NULL;
                free_rules(r);
                break;
            case PB_RULE_MOVE:
                *link = r->next;
                link = &candidate;
                for (UINT32 i = 1; *link != NULL && i < position; ++i) link = &(*link)->next;
                r->next = *link;
                *link = r;
                break;
            }
            ok = commit_rules(candidate, &flush);
        }
    }
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) free_rules(candidate);
    free_rules(replacement);
    pb_rules_end_update();
    if (flush) flush_dns_resolver_cache();
    if (ok) log_message("Updated rule ID: %u", id);
    else log_message("Rule update rejected (%lu); previous rules were kept", error);
    SetLastError(error);
    return ok;
}

PROXYBRIDGE_API BOOL ProxyBridge_EnableRule(UINT32 rule_id)
{ return change_rule(rule_id, PB_RULE_ENABLE, NULL, 0); }
PROXYBRIDGE_API BOOL ProxyBridge_DisableRule(UINT32 rule_id)
{ return change_rule(rule_id, PB_RULE_DISABLE, NULL, 0); }
PROXYBRIDGE_API BOOL ProxyBridge_DeleteRule(UINT32 rule_id)
{ return change_rule(rule_id, PB_RULE_DELETE, NULL, 0); }
PROXYBRIDGE_API BOOL ProxyBridge_MoveRuleToPosition(UINT32 rule_id, UINT32 new_position)
{ return change_rule(rule_id, PB_RULE_MOVE, NULL, new_position); }

PROXYBRIDGE_API BOOL ProxyBridge_EditRule(UINT32 rule_id, const char *process_name,
    const char *target_hosts, const char *target_ports, const char *target_domains,
    RuleProtocol protocol, RuleAction action, UINT32 proxy_config_id)
{
    PROCESS_RULE *replacement = make_rule(process_name, target_hosts, target_ports, target_domains,
                                         protocol, action, proxy_config_id);
    if (replacement == NULL) return FALSE;
    return change_rule(rule_id, PB_RULE_EDIT, replacement, 0);
}

PROXYBRIDGE_API UINT32 ProxyBridge_GetRulePosition(UINT32 rule_id)
{
    UINT32 result = 0, position = 1;
    AcquireSRWLockShared(&g_rules_lock);
    for (const PROCESS_RULE *r = rules_list; r != NULL; r = r->next, ++position)
        if (r->rule_id == rule_id) { result = position; break; }
    ReleaseSRWLockShared(&g_rules_lock);
    return result;
}

// Extended entry points publish fields, enable state and insertion position in
// one transaction. Existing API callers retain their previous defaults.
PROXYBRIDGE_API UINT32 ProxyBridge_AddRule(const char *process, const char *hosts,
    const char *ports, const char *domains, RuleProtocol protocol, RuleAction action, UINT32 proxy)
{
    return ProxyBridge_AddRuleEx(process, hosts, ports, domains, protocol, action, proxy, TRUE, 0);
}

PROXYBRIDGE_API BOOL ProxyBridge_EditRuleEx(UINT32 id, const char *process, const char *hosts,
    const char *ports, const char *domains, RuleProtocol protocol, RuleAction action, UINT32 proxy, BOOL enabled)
{
    PROCESS_RULE *replacement = make_rule(process, hosts, ports, domains, protocol, action, proxy);
    if (replacement == NULL) return FALSE;
    replacement->enabled = !!enabled;
    return change_rule(id, PB_RULE_EDIT_STATE, replacement, 0);
}

// Prepare every rule before touching the active list or the caller's ID array.
// count == 0 clears the set using the same single commit as a replacement.
PROXYBRIDGE_API BOOL ProxyBridge_ReplaceRules(const ProxyBridgeRuleSpec *rules, UINT32 count, UINT32 *out_ids)
{
    if (count != 0 && (rules == NULL || out_ids == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!pb_rules_begin_update()) return FALSE;
    BOOL ok = TRUE, flush = FALSE;
    PROCESS_RULE *candidate = NULL;
    PROCESS_RULE **tail = &candidate;
    if (count != 0 && (g_next_rule_id == 0 || count - 1 > ~(UINT32)0 - g_next_rule_id)) {
        SetLastError(ERROR_ARITHMETIC_OVERFLOW);
        ok = FALSE;
    }
    for (UINT32 i = 0; i < count && ok; ++i) {
        const ProxyBridgeRuleSpec *input = &rules[i];
        PROCESS_RULE *rule = make_rule(input->process_name, input->target_hosts,
            input->target_ports, input->target_domains, input->protocol,
            input->action, input->proxy_config_id);
        if (rule == NULL) { ok = FALSE; break; }
        rule->enabled = !!input->enabled;
        rule->rule_id = g_next_rule_id + i;
        *tail = rule;
        tail = &rule->next;
    }
    if (ok) ok = commit_rules(candidate, &flush);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (ok) {
        for (UINT32 i = 0; i < count; ++i) out_ids[i] = g_next_rule_id + i;
        g_next_rule_id += count;
    } else free_rules(candidate);
    pb_rules_end_update();
    if (flush) flush_dns_resolver_cache();
    SetLastError(error);
    return ok;
}

#include "pb_prepared_profile.inc"

PROXYBRIDGE_API BOOL ProxyBridge_ReplaceProfile(const ProxyBridgeProxySpec *configs, UINT32 config_count,
    const ProxyBridgeRuleSpec *rules, UINT32 rule_count, UINT32 *config_ids, UINT32 *rule_ids, BOOL loopback)
{
    if ((config_count && !config_ids) || (rule_count && !rule_ids)) {
        SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }
    void *prepared = ProxyBridge_PrepareProfile(configs, config_count, rules, rule_count, loopback);
    return prepared ? ProxyBridge_CommitProfile(prepared, config_ids, rule_ids) : FALSE;
}
PROXYBRIDGE_API BOOL ProxyBridge_SetLocalhostViaProxyChecked(BOOL enable)
{
    if (!pb_rules_begin_update()) return FALSE;
    PROCESS_RULE *candidate = NULL;
    BOOL flush = FALSE;
    BOOL ok = snapshot_rules(&candidate);
    if (ok) ok = commit_policy(candidate, &flush, NULL, 0, NULL, &enable);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) free_rules(candidate);
    pb_rules_end_update();
    if (ok) log_message("Localhost routing: %s", enable ? "via proxy" : "direct");
    else log_message("Localhost routing update rejected (%lu); previous policy was kept", error);
    SetLastError(error);
    return ok;
}
