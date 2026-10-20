#include "gui.h"

static char *escape_json_string(const char *src) {
    GString *str = g_string_new("");
    for (const char *p = src ? src : ""; *p; p++) {
        switch (*p) {
            case '\\': g_string_append(str, "\\\\"); break;
            case '"': g_string_append(str, "\\\""); break;
            case '\n': g_string_append(str, "\\n"); break;
            case '\r': g_string_append(str, "\\r"); break;
            case '\t': g_string_append(str, "\\t"); break;
            default:
                if ((unsigned char)*p < 0x20) g_string_append_printf(str, "\\u%04x", (unsigned char)*p);
                else g_string_append_c(str, *p);
        }
    }
    return g_string_free(str, FALSE);
}

// returns NULL if the key is missing, its value is not a string, or the string is unterminated
char *extract_sub_json_str(const char *json, const char *key) {
    char *needle = g_strdup_printf("\"%s\"", key);
    const char *k = strstr(json, needle);
    const char *v = k ? strchr(k + strlen(needle), ':') : NULL;
    g_free(needle);
    if (!v) return NULL;
    v++;
    while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
    if (*v != '"') return NULL;
    v++;

    GString *out = g_string_new("");
    while (*v && *v != '"') {
        if (*v == '\\' && v[1]) {
            v++;
            g_string_append_c(out, *v == 'n' ? '\n' : *v == 'r' ? '\r' : *v == 't' ? '\t' : *v);
        } else {
            g_string_append_c(out, *v);
        }
        v++;
    }
    if (*v != '"') { g_string_free(out, TRUE); return NULL; }
    return g_string_free(out, FALSE);
}

static bool json_has_key(const char *json, const char *key) {
    char *needle = g_strdup_printf("\"%s\"", key);
    bool found = strstr(json, needle) != NULL;
    g_free(needle);
    return found;
}

static bool json_bool(const char *json, const char *key, bool def) {
    if (!json_has_key(json, key)) return def;
    char *needle = g_strdup_printf("\"%s\"", key);
    const char *colon = strchr(strstr(json, needle) + strlen(needle), ':');
    g_free(needle);
    if (!colon) return def;
    colon++;
    while (*colon == ' ' || *colon == '\t' || *colon == '\n' || *colon == '\r') colon++;
    return strncmp(colon, "true", 4) == 0;
}

// '}' closing the object that starts at p, skipping braces inside strings
static const char *object_end(const char *p) {
    bool in_str = false;
    for (p++; *p; p++) {
        if (in_str) {
            if (*p == '\\' && p[1]) p++;
            else if (*p == '"') in_str = false;
        } else if (*p == '"') {
            in_str = true;
        } else if (*p == '}') {
            return p;
        }
    }
    return NULL;
}

static char *first_str(const char *obj, const char *key, const char *alt) {
    char *s = extract_sub_json_str(obj, key);
    return s ? s : extract_sub_json_str(obj, alt);
}

static bool name_is(const char *s, const char *want) {
    return s && g_ascii_strcasecmp(s, want) == 0;
}

// accepts our keys and the macOS ones. unknown action strings (macOS stores a proxy id) mean PROXY
int rules_from_json(const char *json, RuleImportCb cb, void *ud) {
    int count = 0;
    for (const char *cur = json; (cur = strchr(cur, '{')) != NULL; ) {
        const char *end = object_end(cur);
        if (!end) break;
        char *obj = g_strndup(cur, end - cur + 1);
        cur = end + 1;

        RuleData r = {0};
        r.name = extract_sub_json_str(obj, "name");
        r.localhost = json_bool(obj, "localhostViaProxy", false);
        r.process_name = extract_sub_json_str(obj, "processNames");
        r.target_hosts = extract_sub_json_str(obj, "targetHosts");
        r.target_ports = extract_sub_json_str(obj, "targetPorts");
        char *proto = first_str(obj, "protocol", "ruleProtocol");
        char *act = first_str(obj, "action", "ruleAction");
        r.proxy_name = extract_sub_json_str(obj, "proxy");
        r.enabled = json_bool(obj, "enabled", true);
        if (!r.target_hosts) r.target_hosts = g_strdup("*");
        if (!r.target_ports) r.target_ports = g_strdup("*");
        r.protocol = name_is(proto, "TCP") ? RULE_PROTOCOL_TCP : name_is(proto, "UDP") ? RULE_PROTOCOL_UDP : RULE_PROTOCOL_BOTH;
        r.action = name_is(act, "DIRECT") ? RULE_ACTION_DIRECT : name_is(act, "BLOCK") ? RULE_ACTION_BLOCK : RULE_ACTION_PROXY;

        cb(&r, ++count, ud);

        g_free(r.name); g_free(r.process_name); g_free(r.target_hosts); g_free(r.target_ports); g_free(r.proxy_name);
        g_free(proto); g_free(act); g_free(obj);
    }
    return count;
}

char *rules_to_json(GList *rules, bool only_selected) {
    GString *out = g_string_new("[\n");
    bool first = true;
    for (GList *l = rules; l != NULL; l = l->next) {
        RuleData *r = (RuleData *)l->data;
        if (only_selected && !r->selected) continue;
        char *proc = escape_json_string(r->process_name);
        char *host = escape_json_string(r->target_hosts);
        char *port = escape_json_string(r->target_ports);
        char *pxy = escape_json_string(r->action == RULE_ACTION_PROXY ? r->proxy_name : NULL);
        const char *proto = r->protocol == RULE_PROTOCOL_TCP ? "TCP" : r->protocol == RULE_PROTOCOL_UDP ? "UDP" : "BOTH";
        const char *act = r->action == RULE_ACTION_PROXY ? "PROXY" : r->action == RULE_ACTION_DIRECT ? "DIRECT" : "BLOCK";
        char *nm = escape_json_string(r->name);
        g_string_append_printf(out, "%s  {\n    \"name\": \"%s\",\n    \"localhostViaProxy\": %s,\n    \"processNames\": \"%s\",\n    \"targetHosts\": \"%s\",\n    \"targetPorts\": \"%s\",\n"
            "    \"protocol\": \"%s\",\n    \"ruleProtocol\": \"%s\",\n    \"action\": \"%s\",\n    \"ruleAction\": \"%s\",\n"
            "    \"proxy\": \"%s\",\n    \"enabled\": %s\n  }",
            first ? "" : ",\n", nm, r->localhost && r->action == RULE_ACTION_PROXY ? "true" : "false", proc, host, port, proto, proto, act, act, pxy, r->enabled ? "true" : "false");
        g_free(nm);
        g_free(proc); g_free(host); g_free(port); g_free(pxy);
        first = false;
    }
    g_string_append(out, "\n]\n");
    return g_string_free(out, FALSE);
}
