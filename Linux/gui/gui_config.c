#include "gui.h"
#include <fcntl.h>

#define CONFIG_DIR_DEFAULT "/etc/proxybridge"

GList *g_profiles = NULL;
char *g_active_profile = NULL;

// PROXYBRIDGE_CONFIG_DIR overrides the default dir (used for testing)
static char *config_dir() {
    const char *env = getenv("PROXYBRIDGE_CONFIG_DIR");
    return g_strdup((env && *env) ? env : CONFIG_DIR_DEFAULT);
}

static char *esc(const char *s) {
    return g_uri_escape_string(s ? s : "", NULL, FALSE);
}

static char *unesc(const char *s) {
    char *out = g_uri_unescape_string(s ? s : "", NULL);
    return out ? out : g_strdup("");
}

static void put_esc(FILE *f, const char *s, char sep) {
    char *e = esc(s);
    fputs(e, f);
    fputc(sep, f);
    g_free(e);
}

static void free_profile(Profile *p) {
    for (GList *l = p->proxies; l != NULL; l = l->next) free_proxy_data((ProxyData *)l->data);
    for (GList *l = p->rules; l != NULL; l = l->next) free_rule_data((RuleData *)l->data);
    g_list_free(p->proxies);
    g_list_free(p->rules);
    g_free(p->default_proxy);
    g_free(p->name);
    g_free(p);
}

Profile *profile_find(const char *name) {
    if (!name) return NULL;
    for (GList *l = g_profiles; l != NULL; l = l->next)
        if (strcmp(((Profile *)l->data)->name, name) == 0) return (Profile *)l->data;
    return NULL;
}

// the working lists belong to the active profile, copy the (possibly changed) heads back
static void profile_sync_active() {
    Profile *p = profile_find(g_active_profile);
    if (!p) return;
    p->proxies = g_proxies_list;
    p->rules = g_rules_list;
    p->default_proxy = g_default_proxy;
}

static void load_globals_from(Profile *p) {
    g_proxies_list = p->proxies;
    g_rules_list = p->rules;
    g_default_proxy = p->default_proxy;
}

void config_free_all() {
    profile_sync_active();
    g_list_free_full(g_profiles, (GDestroyNotify)free_profile);
    g_profiles = NULL;
    g_free(g_active_profile);
    g_active_profile = NULL;
    g_proxies_list = g_rules_list = NULL;
    g_default_proxy = NULL;
}

static Profile *profile_new_empty(const char *name) {
    Profile *p = g_malloc0(sizeof(Profile));
    p->name = g_strdup(name);
    g_profiles = g_list_append(g_profiles, p);
    return p;
}

static ProxyData *copy_proxy(const ProxyData *src) {
    ProxyData *d = g_malloc0(sizeof(ProxyData));
    d->name = g_strdup(src->name);
    d->type = src->type;
    d->host = g_strdup(src->host);
    d->port = src->port;
    d->username = g_strdup(src->username ? src->username : "");
    d->password = g_strdup(src->password ? src->password : "");
    return d;
}

static RuleData *copy_rule(const RuleData *src) {
    RuleData *d = g_malloc0(sizeof(RuleData));
    d->process_name = g_strdup(src->process_name ? src->process_name : "");
    d->target_hosts = g_strdup(src->target_hosts ? src->target_hosts : "");
    d->target_ports = g_strdup(src->target_ports ? src->target_ports : "");
    d->protocol = src->protocol;
    d->action = src->action;
    d->proxy_name = g_strdup(src->proxy_name);
    d->enabled = src->enabled;
    return d;
}

Profile *profile_create(const char *name, bool copy_active) {
    if (!name || !*name || profile_find(name)) return NULL;
    profile_sync_active();
    Profile *src = copy_active ? profile_find(g_active_profile) : NULL;
    Profile *p = profile_new_empty(name);
    if (src) {
        for (GList *l = src->proxies; l != NULL; l = l->next) p->proxies = g_list_append(p->proxies, copy_proxy((ProxyData *)l->data));
        for (GList *l = src->rules; l != NULL; l = l->next) p->rules = g_list_append(p->rules, copy_rule((RuleData *)l->data));
        p->default_proxy = g_strdup(src->default_proxy);
    }
    return p;
}

bool profile_rename(Profile *p, const char *new_name) {
    if (!p || !new_name || !*new_name) return false;
    if (strcmp(p->name, new_name) == 0) return true;
    if (profile_find(new_name)) return false;
    bool active = g_active_profile && strcmp(g_active_profile, p->name) == 0;
    g_free(p->name);
    p->name = g_strdup(new_name);
    if (active) {
        g_free(g_active_profile);
        g_active_profile = g_strdup(new_name);
    }
    return true;
}

bool profile_activate(const char *name) {
    Profile *p = profile_find(name);
    if (!p) return false;
    profile_sync_active();
    if (name != g_active_profile) {
        char *copy = g_strdup(name);
        g_free(g_active_profile);
        g_active_profile = copy;
    }
    load_globals_from(p);
    return true;
}

// the last profile stays; deleting the active one activates another first
bool profile_delete(Profile *p) {
    if (!p || !g_profiles || !g_profiles->next) return false;
    if (g_active_profile && strcmp(g_active_profile, p->name) == 0) {
        Profile *other = (Profile *)g_profiles->data;
        if (other == p) other = (Profile *)g_profiles->next->data;
        if (!profile_activate(other->name)) return false;
    }
    g_profiles = g_list_remove(g_profiles, p);
    free_profile(p);
    return true;
}

static void write_profile(FILE *f, Profile *prof) {
    fputs("[PROFILE:", f);
    char *pn = esc(prof->name);
    fprintf(f, "%s]\ndefaultProxy=", pn);
    g_free(pn);
    put_esc(f, prof->default_proxy, '\n');

    // fields are percent-encoded so '|' and newlines are safe: name|type|host|port|user|pass
    fputs("[PROXIES]\n", f);
    for (GList *l = prof->proxies; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        put_esc(f, p->name, '|');
        fprintf(f, "%d|", p->type);
        put_esc(f, p->host, '|');
        fprintf(f, "%u|", p->port);
        put_esc(f, p->username, '|');
        put_esc(f, p->password, '\n');
    }

    // id|protocol|action|enabled|procname|hosts|ports|proxyname
    fputs("[RULES]\n", f);
    for (GList *l = prof->rules; l != NULL; l = l->next) {
        RuleData *r = (RuleData *)l->data;
        fprintf(f, "%u|%d|%d|%d|%s|%s|%s|", r->id, r->protocol, r->action, r->enabled,
                r->process_name ? r->process_name : "", r->target_hosts ? r->target_hosts : "",
                r->target_ports ? r->target_ports : "");
        put_esc(f, r->proxy_name, '\n');
    }
}

void save_config() {
    profile_sync_active();

    char *dir = config_dir();
    char *path = g_strdup_printf("%s/config.ini", dir);
    struct stat st;
    if (stat(dir, &st) == -1) {
        if (g_mkdir_with_parents(dir, 0700) != 0) {
            perror("failed to create config dir");
            goto out;
        }
    } else if (chmod(dir, 0700) != 0) {
        perror("chmod config dir failed");
    }

    int cfg_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (cfg_fd < 0) {
        fprintf(stderr, "failed to save config to %s\n", path);
        goto out;
    }
    // mode on open only hits create; tighten existing 0644 installs too
    if (fchmod(cfg_fd, 0600) != 0) perror("chmod config file failed");
    FILE *f = fdopen(cfg_fd, "w");
    if (!f) {
        close(cfg_fd);
        fprintf(stderr, "failed to save config to %s\n", path);
        goto out;
    }

    fputs("[SETTINGS]\nactiveProfile=", f);
    put_esc(f, g_active_profile, '\n');
    fprintf(f, "logging=%d\ndns=%d\n", g_chk_logging, g_chk_dns);
    for (GList *l = g_profiles; l != NULL; l = l->next) write_profile(f, (Profile *)l->data);
    fclose(f);
out:
    g_free(dir);
    g_free(path);
}

static ProxyType proxy_type_from_int(int v) {
    return v == PROXY_TYPE_HTTP ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
}

static ProxyData *find_in_list(GList *list, const char *name) {
    for (GList *l = list; l != NULL; l = l->next)
        if (strcmp(((ProxyData *)l->data)->name, name) == 0) return (ProxyData *)l->data;
    return NULL;
}

static ProxyData *parse_proxy_line(char *line) {
    char *fields[6] = {NULL};
    int n = 0;
    char *tok;
    while (n < 6 && (tok = strsep(&line, "|")) != NULL) fields[n++] = tok;
    if (n < 4) return NULL;

    int port = parse_long(fields[3]);
    ProxyData *px = g_malloc0(sizeof(ProxyData));
    px->name = unesc(fields[0]);
    px->type = proxy_type_from_int(parse_long(fields[1]));
    px->host = unesc(fields[2]);
    px->port = (port >= 1 && port <= 65535) ? (uint16_t)port : 0;
    px->username = unesc(n > 4 ? fields[4] : "");
    px->password = unesc(n > 5 ? fields[5] : "");
    return px;
}

static RuleData *parse_rule_line(char *line) {
    RuleData *rule = g_malloc0(sizeof(RuleData));
    char *tok;
    int idx = 0;
    while ((tok = strsep(&line, "|")) != NULL) {
        switch (idx++) {
            case 1: rule->protocol = parse_long(tok); break;
            case 2: rule->action = parse_long(tok); break;
            case 3: rule->enabled = parse_long(tok); break;
            case 4: rule->process_name = g_strdup(tok); break;
            case 5: rule->target_hosts = g_strdup(tok); break;
            case 6: rule->target_ports = g_strdup(tok); break;
            case 7: rule->proxy_name = unesc(tok); break;
        }
    }
    // old files can hold garbage, ids belong to the library and are assigned when the rule is added
    if (idx < 4 || rule->protocol > RULE_PROTOCOL_BOTH || rule->action > RULE_ACTION_BLOCK) {
        free_rule_data(rule);
        return NULL;
    }
    if (!rule->process_name) rule->process_name = g_strdup("");
    if (!rule->target_hosts) rule->target_hosts = g_strdup("");
    if (!rule->target_ports) rule->target_ports = g_strdup("");
    return rule;
}

// files without profile blocks (old format) end up in a profile called "Default"
void load_config() {
    char *dir = config_dir();
    char *path = g_strdup_printf("%s/config.ini", dir);
    chmod(path, 0600);
    FILE *f = fopen(path, "r");
    g_free(dir);
    g_free(path);

    char line[8192];
    int section = 0; // 1=settings, 2=rules, 3=proxies, 4=profile header
    Profile *cur = NULL;
    char *saved_active = NULL;

    // pre multi-proxy config, migrated to a proxy called "default"
    char old_ip[256] = "", old_user[256] = "", old_pass[256] = "";
    int old_port = 0, old_type = PROXY_TYPE_SOCKS5;

    while (f && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0] || line[0] == '#') continue;

        if (strcmp(line, "[SETTINGS]") == 0) { section = 1; continue; }
        if (strcmp(line, "[RULES]") == 0 || strcmp(line, "[PROXIES]") == 0) {
            section = line[1] == 'R' ? 2 : 3;
            if (!cur) cur = profile_new_empty("Default");
            continue;
        }
        size_t len = strlen(line);
        if (strncmp(line, "[PROFILE:", 9) == 0 && line[len - 1] == ']') {
            line[len - 1] = 0;
            char *pn = unesc(line + 9);
            cur = pn[0] ? profile_find(pn) : NULL;
            if (!cur && pn[0]) cur = profile_new_empty(pn);
            g_free(pn);
            section = cur ? 4 : 0;
            continue;
        }

        if (section == 1 || section == 4) {
            char *val = strchr(line, '=');
            if (!val) continue;
            *val++ = 0;

            if (strcmp(line, "defaultProxy") == 0) {
                if (!cur) cur = profile_new_empty("Default");
                g_free(cur->default_proxy);
                cur->default_proxy = unesc(val);
                if (!cur->default_proxy[0]) { g_free(cur->default_proxy); cur->default_proxy = NULL; }
            }
            else if (section != 1) continue;
            else if (strcmp(line, "ip") == 0) g_strlcpy(old_ip, val, sizeof(old_ip));
            else if (strcmp(line, "port") == 0) old_port = parse_long(val);
            else if (strcmp(line, "type") == 0) old_type = parse_long(val);
            else if (strcmp(line, "user") == 0) g_strlcpy(old_user, val, sizeof(old_user));
            else if (strcmp(line, "pass") == 0) g_strlcpy(old_pass, val, sizeof(old_pass));
            else if (strcmp(line, "activeProfile") == 0) { g_free(saved_active); saved_active = unesc(val); }
            else if (strcmp(line, "logging") == 0) g_chk_logging = parse_long(val);
            else if (strcmp(line, "dns") == 0) g_chk_dns = parse_long(val);
        }
        else if (section == 3 && cur) {
            ProxyData *px = parse_proxy_line(line);
            if (px && (!px->name[0] || find_in_list(cur->proxies, px->name))) { free_proxy_data(px); px = NULL; }
            if (px) cur->proxies = g_list_append(cur->proxies, px);
        }
        else if (section == 2 && cur) {
            RuleData *rule = parse_rule_line(line);
            if (rule) cur->rules = g_list_append(cur->rules, rule);
        }
    }
    if (f) fclose(f);

    if (old_ip[0] && old_port >= 1 && old_port <= 65535) {
        Profile *d = profile_find("Default");
        if (!d) d = profile_new_empty("Default");
        if (!d->proxies) {
            ProxyData *px = g_malloc0(sizeof(ProxyData));
            px->name = g_strdup("default");
            px->type = proxy_type_from_int(old_type);
            px->host = g_strdup(old_ip);
            px->port = (uint16_t)old_port;
            px->username = g_strdup(old_user);
            px->password = g_strdup(old_pass);
            d->proxies = g_list_append(d->proxies, px);
            g_free(d->default_proxy);
            d->default_proxy = g_strdup("default");
        }
    }

    if (!g_profiles) profile_new_empty("Default");

    for (GList *l = g_profiles; l != NULL; l = l->next) {
        Profile *p = (Profile *)l->data;
        if (p->proxies && (!p->default_proxy || !find_in_list(p->proxies, p->default_proxy))) {
            g_free(p->default_proxy);
            p->default_proxy = g_strdup(((ProxyData *)p->proxies->data)->name);
        }
    }

    Profile *act = profile_find(saved_active);
    if (!act) act = (Profile *)g_profiles->data;
    g_free(saved_active);
    g_free(g_active_profile);
    g_active_profile = g_strdup(act->name);
    load_globals_from(act);
}
