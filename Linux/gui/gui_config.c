#include "gui.h"
#include <fcntl.h>

#define CONFIG_DIR_DEFAULT "/etc/proxybridge"

GList *g_profiles = NULL;      // list of Profile
char *g_active_profile = NULL; // name of the active profile

// PROXYBRIDGE_CONFIG_DIR overrides the default dir (used for testing)
static char *config_dir() {
    const char *env = getenv("PROXYBRIDGE_CONFIG_DIR");
    return g_strdup((env && *env) ? env : CONFIG_DIR_DEFAULT);
}

static char *config_path() {
    char *dir = config_dir();
    char *path = g_strdup_printf("%s/config.ini", dir);
    g_free(dir);
    return path;
}

// ---- profiles ----

static void free_profile(Profile *p) {
    if (!p) return;
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
    for (GList *l = g_profiles; l != NULL; l = l->next) {
        Profile *p = (Profile *)l->data;
        if (strcmp(p->name, name) == 0) return p;
    }
    return NULL;
}

// the working lists (g_proxies_list etc.) belong to the active profile, copy the heads back
void profile_sync_active() {
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
    d->proxy_name = src->proxy_name ? g_strdup(src->proxy_name) : NULL;
    d->enabled = src->enabled;
    return d;
}

// new profile (empty, or a copy of the active one). NULL if the name is empty or taken
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

// makes the profile active (working lists swap). does not touch the library
bool profile_activate(const char *name) {
    Profile *p = profile_find(name);
    if (!p) return false;
    profile_sync_active();
    if (g_active_profile != name) { // name may alias g_active_profile
        char *copy = g_strdup(name);
        g_free(g_active_profile);
        g_active_profile = copy;
    }
    load_globals_from(p);
    return true;
}

// last profile cannot be deleted. deleting the active one activates another first
bool profile_delete(Profile *p) {
    if (!p || !g_profiles || !g_profiles->next) return false;
    if (g_active_profile && strcmp(g_active_profile, p->name) == 0) {
        Profile *other = NULL;
        for (GList *l = g_profiles; l != NULL; l = l->next) if (l->data != p) { other = (Profile *)l->data; break; }
        if (!other || !profile_activate(other->name)) return false;
    }
    g_profiles = g_list_remove(g_profiles, p);
    free_profile(p);
    return true;
}

// ---- save ----

static void write_profile(FILE *f, Profile *prof) {
    char *pn = g_uri_escape_string(prof->name, NULL, FALSE);
    char *def_esc = g_uri_escape_string(prof->default_proxy ? prof->default_proxy : "", NULL, FALSE);
    fprintf(f, "[PROFILE:%s]\n", pn);
    fprintf(f, "defaultProxy=%s\n", def_esc);
    g_free(pn);
    g_free(def_esc);

    // proxies section, text fields are percent-encoded so '|' and newlines are safe
    fprintf(f, "[PROXIES]\n");
    for (GList *l = prof->proxies; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        // format: name|type|host|port|user|pass
        char *name = g_uri_escape_string(p->name ? p->name : "", NULL, FALSE);
        char *host = g_uri_escape_string(p->host ? p->host : "", NULL, FALSE);
        char *user = g_uri_escape_string(p->username ? p->username : "", NULL, FALSE);
        char *pass = g_uri_escape_string(p->password ? p->password : "", NULL, FALSE);
        fprintf(f, "%s|%d|%s|%u|%s|%s\n", name, p->type, host, p->port, user, pass);
        g_free(name); g_free(host); g_free(user); g_free(pass);
    }

    // rules section
    fprintf(f, "[RULES]\n");
    for (GList *l = prof->rules; l != NULL; l = l->next) {
        RuleData *rule = (RuleData *)l->data;
        // format: id|protocol|action|enabled|procname|hosts|ports|proxyname
        char *pname = g_uri_escape_string(rule->proxy_name ? rule->proxy_name : "", NULL, FALSE);
        fprintf(f, "%u|%d|%d|%d|%s|%s|%s|%s\n",
            rule->id,
            rule->protocol,
            rule->action,
            rule->enabled,
            rule->process_name ? rule->process_name : "",
            rule->target_hosts ? rule->target_hosts : "",
            rule->target_ports ? rule->target_ports : "",
            pname
        );
        g_free(pname);
    }
}

// save config
void save_config() {
    profile_sync_active();

    char *dir = config_dir();
    char *path = config_path();
    struct stat st = {0};
    if (stat(dir, &st) == -1) {
        if (g_mkdir_with_parents(dir, 0700) != 0) {
            perror("failed to create config dir");
            g_free(dir); g_free(path);
            return;
        }
    } else if (chmod(dir, 0700) != 0) {
        perror("chmod config dir failed");
    }

    int cfg_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (cfg_fd < 0) {
        printf("failed to save config to %s\n", path);
        g_free(dir); g_free(path);
        return;
    }
    // mode on open only hits create; tighten existing 0644 installs too
    if (fchmod(cfg_fd, 0600) != 0) {
        perror("chmod config file failed");
    }
    FILE *f = fdopen(cfg_fd, "w");
    if (!f) {
        close(cfg_fd);
        printf("failed to save config to %s\n", path);
        g_free(dir); g_free(path);
        return;
    }

    // settings section, global
    char *act_esc = g_uri_escape_string(g_active_profile ? g_active_profile : "", NULL, FALSE);
    fprintf(f, "[SETTINGS]\n");
    fprintf(f, "activeProfile=%s\n", act_esc);
    g_free(act_esc);
    fprintf(f, "logging=%d\n", g_chk_logging);
    fprintf(f, "dns=%d\n", g_chk_dns);

    for (GList *l = g_profiles; l != NULL; l = l->next) write_profile(f, (Profile *)l->data);

    fclose(f);
    g_free(dir); g_free(path);
}

// decode a percent-encoded field, never returns NULL
static char *unescape_field(const char *src) {
    char *out = g_uri_unescape_string(src ? src : "", NULL);
    return out ? out : g_strdup("");
}

static ProxyType proxy_type_from_int(int v) {
    return v == PROXY_TYPE_HTTP ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
}

static ProxyData *find_in_list(GList *list, const char *name) {
    for (GList *l = list; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        if (p->name && strcmp(p->name, name) == 0) return p;
    }
    return NULL;
}

// load settings from file. old files (no profiles) end up in a profile called "Default"
void load_config() {
    char *path = config_path();
    chmod(path, 0600); // old installs might still be world readable
    FILE *f = fopen(path, "r");
    g_free(path);

    char line[8192];
    int section = 0; // 0=none, 1=settings, 2=rules, 3=proxies, 4=profile header
    Profile *cur = NULL;
    char *saved_active = NULL;

    // old single proxy config (pre multi-proxy), migrated to a proxy called "default"
    char old_ip[256] = "", old_user[256] = "", old_pass[256] = "";
    int old_port = 0, old_type = PROXY_TYPE_SOCKS5;

    while (f && fgets(line, sizeof(line), f)) {
        // trim newline
        line[strcspn(line, "\r\n")] = 0;

        if (strlen(line) == 0 || line[0] == '#') continue;

        if (strcmp(line, "[SETTINGS]") == 0) { section = 1; continue; }
        if (strcmp(line, "[RULES]") == 0) { section = 2; if (!cur) cur = profile_new_empty("Default"); continue; }
        if (strcmp(line, "[PROXIES]") == 0) { section = 3; if (!cur) cur = profile_new_empty("Default"); continue; }
        if (strncmp(line, "[PROFILE:", 9) == 0 && line[strlen(line) - 1] == ']') {
            line[strlen(line) - 1] = 0;
            char *pn = unescape_field(line + 9);
            cur = (pn[0] != '\0') ? profile_find(pn) : NULL;
            if (!cur && pn[0] != '\0') cur = profile_new_empty(pn);
            g_free(pn);
            section = cur ? 4 : 0;
            continue;
        }

        if (section == 1 || section == 4) {
            char *val = strchr(line, '=');
            if (!val) continue;
            *val = 0; val++;

            if (section == 1 && strcmp(line, "ip") == 0) g_strlcpy(old_ip, val, sizeof(old_ip));
            else if (section == 1 && strcmp(line, "port") == 0) old_port = atoi(val);
            else if (section == 1 && strcmp(line, "type") == 0) old_type = atoi(val);
            else if (section == 1 && strcmp(line, "user") == 0) g_strlcpy(old_user, val, sizeof(old_user));
            else if (section == 1 && strcmp(line, "pass") == 0) g_strlcpy(old_pass, val, sizeof(old_pass));
            else if (strcmp(line, "defaultProxy") == 0) {
                // profile blocks own it, old files kept it in [SETTINGS]
                if (!cur) cur = profile_new_empty("Default");
                g_free(cur->default_proxy);
                cur->default_proxy = unescape_field(val);
                if (cur->default_proxy[0] == '\0') { g_free(cur->default_proxy); cur->default_proxy = NULL; }
            }
            else if (section == 1 && strcmp(line, "activeProfile") == 0) {
                g_free(saved_active);
                saved_active = unescape_field(val);
            }
            else if (section == 1 && strcmp(line, "logging") == 0) g_chk_logging = atoi(val);
            else if (section == 1 && strcmp(line, "dns") == 0) g_chk_dns = atoi(val);
        }
        else if (section == 3 && cur) {
            // parse proxy line: name|type|host|port|user|pass
            char *fields[6] = {NULL};
            char *p = line;
            int idx = 0;
            char *token;
            while (idx < 6 && (token = strsep(&p, "|")) != NULL) fields[idx++] = token;
            if (idx < 4) continue;

            int port = atoi(fields[3]);
            ProxyData *px = g_malloc0(sizeof(ProxyData));
            px->name = unescape_field(fields[0]);
            px->type = proxy_type_from_int(atoi(fields[1]));
            px->host = unescape_field(fields[2]);
            px->port = (port >= 1 && port <= 65535) ? (uint16_t)port : 0;
            px->username = unescape_field(idx > 4 ? fields[4] : "");
            px->password = unescape_field(idx > 5 ? fields[5] : "");
            if (px->name[0] == '\0' || find_in_list(cur->proxies, px->name)) {
                free_proxy_data(px);
                continue;
            }
            cur->proxies = g_list_append(cur->proxies, px);
        }
        else if (section == 2 && cur) {
            // parse rule line
            RuleData *rule = g_malloc0(sizeof(RuleData));
            char *p = line;
            char *token;
            int idx = 0;

            while ((token = strsep(&p, "|")) != NULL) {
                switch(idx) {
                    case 0: rule->id = atoi(token); break;
                    case 1: rule->protocol = atoi(token); break;
                    case 2: rule->action = atoi(token); break;
                    case 3: rule->enabled = atoi(token); break;
                    case 4: rule->process_name = g_strdup(token); break;
                    case 5: rule->target_hosts = g_strdup(token); break;
                    case 6: rule->target_ports = g_strdup(token); break;
                    case 7: rule->proxy_name = unescape_field(token); break;
                }
                idx++;
            }

            // old files can hold garbage, keep enums in range
            if (idx >= 4 && rule->protocol <= RULE_PROTOCOL_BOTH && rule->action <= RULE_ACTION_BLOCK) {
               if (!rule->process_name) rule->process_name = g_strdup("");
               if (!rule->target_hosts) rule->target_hosts = g_strdup("");
               if (!rule->target_ports) rule->target_ports = g_strdup("");
               rule->id = 0; // ids belong to the library, assigned when the rule is added
               cur->rules = g_list_append(cur->rules, rule);
            } else {
               free_rule_data(rule);
            }
        }
    }
    if (f) fclose(f);

    // migrate old single proxy config into the "Default" profile
    if (old_ip[0] != '\0' && old_port >= 1 && old_port <= 65535) {
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

    // always at least one profile
    if (!g_profiles) profile_new_empty("Default");

    // default points to nothing -> first proxy
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
