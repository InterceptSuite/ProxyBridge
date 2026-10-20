#include "gui.h"
#include <fcntl.h>
#include <dirent.h>
#include "pb_profile.h"

GList *g_profiles = NULL;
char *g_active_profile = NULL;

static char *config_dir() {
    return g_strdup(pbp_config_dir());
}

static char *profile_path(const char *name) {
    char *file = pbp_filename_for(name);
    if (!file) return NULL;
    char *dir = config_dir();
    char *path = g_strdup_printf("%s/profiles/%s", dir, file);
    free(file);
    g_free(dir);
    return path;
}

// the file of a deleted or renamed profile must go, or it would come back at the next start
static void remove_profile_file(const char *name) {
    char *path = profile_path(name);
    if (path) unlink(path);
    g_free(path);
}

static char *unesc(const char *s) {
    char *out = g_uri_unescape_string(s ? s : "", NULL);
    return out ? out : g_strdup("");
}

static void free_profile(Profile *p) {
    for (GList *l = p->proxies; l != NULL; l = l->next) free_proxy_data((ProxyData *)l->data);
    for (GList *l = p->rules; l != NULL; l = l->next) free_rule_data((RuleData *)l->data);
    g_list_free(p->proxies);
    g_list_free(p->rules);
    g_free(p->default_proxy);
    g_free(p->name);
    free(p->saved);
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
    p->logging = g_chk_logging;
    p->dns = g_chk_dns;
}

static void load_globals_from(Profile *p) {
    g_proxies_list = p->proxies;
    g_rules_list = p->rules;
    g_default_proxy = p->default_proxy;
    g_chk_logging = p->logging;
    g_chk_dns = p->dns;
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
    p->logging = p->dns = true;
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
    d->send_domain = src->send_domain;
    return d;
}

static RuleData *copy_rule(const RuleData *src) {
    RuleData *d = g_malloc0(sizeof(RuleData));
    d->name = g_strdup(src->name ? src->name : "");
    d->localhost = src->localhost;
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
        p->logging = src->logging;
        p->dns = src->dns;
    }
    return p;
}

bool profile_rename(Profile *p, const char *new_name) {
    if (!p || !new_name || !*new_name) return false;
    if (strcmp(p->name, new_name) == 0) return true;
    if (profile_find(new_name)) return false;
    bool active = g_active_profile && strcmp(g_active_profile, p->name) == 0;
    remove_profile_file(p->name);
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
    remove_profile_file(p->name);
    free_profile(p);
    return true;
}

static ProxyData *find_in_list(GList *list, const char *name) {
    for (GList *l = list; l != NULL; l = l->next)
        if (strcmp(((ProxyData *)l->data)->name, name) == 0) return (ProxyData *)l->data;
    return NULL;
}

// Borrows the strings of the profile; release with free_pbp_view, not pbp_free.
static void profile_to_pbp(const Profile *prof, struct pbp_profile *out) {
    memset(out, 0, sizeof *out);
    out->name = prof->name;
    out->logging = prof->logging;
    out->dns_via_proxy = prof->dns;
    out->nproxies = g_list_length(prof->proxies);
    out->nrules = g_list_length(prof->rules);
    out->proxies = g_new0(struct pbp_proxy, out->nproxies + 1);
    out->rules = g_new0(struct pbp_rule, out->nrules + 1);

    uint32_t id = 0;
    for (GList *l = prof->proxies; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        struct pbp_proxy *x = &out->proxies[id++];
        x->id = id;
        x->name = p->name;
        x->type = p->type == PROXY_TYPE_HTTP ? 0 : 1;
        x->host = p->host;
        x->port = p->port;
        x->user = p->username ? p->username : (char *)"";
        x->pass = p->password ? p->password : (char *)"";
        x->send_domain = p->send_domain;
        if (prof->default_proxy && strcmp(prof->default_proxy, p->name) == 0) out->default_proxy_id = x->id;
    }
    size_t i = 0;
    for (GList *l = prof->rules; l != NULL; l = l->next) {
        RuleData *r = (RuleData *)l->data;
        struct pbp_rule *x = &out->rules[i++];
        x->name = r->name ? r->name : (char *)"";
        x->localhost = r->localhost;
        x->process = r->process_name ? r->process_name : (char *)"*";
        x->hosts = r->target_hosts ? r->target_hosts : (char *)"*";
        x->ports = r->target_ports ? r->target_ports : (char *)"*";
        x->protocol = r->protocol;
        x->action = r->action;
        x->enabled = r->enabled;
        if (r->action == RULE_ACTION_PROXY && r->proxy_name && r->proxy_name[0])
            for (size_t k = 0; k < out->nproxies; k++)
                if (strcmp(out->proxies[k].name, r->proxy_name) == 0) { x->proxy_id = out->proxies[k].id; break; }
    }
}

static void free_pbp_view(struct pbp_profile *v) {
    g_free(v->proxies);
    g_free(v->rules);
}

static void fill_profile_from_pbp(Profile *p, const struct pbp_profile *src) {
    for (size_t i = 0; i < src->nproxies; i++) {
        const struct pbp_proxy *x = &src->proxies[i];
        ProxyData *px = g_malloc0(sizeof(ProxyData));
        px->name = g_strdup(x->name);
        px->type = x->type ? PROXY_TYPE_SOCKS5 : PROXY_TYPE_HTTP;
        px->host = g_strdup(x->host);
        px->port = x->port;
        px->username = g_strdup(x->user);
        px->password = g_strdup(x->pass);
        px->send_domain = x->send_domain;
        p->proxies = g_list_append(p->proxies, px);
    }
    for (size_t i = 0; i < src->nrules; i++) {
        const struct pbp_rule *x = &src->rules[i];
        RuleData *r = g_malloc0(sizeof(RuleData));
        r->name = g_strdup(x->name);
        r->localhost = x->localhost;
        r->process_name = g_strdup(x->process);
        r->target_hosts = g_strdup(x->hosts);
        r->target_ports = g_strdup(x->ports);
        r->protocol = x->protocol;
        r->action = x->action;
        r->enabled = x->enabled;
        const struct pbp_proxy *px = x->proxy_id ? pbp_find_proxy(src, x->proxy_id) : NULL;
        if (px) r->proxy_name = g_strdup(px->name);
        p->rules = g_list_append(p->rules, r);
    }
    const struct pbp_proxy *d = src->default_proxy_id ? pbp_find_proxy(src, src->default_proxy_id) : NULL;
    g_free(p->default_proxy);
    p->default_proxy = d ? g_strdup(d->name) : NULL;
    p->logging = src->logging;
    p->dns = src->dns_via_proxy;
}

bool profile_export(const Profile *prof, const char *path, char *err, size_t errlen) {
    profile_sync_active();
    struct pbp_profile view;
    profile_to_pbp(prof, &view);
    bool ok = pbp_save_file(path, &view, err, errlen) == 0;
    free_pbp_view(&view);
    return ok;
}

static bool name_storable(const char *name) {
    char *file = pbp_filename_for(name);
    free(file);
    return file != NULL;
}

// the profile is named after the file (or the "Name" it carries), made unique if needed
Profile *profile_import(const char *path, char *err, size_t errlen) {
    struct pbp_profile src;
    if (pbp_load_file(path, &src, err, errlen) != 0) return NULL;

    char *base = NULL;
    if (src.name && src.name[0]) {
        base = g_strdup(src.name);
    } else {
        char *file = g_path_get_basename(path);
        size_t n = strlen(file), e = strlen(PBP_EXT);
        if (n > e && strcmp(file + n - e, PBP_EXT) == 0) file[n - e] = 0;
        base = file;
    }
    char *name = g_strdup(base);
    for (int i = 2; profile_find(name) || !name_storable(name); i++) {
        g_free(name);
        name = g_strdup_printf("%s (%d)", base[0] ? base : "Imported", i);
        if (i > 1000) { g_free(name); g_free(base); pbp_free(&src); snprintf(err, errlen, "no free profile name"); return NULL; }
    }
    profile_sync_active();
    Profile *p = profile_new_empty(name);
    fill_profile_from_pbp(p, &src);
    g_free(name);
    g_free(base);
    pbp_free(&src);
    return p;
}

static bool ensure_private_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == -1) {
        if (g_mkdir_with_parents(dir, 0700) != 0) { perror("failed to create config dir"); return false; }
    } else if (chmod(dir, 0700) != 0) {
        perror("chmod config dir failed");
    }
    return true;
}

void save_config() {
    profile_sync_active();

    char *dir = config_dir();
    char *pdir = g_strdup_printf("%s/profiles", dir);
    if (!ensure_private_dir(dir) || !ensure_private_dir(pdir)) goto out;

    char err[256];
    for (GList *l = g_profiles; l != NULL; l = l->next) {
        Profile *prof = (Profile *)l->data;
        char *path = profile_path(prof->name);
        if (!path) {
            fprintf(stderr, "profile '%s': the name is too long to be stored\n", prof->name);
            continue;
        }
        struct pbp_profile view;
        profile_to_pbp(prof, &view);
        char *json = pbp_serialize(&view);
        free_pbp_view(&view);
        if (json && !(prof->saved && strcmp(prof->saved, json) == 0 && access(path, F_OK) == 0)) {
            if (pbp_write_file(path, json, err, sizeof err) == 0) {
                free(prof->saved);
                prof->saved = json;
                json = NULL;
            } else {
                fprintf(stderr, "failed to save profile '%s': %s\n", prof->name, err);
            }
        }
        free(json);
        g_free(path);
    }
    char *settings = g_strdup_printf("%s/settings.json", dir);
    if (pbp_settings_save(settings, g_active_profile, err, sizeof err) != 0)
        fprintf(stderr, "failed to save settings: %s\n", err);
    g_free(settings);
out:
    g_free(pdir);
    g_free(dir);
}

static ProxyType proxy_type_from_int(int v) {
    return v == PROXY_TYPE_HTTP ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
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
    px->send_domain = true;
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

// config.ini of the previous versions; files without profile blocks end up in a profile called "Default".
// Returns false when there is no such file.
static bool load_legacy_ini(const char *dir, char **saved_active_out) {
    char *path = g_strdup_printf("%s/config.ini", dir);
    chmod(path, 0600);
    FILE *f = fopen(path, "r");
    g_free(path);
    if (!f) return false;

    char line[8192];
    int section = 0; // 1=settings, 2=rules, 3=proxies, 4=profile header
    Profile *cur = NULL;
    char *saved_active = NULL;

    // pre multi-proxy config, migrated to a proxy called "default"
    char old_ip[256] = "", old_user[256] = "", old_pass[256] = "";
    int old_port = 0, old_type = PROXY_TYPE_SOCKS5;

    while (fgets(line, sizeof(line), f)) {
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
    fclose(f);

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
            px->send_domain = true;
            d->proxies = g_list_append(d->proxies, px);
            g_free(d->default_proxy);
            d->default_proxy = g_strdup("default");
        }
    }

    *saved_active_out = saved_active;
    return true;
}

static void finish_load(char *saved_active) {
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

static gint compare_names(gconstpointer a, gconstpointer b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

// sorted by file name, so the order is the same on every start
static void load_profile_files(const char *dir) {
    char *pdir = g_strdup_printf("%s/profiles", dir);
    GPtrArray *files = g_ptr_array_new_with_free_func(g_free);
    DIR *d = opendir(pdir);
    struct dirent *de;
    while (d && (de = readdir(d)) != NULL)
        if (strlen(de->d_name) > strlen(PBP_EXT)) g_ptr_array_add(files, g_strdup(de->d_name));
    if (d) closedir(d);
    g_ptr_array_sort(files, compare_names);

    for (guint i = 0; i < files->len; i++) {
        const char *file = g_ptr_array_index(files, i);
        char *name = pbp_name_from_filename(file);
        if (!name) continue;
        char *path = g_strdup_printf("%s/%s", pdir, file);
        struct pbp_profile src;
        char err[256];
        chmod(path, 0600);
        if (profile_find(name)) {
            /* duplicate name after decoding: keep the first */
        } else if (pbp_load_file(path, &src, err, sizeof err) == 0) {
            fill_profile_from_pbp(profile_new_empty(name), &src);
            pbp_free(&src);
        } else {
            fprintf(stderr, "ignoring profile '%s': %s\n", name, err);
        }
        g_free(path);
        free(name);
    }
    g_ptr_array_free(files, TRUE);
    g_free(pdir);
}

// profiles/<name>.pbprofile + settings.json; a config.ini from an older version is converted on first start
void load_config() {
    char *dir = config_dir();
    char *settings_active = NULL, *legacy_active = NULL;
    bool migrate = false;

    load_profile_files(dir);
    char *settings = g_strdup_printf("%s/settings.json", dir);
    pbp_settings_load(settings, &settings_active);
    g_free(settings);
    if (!g_profiles) {
        migrate = load_legacy_ini(dir, &legacy_active);
        for (GList *l = g_profiles; l != NULL; l = l->next) {      // the old file had one pair of switches for all profiles
            ((Profile *)l->data)->logging = g_chk_logging;
            ((Profile *)l->data)->dns = g_chk_dns;
        }
    }
    char *active = g_strdup(migrate && legacy_active ? legacy_active : settings_active);
    free(settings_active);
    g_free(legacy_active);
    finish_load(active);

    if (migrate) {
        save_config();
        char *from = g_strdup_printf("%s/config.ini", dir), *to = g_strdup_printf("%s/config.ini.bak", dir);
        if (rename(from, to) != 0) perror("could not set the old config.ini aside");
        g_free(from);
        g_free(to);
    }
    g_free(dir);
}
