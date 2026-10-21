#include "gui.h"
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include "pb_profile.h"

GList *g_profiles = NULL;
bool g_chk_boot = false;
char *g_active_profile = NULL;

static const char *config_dir_path() {
    return pbp_config_dir();
}

static char *config_dir() {
    return g_strdup(pbp_config_dir());
}

char *profile_path(const char *name) {
    char *file = pbp_filename_for(name);
    if (!file) return NULL;
    char *dir = config_dir();
    char *path = g_strdup_printf("%s/profiles/%s", dir, file);
    free(file);
    g_free(dir);
    return path;
}

// ---- where profiles live ---------------------------------------------------------------------------------------------------
// The window reads and writes profiles through a small interface: files under /etc/proxybridge when it runs as root with its own
// engine, or the ProxyBridge service (pb_client.c) when it does not have root. The model and the .pbprofile code are the same.
static bool ensure_private_dir(const char *dir);

static bool file_list(GPtrArray *names) {
    char *pdir = g_strdup_printf("%s/profiles", config_dir_path());
    DIR *d = opendir(pdir);
    struct dirent *de;
    while (d && (de = readdir(d)) != NULL) {
        if (strlen(de->d_name) <= strlen(PBP_EXT)) continue;
        char *name = pbp_name_from_filename(de->d_name);
        if (name) { g_ptr_array_add(names, g_strdup(name)); free(name); }
    }
    if (d) closedir(d);
    g_free(pdir);
    return true;
}

static char *file_get(const char *name) {
    char *path = profile_path(name);
    if (!path) return NULL;
    chmod(path, 0600);
    char *data = NULL;
    gsize len = 0;
    if (!g_file_get_contents(path, &data, &len, NULL) || len > PBP_MAX_FILE) { g_free(data); data = NULL; }
    g_free(path);
    return data;
}

static bool file_put(const char *name, const char *data, char *err, size_t en) {
    char *dir = g_strdup(config_dir_path());
    char *pdir = g_strdup_printf("%s/profiles", dir);
    char *path = profile_path(name);
    bool ok = false;
    if (!path) snprintf(err, en, "the name is too long to be stored");
    else if (!ensure_private_dir(dir) || !ensure_private_dir(pdir)) snprintf(err, en, "cannot create %s", pdir);
    else ok = pbp_write_file(path, data, err, en) == 0;
    g_free(path); g_free(pdir); g_free(dir);
    return ok;
}

static bool file_del(const char *name) {
    char *path = profile_path(name);
    if (path) unlink(path);
    g_free(path);
    return true;
}

static bool file_exists(const char *name) {
    char *path = profile_path(name);
    bool yes = path && access(path, F_OK) == 0;
    g_free(path);
    return yes;
}

static bool file_settings_get(char **active, bool *updates, bool *boot) {
    char *p = g_strdup_printf("%s/settings.json", config_dir_path());
    bool ok = pbp_settings_load(p, active, updates, boot) == 0;
    g_free(p);
    return ok;
}

static bool file_settings_set(const char *active, bool updates, bool boot, char *err, size_t en) {
    char *dir = g_strdup(config_dir_path());
    char *p = g_strdup_printf("%s/settings.json", dir);
    bool ok = ensure_private_dir(dir) && pbp_settings_save(p, active, updates, boot, err, en) == 0;
    g_free(p); g_free(dir);
    return ok;
}

static char *file_legacy_get(void) {
    char *path = g_strdup_printf("%s/config.ini", config_dir_path());
    chmod(path, 0600);
    char *data = NULL;
    gsize len = 0;
    if (!g_file_get_contents(path, &data, &len, NULL) || len > (1u << 20)) { g_free(data); data = NULL; }
    g_free(path);
    return data;
}

static void file_legacy_done(void) {
    char *from = g_strdup_printf("%s/config.ini", config_dir_path()), *to = g_strdup_printf("%s/config.ini.bak", config_dir_path());
    if (rename(from, to) != 0) perror("could not set the old config.ini aside");
    g_free(from);
    g_free(to);
}

const struct gui_store gui_store_files = { file_list, file_get, file_put, file_del, file_exists, file_settings_get, file_settings_set,
                                           file_legacy_get, file_legacy_done };
static const struct gui_store *g_store = &gui_store_files;
void gui_store_use(const struct gui_store *s) { g_store = s ? s : &gui_store_files; }

// the file of a deleted or renamed profile must go, or it would come back at the next start
static void remove_profile_file(const char *name) {
    g_store->del(name);
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
    for (size_t i = 0; i < p->nfilters; i++) pbp_filter_clear(&p->filters[i]);
    free(p->filters);
    g_free(p);
}

struct pbp_filter pbp_filter_dup(const struct pbp_filter *f) {
    struct pbp_filter d = { f->exclude, strdup(f->process ? f->process : ""), strdup(f->ip ? f->ip : ""), strdup(f->port ? f->port : ""),
                            strdup(f->protocol ? f->protocol : "All"), strdup(f->action ? f->action : "All") };
    return d;
}

void pbp_filter_clear(struct pbp_filter *f) {
    free(f->process); free(f->ip); free(f->port); free(f->protocol); free(f->action);
    memset(f, 0, sizeof *f);
}

static struct pbp_filter *filters_dup(const struct pbp_filter *src, size_t n) {
    struct pbp_filter *d = calloc(n ? n : 1, sizeof *d);
    for (size_t i = 0; d && i < n; i++) d[i] = pbp_filter_dup(&src[i]);
    return d;
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
    p->log_every = g_chk_log_every;
    p->auto_clear = g_chk_auto_clear;
    p->zoom = g_zoom;
}

static void load_globals_from(Profile *p) {
    g_proxies_list = p->proxies;
    g_rules_list = p->rules;
    g_default_proxy = p->default_proxy;
    g_chk_logging = p->logging;
    g_chk_dns = p->dns;
    g_chk_log_every = p->log_every;
    g_chk_auto_clear = p->auto_clear;
    g_zoom = p->zoom;
    gui_logs_set_filters(p->filters, p->nfilters);
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
    p->auto_clear = true;
    p->zoom = 100;
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
        p->log_every = src->log_every;
        p->auto_clear = src->auto_clear;
        p->zoom = src->zoom;
        p->filters = filters_dup(src->filters, src->nfilters);
        p->nfilters = src->nfilters;
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
    out->log_every = prof->log_every;
    out->auto_clear = prof->auto_clear;
    out->font_zoom = prof->zoom;
    out->filters = prof->filters;
    out->nfilters = prof->nfilters;
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
    p->log_every = src->log_every;
    p->auto_clear = src->auto_clear;
    p->zoom = src->font_zoom >= PBP_ZOOM_MIN && src->font_zoom <= PBP_ZOOM_MAX ? src->font_zoom : 100;
    for (size_t i = 0; i < p->nfilters; i++) pbp_filter_clear(&p->filters[i]);
    free(p->filters);
    p->filters = filters_dup(src->filters, src->nfilters);
    p->nfilters = src->nfilters;
}

// Under sudo or pkexec the file is written by root into the invoking user's directory: hand it to that user, so the
// "readable by you only" promise means the person at the keyboard. Only when the directory is theirs, never elsewhere.
static void give_to_invoker(const char *path) {
    const char *uid_s = getenv("PKEXEC_UID"), *gid_s = getenv("SUDO_GID");
    if (!uid_s) uid_s = getenv("SUDO_UID");
    if (!uid_s || !*uid_s) return;
    char *end = NULL;
    guint64 uid = g_ascii_strtoull(uid_s, &end, 10);
    if (!end || *end || uid == 0 || uid > 0xFFFFFFFEull) return;
    char *dir = g_path_get_dirname(path);
    struct stat st;
    bool theirs = stat(dir, &st) == 0 && st.st_uid == (uid_t)uid;
    g_free(dir);
    if (!theirs) return;
    guint64 gid = st.st_gid;
    if (gid_s && *gid_s) { gid = g_ascii_strtoull(gid_s, &end, 10); if (!end || *end || gid > 0xFFFFFFFEull) gid = st.st_gid; }
    // lchown: if the invoker swapped the file for a symlink in their own directory, it is the link that changes hands, not its target
    if (lchown(path, (uid_t)uid, (gid_t)gid) != 0) g_warning("could not hand %s to the invoking user: %s", path, g_strerror(errno));
}

bool profile_export(const Profile *prof, const char *path, char *err, size_t errlen) {
    profile_sync_active();
    struct pbp_profile view;
    profile_to_pbp(prof, &view);
    bool ok = pbp_save_file(path, &view, err, errlen) == 0;
    free_pbp_view(&view);
    if (ok) give_to_invoker(path);
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

    char err[256];
    for (GList *l = g_profiles; l != NULL; l = l->next) {
        Profile *prof = (Profile *)l->data;
        struct pbp_profile view;
        profile_to_pbp(prof, &view);
        char *json = pbp_serialize(&view);
        free_pbp_view(&view);
        if (json && !(prof->saved && strcmp(prof->saved, json) == 0 && g_store->exists(prof->name))) {
            if (g_store->put(prof->name, json, err, sizeof err)) {
                free(prof->saved);
                prof->saved = json;
                json = NULL;
            } else {
                fprintf(stderr, "failed to save profile '%s': %s\n", prof->name, err);
            }
        }
        free(json);
    }
    if (!g_store->settings_set(g_active_profile, g_chk_updates, g_chk_boot, err, sizeof err))
        fprintf(stderr, "failed to save settings: %s\n", err);
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
static bool load_legacy_ini(const char *text, char **saved_active_out) {
    FILE *f = fmemopen((void *)text, strlen(text), "r");
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

// sorted by name, so the order is the same on every start
static void load_profile_files() {
    GPtrArray *names = g_ptr_array_new_with_free_func(g_free);
    g_store->list(names);
    g_ptr_array_sort(names, compare_names);

    for (guint i = 0; i < names->len; i++) {
        const char *name = g_ptr_array_index(names, i);
        if (profile_find(name)) continue;               // duplicate name after decoding: keep the first
        char *data = g_store->get(name);
        struct pbp_profile src;
        char err[256];
        if (!data) {
            fprintf(stderr, "ignoring profile '%s': cannot be read\n", name);
        } else if (pbp_parse(data, strlen(data), &src, err, sizeof err) == 0) {
            fill_profile_from_pbp(profile_new_empty(name), &src);
            pbp_free(&src);
        } else {
            fprintf(stderr, "ignoring profile '%s': %s\n", name, err);
        }
        g_free(data);
    }
    g_ptr_array_free(names, TRUE);
}

// profiles/<name>.pbprofile + settings.json; a config.ini from an older version is converted on first start
void load_config() {
    char *settings_active = NULL, *legacy_active = NULL;
    bool migrate = false;

    load_profile_files();
    g_store->settings_get(&settings_active, &g_chk_updates, &g_chk_boot);
    if (!g_profiles) {                                          // a config.ini of an older version (3.2.x, the Linux beta) sits next to the profiles
        char *old = g_store->legacy_get();
        if (old) {
            migrate = load_legacy_ini(old, &legacy_active);
            g_free(old);
        }
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
        g_store->legacy_done();
    }
}

struct pbp_filter *gui_filters(size_t *n) {
    Profile *p = profile_find(g_active_profile);
    if (n) *n = p ? p->nfilters : 0;
    return p ? p->filters : NULL;
}

void gui_filters_replace(struct pbp_filter *filters, size_t n) {
    Profile *p = profile_find(g_active_profile);
    if (!p) return;
    for (size_t i = 0; i < p->nfilters; i++) pbp_filter_clear(&p->filters[i]);
    free(p->filters);
    p->filters = filters;
    p->nfilters = n;
    gui_logs_set_filters(p->filters, p->nfilters);
}
