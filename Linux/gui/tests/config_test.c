// root-free test of gui_config.c: profiles, migration, round trip, leak/heap stress
// build: see run_tests.sh
#include "gui.h"
#include "pb_profile.h"
#include <malloc.h>
#include <glib/gstdio.h>

GList *g_proxies_list = NULL;
char *g_default_proxy = NULL;
GList *g_rules_list = NULL;
bool g_chk_logging = true;
bool g_chk_dns = true;
bool g_chk_log_every = false;
bool g_chk_auto_clear = true;
int g_zoom = 100;
bool g_chk_updates = true;

// the log view lives in gui_logs.c; the test only records what the config code tells it
static size_t g_filters_seen;
void gui_logs_set_filters(const struct pbp_filter *f, size_t n) { (void)f; g_filters_seen = n; }

void free_proxy_data(ProxyData *p) {
    g_free(p->name); g_free(p->host); g_free(p->username); g_free(p->password); g_free(p);
}

void free_rule_data(RuleData *r) {
    g_free(r->name); g_free(r->process_name); g_free(r->target_hosts); g_free(r->target_ports); g_free(r->proxy_name); g_free(r);
}

static int failures = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static void write_file(const char *dir, const char *content) {
    char *path = g_strdup_printf("%s/config.ini", dir);
    g_file_set_contents(path, content, -1, NULL);
    g_free(path);
}

// 0 when the allocator is intercepted (ASan), LeakSanitizer covers that case
static size_t heap_used() {
    return mallinfo2().uordblks;
}

static void add_content(const char *proxy_name) {
    ProxyData *px = g_malloc0(sizeof(ProxyData));
    px->name = g_strdup(proxy_name); px->host = g_strdup("github.com"); px->port = 8080;
    px->username = g_strdup(""); px->password = g_strdup("s3cr|et");
    px->send_domain = false;
    g_proxies_list = g_list_append(g_proxies_list, px);
    g_free(g_default_proxy);
    g_default_proxy = g_strdup(proxy_name);
    RuleData *r = g_malloc0(sizeof(RuleData));
    r->process_name = g_strdup("curl"); r->target_hosts = g_strdup("*.github.com"); r->target_ports = g_strdup("*");
    r->action = RULE_ACTION_PROXY; r->proxy_name = g_strdup(proxy_name); r->enabled = true;
    r->name = g_strdup("Burp \"intercept\""); r->localhost = true;
    g_rules_list = g_list_append(g_rules_list, r);
}

static void check_storage(const char *dir) {
    struct stat st;
    char *p = g_strdup_printf("%s/profiles/Work.pbprofile", dir);
    CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600);       // profiles hold proxy credentials
    g_free(p);
    p = g_strdup_printf("%s/profiles", dir);
    CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0700);
    g_free(p);
    p = g_strdup_printf("%s/settings.json", dir);
    char *settings = NULL;
    CHECK(g_file_get_contents(p, &settings, NULL, NULL) && strstr(settings, "ActiveProfileName") &&
          !strstr(settings, "Logging") && !strstr(settings, "Dns"));      // nothing but the pointer to the active profile
    g_free(settings);
    g_free(p);
    p = g_strdup_printf("%s/profiles/Work.pbprofile", dir);
    char *prof = NULL;
    CHECK(g_file_get_contents(p, &prof, NULL, NULL) && strstr(prof, "\"IsTrafficLoggingEnabled\": false") && strstr(prof, "\"DnsViaProxy\": false"));
    g_free(prof);
    g_free(p);
    // the migration set the old file aside
    p = g_strdup_printf("%s/config.ini", dir);
    CHECK(stat(p, &st) != 0);
    g_free(p);
    p = g_strdup_printf("%s/config.ini.bak", dir);
    CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600);
    g_free(p);
}

static bool profile_file_exists(const char *dir, const char *file) {
    char *p = g_strdup_printf("%s/profiles/%s", dir, file);
    bool ok = g_file_test(p, G_FILE_TEST_EXISTS);
    g_free(p);
    return ok;
}

// import/export in the Windows .pbprofile format, odd names, corrupt files, file bookkeeping
static void test_pbprofile(const char *dir) {
    char err[256];
    CHECK(profile_activate("Default"));
    add_content("exp");
    char *out = g_strdup_printf("%s/out.pbprofile", dir);
    CHECK(profile_export(profile_find("Default"), out, err, sizeof err));
    char *json = NULL;
    CHECK(g_file_get_contents(out, &json, NULL, NULL));
    CHECK(json && strstr(json, "\"TargetDomains\": \"*.github.com\"") && strstr(json, "\"TargetHosts\": \"*\""));
    CHECK(json && strstr(json, "\"Type\": \"HTTP\"") != NULL);
    g_free(json);

    Profile *imp = profile_import(out, err, sizeof err);
    CHECK(imp && strcmp(imp->name, "Default") != 0);            // the "Name" in the file is taken, then made unique
    CHECK(imp && g_list_length(imp->proxies) == g_list_length(profile_find("Default")->proxies));
    CHECK(imp && g_list_length(imp->rules) == g_list_length(profile_find("Default")->rules));
    CHECK(imp && strcmp(((RuleData *)g_list_last(imp->rules)->data)->target_hosts, "*.github.com") == 0);
    Profile *imp2 = profile_import(out, err, sizeof err);
    CHECK(imp2 && imp && strcmp(imp2->name, imp->name) != 0);

    // a hostile or damaged file is refused and changes nothing
    guint before = g_list_length(g_profiles);
    char *bad = g_strdup_printf("%s/bad.pbprofile", dir);
    g_file_set_contents(bad, "{\"ProxyRules\":[{\"ProxyConfigId\":42}]}", -1, NULL);
    CHECK(profile_import(bad, err, sizeof err) == NULL && strstr(err, "does not match"));
    g_file_set_contents(bad, "garbage", -1, NULL);
    CHECK(profile_import(bad, err, sizeof err) == NULL);
    CHECK(profile_import("/nonexistent.pbprofile", err, sizeof err) == NULL);
    CHECK(g_list_length(g_profiles) == before);
    g_free(bad);

    // names with path characters are stored safely and survive a restart
    CHECK(profile_create("../../etc/x", false) != NULL);
    CHECK(profile_create("a/b:c*", false) != NULL);
    save_config();
    char *esc_check = g_strdup_printf("%s/../../etc/x", dir);
    CHECK(!g_file_test(esc_check, G_FILE_TEST_EXISTS));            // nothing was written outside the profiles directory
    g_free(esc_check);
    config_free_all();
    load_config();
    CHECK(profile_find("../../etc/x") && profile_find("a/b:c*"));

    // rename and delete take their files with them
    CHECK(profile_rename(profile_find("a/b:c*"), "plain"));
    save_config();
    CHECK(profile_file_exists(dir, "plain.pbprofile"));
    CHECK(profile_delete(profile_find("plain")));
    CHECK(!profile_file_exists(dir, "plain.pbprofile"));
    config_free_all();
    load_config();
    CHECK(!profile_find("plain") && !profile_find("a/b:c*"));

    // a damaged file in the profiles directory is skipped, kept on disk, and the rest still loads
    char *broken = g_strdup_printf("%s/profiles/Broken.pbprofile", dir);
    g_file_set_contents(broken, "{ not json", -1, NULL);
    config_free_all();
    load_config();
    CHECK(!profile_find("Broken") && profile_find("Default"));
    save_config();
    CHECK(profile_file_exists(dir, "Broken.pbprofile"));
    g_remove(broken);
    g_free(broken);
    g_free(out);

    for (GList *l = g_profiles; l;) {                              // back to a single profile for the stress run
        Profile *p = (Profile *)l->data;
        l = l->next;
        if (strcmp(p->name, "Default") != 0) CHECK(profile_delete(p));
    }
    CHECK(g_list_length(g_profiles) == 1 && strcmp(g_active_profile, "Default") == 0);
    g_free(g_default_proxy);
    for (GList *l = g_proxies_list; l; l = l->next) free_proxy_data(l->data);
    for (GList *l = g_rules_list; l; l = l->next) free_rule_data(l->data);
    g_list_free(g_proxies_list); g_list_free(g_rules_list);
    g_proxies_list = g_rules_list = NULL;
    g_default_proxy = NULL;
    save_config();
}

int main() {
    char *dir = g_dir_make_tmp("pbcfg-XXXXXX", NULL);
    CHECK(dir != NULL);
    setenv("PROXYBRIDGE_CONFIG_DIR", dir, 1);

    load_config();
    CHECK(g_list_length(g_profiles) == 1 && strcmp(g_active_profile, "Default") == 0);
    config_free_all();

    // old single-proxy format
    write_file(dir, "[SETTINGS]\nip=1.2.3.4\nport=1080\ntype=1\nuser=u\npass=p|w\nlogging=0\ndns=1\n[RULES]\n3|2|0|1|firefox|*|443;80|\n");
    load_config();
    CHECK(strcmp(g_active_profile, "Default") == 0);
    CHECK(g_list_length(g_proxies_list) == 1);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->host, "1.2.3.4") == 0);
    CHECK(strcmp(g_default_proxy, "default") == 0);
    CHECK(g_list_length(g_rules_list) == 1 && strcmp(((RuleData *)g_rules_list->data)->target_ports, "443;80") == 0);
    CHECK(!g_chk_logging);

    CHECK(profile_create("Work", false) != NULL);
    CHECK(profile_create("Work", false) == NULL);
    CHECK(profile_create("", false) == NULL);
    Profile *dup = profile_create("Copy", true);
    CHECK(dup && g_list_length(dup->proxies) == 1 && g_list_length(dup->rules) == 1);
    CHECK(profile_rename(profile_find("Copy"), "Home"));
    CHECK(!profile_rename(profile_find("Home"), "Work"));
    CHECK(profile_activate("Work"));
    CHECK(g_proxies_list == NULL && g_rules_list == NULL);
    add_content("p 1|x");
    CHECK(g_chk_logging && g_chk_dns);                      // a new profile starts with both switches on
    g_chk_dns = false;
    g_chk_logging = false;
    g_chk_log_every = true;
    g_chk_auto_clear = false;
    g_zoom = 140;
    g_chk_updates = false;
    {
        struct pbp_filter *fl = calloc(2, sizeof *fl);
        struct pbp_filter a = { true, (char *)"chrome*", (char *)"10.*", (char *)"443", (char *)"TCP", (char *)"Proxy" };
        struct pbp_filter b = { false, (char *)"", (char *)"", (char *)"", (char *)"All", (char *)"All" };
        fl[0] = pbp_filter_dup(&a);
        fl[1] = pbp_filter_dup(&b);
        gui_filters_replace(fl, 2);
        CHECK(g_filters_seen == 2);
    }
    save_config();

    check_storage(dir);

    config_free_all();
    load_config();
    CHECK(g_list_length(g_profiles) == 3 && strcmp(g_active_profile, "Work") == 0);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->name, "p 1|x") == 0);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->password, "s3cr|et") == 0);
    CHECK(strcmp(((RuleData *)g_rules_list->data)->target_hosts, "*.github.com") == 0);
    CHECK(!((ProxyData *)g_proxies_list->data)->send_domain);                       // per-proxy "DNS via proxy" survives a restart
    CHECK(strcmp(((RuleData *)g_rules_list->data)->name, "Burp \"intercept\"") == 0 && ((RuleData *)g_rules_list->data)->localhost);
    CHECK(!g_chk_dns && !g_chk_logging && g_chk_log_every);   // restored from the Work profile file itself
    CHECK(!g_chk_auto_clear && g_zoom == 140 && !g_chk_updates);   // zoom and auto-clear belong to the profile, the update check to settings.json
    {
        size_t n = 0;
        struct pbp_filter *fl = gui_filters(&n);
        CHECK(n == 2 && fl && fl[0].exclude && strcmp(fl[0].process, "chrome*") == 0 && strcmp(fl[0].port, "443") == 0 &&
              strcmp(fl[0].protocol, "TCP") == 0 && strcmp(fl[0].action, "Proxy") == 0 && !fl[1].exclude);
        CHECK(g_filters_seen == 2);                                // the log view got the filters when the profile was loaded
    }
    CHECK(profile_find("Home") && !profile_find("Home")->logging && profile_find("Home")->dns);   // migrated values of the old file, per profile
    CHECK(profile_find("Home") && g_list_length(profile_find("Home")->rules) == 1);

    CHECK(profile_activate("Home"));                        // switching profiles switches the values too
    CHECK(!g_chk_logging && g_chk_dns && !g_chk_log_every);
    CHECK(g_chk_auto_clear && g_zoom == 100 && g_filters_seen == 0);   // the migrated profile has the defaults
    CHECK(profile_activate("Work"));
    CHECK(!g_chk_logging && !g_chk_dns && g_chk_log_every && g_zoom == 140 && g_filters_seen == 2);
    CHECK(profile_activate("Home"));
    CHECK(profile_activate("Work"));
    CHECK(profile_delete(profile_find("Work")));
    CHECK(strcmp(g_active_profile, "Default") == 0 && g_list_length(g_rules_list) == 1);
    CHECK(profile_delete(profile_find("Home")));
    CHECK(!profile_delete(profile_find("Default")));
    CHECK(g_list_length(g_profiles) == 1);
    save_config();
    test_pbprofile(dir);
    config_free_all();

    // stress: heap must return to baseline
    load_config();
    for (int i = 0; i < 200; i++) {                   // warm up allocator caches
        Profile *p = profile_create("w", true);
        if (p) profile_delete(p);
    }
    size_t base = heap_used();
    for (int i = 0; i < 1500; i++) {                  // every pass writes profile files to disk
        char *a = g_strdup_printf("p%d", i), *b = g_strdup_printf("q%d", i), *c = g_strdup_printf("c%d", i);
        CHECK(profile_create(a, false) != NULL);
        CHECK(profile_activate(a));
        add_content("px");
        CHECK(profile_rename(profile_find(a), b));
        CHECK(profile_create(c, true) != NULL);
        save_config();
        if (i % 1000 == 0) {
            config_free_all();
            load_config();
        }
        CHECK(profile_activate("Default"));
        CHECK(profile_delete(profile_find(b)));
        CHECK(profile_delete(profile_find(c)));
        g_free(a); g_free(b); g_free(c);
    }
    size_t after = heap_used();
    printf("heap before=%zu after=%zu\n", base, after);
    CHECK(base == 0 || after < base + 64 * 1024);
    CHECK(g_list_length(g_profiles) == 1);

    config_free_all();
    g_free(dir);
    if (!failures) printf("config_test: all passed\n");
    return failures ? 1 : 0;
}
