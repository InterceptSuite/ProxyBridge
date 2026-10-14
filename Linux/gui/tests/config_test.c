// root-free test of gui_config.c: profiles, migration, round trip, leak/heap stress
// build: see run_tests.sh
#include "gui.h"
#include <malloc.h>

GList *g_proxies_list = NULL;
char *g_default_proxy = NULL;
GList *g_rules_list = NULL;
bool g_chk_logging = true;
bool g_chk_dns = true;

void free_proxy_data(ProxyData *p) {
    g_free(p->name); g_free(p->host); g_free(p->username); g_free(p->password); g_free(p);
}

void free_rule_data(RuleData *r) {
    g_free(r->process_name); g_free(r->target_hosts); g_free(r->target_ports); g_free(r->proxy_name); g_free(r);
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
    g_proxies_list = g_list_append(g_proxies_list, px);
    g_default_proxy = g_strdup(proxy_name);
    RuleData *r = g_malloc0(sizeof(RuleData));
    r->process_name = g_strdup("curl"); r->target_hosts = g_strdup("*.github.com"); r->target_ports = g_strdup("*");
    r->action = RULE_ACTION_PROXY; r->proxy_name = g_strdup(proxy_name); r->enabled = true;
    g_rules_list = g_list_append(g_rules_list, r);
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
    g_chk_dns = false;
    save_config();

    char *path = g_strdup_printf("%s/config.ini", dir);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    g_free(path);

    config_free_all();
    load_config();
    CHECK(g_list_length(g_profiles) == 3 && strcmp(g_active_profile, "Work") == 0);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->name, "p 1|x") == 0);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->password, "s3cr|et") == 0);
    CHECK(strcmp(((RuleData *)g_rules_list->data)->target_hosts, "*.github.com") == 0);
    CHECK(!g_chk_dns && !g_chk_logging);
    CHECK(profile_find("Home") && g_list_length(profile_find("Home")->rules) == 1);

    CHECK(profile_delete(profile_find("Work")));
    CHECK(strcmp(g_active_profile, "Default") == 0 && g_list_length(g_rules_list) == 1);
    CHECK(profile_delete(profile_find("Home")));
    CHECK(!profile_delete(profile_find("Default")));
    CHECK(g_list_length(g_profiles) == 1);
    save_config();
    config_free_all();

    // stress: heap must return to baseline
    load_config();
    for (int i = 0; i < 200; i++) {                   // warm up allocator caches
        Profile *p = profile_create("w", true);
        if (p) profile_delete(p);
    }
    size_t base = heap_used();
    for (int i = 0; i < 20000; i++) {
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
