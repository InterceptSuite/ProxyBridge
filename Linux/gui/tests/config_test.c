// root-free test of gui_config.c (profiles, migration, round trip)
// build: gcc -I../../src -I.. -D_GNU_SOURCE $(pkg-config --cflags gtk+-3.0) config_test.c ../gui_config.c -o config_test $(pkg-config --libs gtk+-3.0)
#include "gui.h"

GList *g_proxies_list = NULL;
char *g_default_proxy = NULL;
GList *g_rules_list = NULL;
bool g_chk_logging = true;
bool g_chk_dns = true;

void free_proxy_data(ProxyData *p) {
    if (!p) return;
    g_free(p->name); g_free(p->host); g_free(p->username); g_free(p->password); g_free(p);
}
void free_rule_data(RuleData *r) {
    if (!r) return;
    g_free(r->process_name); g_free(r->target_hosts); g_free(r->target_ports); g_free(r->proxy_name); g_free(r);
}

static int failures = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static void reset_state() {
    g_profiles = NULL; g_active_profile = NULL;
    g_proxies_list = NULL; g_rules_list = NULL; g_default_proxy = NULL;
    g_chk_logging = true; g_chk_dns = true;
}

static void write_file(const char *dir, const char *content) {
    char *path = g_strdup_printf("%s/config.ini", dir);
    g_file_set_contents(path, content, -1, NULL);
    g_free(path);
}

int main() {
    char *dir = g_dir_make_tmp("pbcfg-XXXXXX", NULL);
    CHECK(dir != NULL);
    setenv("PROXYBRIDGE_CONFIG_DIR", dir, 1);

    // 1. no file -> one "Default" profile
    reset_state();
    load_config();
    CHECK(g_list_length(g_profiles) == 1);
    CHECK(strcmp(g_active_profile, "Default") == 0);

    // 2. old single-proxy format
    write_file(dir, "[SETTINGS]\nip=1.2.3.4\nport=1080\ntype=1\nuser=u\npass=p|w\nlogging=0\ndns=1\n[RULES]\n3|2|0|1|firefox|*|443;80|\n");
    reset_state();
    load_config();
    CHECK(strcmp(g_active_profile, "Default") == 0);
    CHECK(g_list_length(g_proxies_list) == 1);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->name, "default") == 0);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->host, "1.2.3.4") == 0);
    CHECK(strcmp(g_default_proxy, "default") == 0);
    CHECK(g_list_length(g_rules_list) == 1);
    CHECK(strcmp(((RuleData *)g_rules_list->data)->target_ports, "443;80") == 0);
    CHECK(!g_chk_logging);

    // 3. profiles: create, add data, rename, switch, save, reload
    CHECK(profile_create("Work", false) != NULL);
    CHECK(profile_create("Work", false) == NULL);
    CHECK(profile_create("", false) == NULL);
    Profile *dup = profile_create("Copy", true);
    CHECK(dup && g_list_length(dup->proxies) == 1 && g_list_length(dup->rules) == 1);
    CHECK(profile_rename(profile_find("Copy"), "Home"));
    CHECK(!profile_rename(profile_find("Home"), "Work"));
    CHECK(profile_activate("Work"));
    CHECK(g_proxies_list == NULL && g_rules_list == NULL);
    ProxyData *px = g_malloc0(sizeof(ProxyData));
    px->name = g_strdup("p 1|x"); px->host = g_strdup("github.com"); px->port = 8080;
    px->username = g_strdup(""); px->password = g_strdup("s3cr|et");
    g_proxies_list = g_list_append(g_proxies_list, px);
    g_default_proxy = g_strdup("p 1|x");
    RuleData *r = g_malloc0(sizeof(RuleData));
    r->process_name = g_strdup("curl"); r->target_hosts = g_strdup("*.github.com"); r->target_ports = g_strdup("*");
    r->protocol = RULE_PROTOCOL_BOTH; r->action = RULE_ACTION_PROXY; r->proxy_name = g_strdup("p 1|x"); r->enabled = true;
    g_rules_list = g_list_append(g_rules_list, r);
    g_chk_dns = false;
    save_config();

    char *path = g_strdup_printf("%s/config.ini", dir);
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    g_free(path);

    reset_state();
    load_config();
    CHECK(g_list_length(g_profiles) == 3);
    CHECK(strcmp(g_active_profile, "Work") == 0);
    CHECK(g_list_length(g_proxies_list) == 1);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->name, "p 1|x") == 0);
    CHECK(strcmp(((ProxyData *)g_proxies_list->data)->password, "s3cr|et") == 0);
    CHECK(strcmp(((RuleData *)g_rules_list->data)->target_hosts, "*.github.com") == 0);
    CHECK(strcmp(((RuleData *)g_rules_list->data)->proxy_name, "p 1|x") == 0);
    CHECK(!g_chk_dns && !g_chk_logging);
    CHECK(profile_find("Home") && g_list_length(profile_find("Home")->rules) == 1);

    // 4. delete: non-last allowed, active one falls back, last refused
    CHECK(profile_delete(profile_find("Work")));
    CHECK(strcmp(g_active_profile, "Default") == 0 && g_list_length(g_rules_list) == 1);
    CHECK(profile_delete(profile_find("Home")));
    CHECK(!profile_delete(profile_find("Default")));
    CHECK(g_list_length(g_profiles) == 1);

    if (failures == 0) printf("config_test: all passed\n");
    return failures ? 1 : 0;
}
