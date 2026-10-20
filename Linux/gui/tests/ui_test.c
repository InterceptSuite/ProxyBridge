// Drives the real ProxyBridge window and its dialogs (GTK Broadway backend, needs root like the GUI itself).
// The program under test is main.c compiled with -Dmain=pb_gui_main; pb_gui_ready_hook hands control to this test once the window
// exists. Dialogs run modal loops, so every dialog the test expects is "armed" first: an independent timer source finds it by
// widget name, fills it in and answers it. Results are checked in the widgets, in the model and in the profile file on disk.
#include "gui.h"
#include "pb_profile.h"

extern void (*pb_gui_ready_hook)(void);
extern int pb_gui_main(int argc, char *argv[]);

static int checks, fails;
#define STEP(msg) do { printf("  . %s\n", msg); fflush(stdout); } while (0)
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_STR(got, want) do { const char *g_ = (got), *w_ = (want); checks++; \
    if (!g_ || strcmp(g_, w_) != 0) { fails++; printf("FAIL %s:%d  got '%s', wanted '%s'\n", __FILE__, __LINE__, g_ ? g_ : "(null)", w_); } } while (0)
#define CHECK_HAS(got, want) do { const char *g_ = (got), *w_ = (want); checks++; \
    if (!g_ || !strstr(g_, w_)) { fails++; printf("FAIL %s:%d  '%s' lacks '%s'\n", __FILE__, __LINE__, g_ ? g_ : "(null)", w_); } } while (0)

static void pump(int ms) {
    gint64 end = g_get_monotonic_time() + (gint64)ms * 1000;
    while (g_get_monotonic_time() < end) {
        while (gtk_events_pending()) gtk_main_iteration();
        g_usleep(2000);
    }
}

// ---- finding widgets ------------------------------------------------------------------------------------------------------
typedef struct { const char *key; GtkWidget *found; bool by_label; } Find;

static void find_cb(GtkWidget *w, gpointer p) {
    Find *f = p;
    if (f->found) return;
    if (f->by_label) {
        if (GTK_IS_MENU_ITEM(w)) {
            const char *l = gtk_menu_item_get_label(GTK_MENU_ITEM(w));
            if (l && strcmp(l, f->key) == 0) { f->found = w; return; }
        }
    } else {
        const char *n = gtk_widget_get_name(w);
        if (n && strcmp(n, f->key) == 0) { f->found = w; return; }
    }
    if (GTK_IS_MENU_ITEM(w)) {
        GtkWidget *sub = gtk_menu_item_get_submenu(GTK_MENU_ITEM(w));
        if (sub) find_cb(sub, p);
    }
    if (GTK_IS_CONTAINER(w)) gtk_container_foreach(GTK_CONTAINER(w), find_cb, p);
}

static GtkWidget *find_in(GtkWidget *root, const char *name) {
    Find f = { name, NULL, false };
    find_cb(root, &f);
    return f.found;
}

static GtkWidget *find_named(const char *name) {
    GList *tops = gtk_window_list_toplevels();
    Find f = { name, NULL, false };
    for (GList *l = tops; l && !f.found; l = l->next) find_cb(l->data, &f);
    g_list_free(tops);
    return f.found;
}

static GtkWidget *menu_item(const char *label) {
    Find f = { label, NULL, true };
    find_cb(window, &f);
    return f.found;
}

static void click(const char *name) {
    GtkWidget *w = find_named(name);
    CHECK(w != NULL);
    if (w) gtk_button_clicked(GTK_BUTTON(w));
}

static void activate(const char *label) {
    GtkWidget *w = menu_item(label);
    CHECK(w != NULL);
    if (w) gtk_menu_item_activate(GTK_MENU_ITEM(w));
}

// ---- answering dialogs ----------------------------------------------------------------------------------------------------
typedef void (*FillFn)(GtkWidget *, gpointer);
typedef struct { const char *name; FillFn fill; gpointer arg; int response; int ticks; int line; } Armed;

static GtkWidget *visible_dialog(const char *name) {
    GList *tops = gtk_window_list_toplevels();
    GtkWidget *found = NULL;
    for (GList *l = tops; l; l = l->next) {
        GtkWidget *w = l->data;
        if (!GTK_IS_DIALOG(w) || !gtk_widget_get_visible(w)) continue;
        bool match = strcmp(name, "msg") == 0 ? GTK_IS_MESSAGE_DIALOG(w)
                   : strcmp(name, "chooser") == 0 ? GTK_IS_FILE_CHOOSER_DIALOG(w)
                   : strcmp(gtk_widget_get_name(w), name) == 0;
        if (match) found = w;
    }
    g_list_free(tops);
    return found;
}

static gboolean armed_poll(gpointer p) {
    Armed *a = p;
    GtkWidget *d = visible_dialog(a->name);
    if (!d) {
        if (++a->ticks > 500) {
            CHECK(!"an expected dialog never appeared");
            printf("   (armed at line %d, waiting for '%s')\n", a->line, a->name);
            g_free(a);
            return G_SOURCE_REMOVE;
        }
        return G_SOURCE_CONTINUE;
    }
    FillFn fill = a->fill;
    gpointer arg = a->arg;
    int response = a->response;
    g_free(a);                          // before filling: a fill may arm the next dialog
    if (fill) fill(d, arg);
    if (response) gtk_dialog_response(GTK_DIALOG(d), response);
    return G_SOURCE_REMOVE;
}

static void arm_at(int line, const char *name, FillFn fill, gpointer arg, int response) {
    Armed *a = g_malloc0(sizeof *a);
    a->name = name; a->fill = fill; a->arg = arg; a->response = response; a->line = line;
    g_timeout_add(30, armed_poll, a);
}

static char *last_msg;
static void remember_msg(GtkWidget *d, gpointer arg) {
    (void)arg;
    g_free(last_msg);
    g_object_get(d, "text", &last_msg, NULL);
}
#define arm(name, fill, arg, response) arm_at(__LINE__, name, fill, arg, response)
#define arm_msg(response) arm_at(__LINE__, "msg", remember_msg, NULL, response)

// ---- widget helpers -------------------------------------------------------------------------------------------------------
static void set_text(GtkWidget *dlg, const char *name, const char *text) {
    GtkWidget *w = find_in(dlg, name);
    CHECK(w != NULL);
    if (!w) return;
    if (GTK_IS_TEXT_VIEW(w)) gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(w)), text, -1);
    else gtk_entry_set_text(GTK_ENTRY(w), text);
}

static char *get_text(GtkWidget *dlg, const char *name) {
    GtkWidget *w = find_in(dlg, name);
    if (!w) return g_strdup("");
    if (GTK_IS_TEXT_VIEW(w)) {
        GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(w));
        GtkTextIter s, e;
        gtk_text_buffer_get_bounds(b, &s, &e);
        return gtk_text_buffer_get_text(b, &s, &e, FALSE);
    }
    if (GTK_IS_LABEL(w)) return g_strdup(gtk_label_get_text(GTK_LABEL(w)));
    return g_strdup(gtk_entry_get_text(GTK_ENTRY(w)));
}

static void set_combo(GtkWidget *dlg, const char *name, int idx) {
    GtkWidget *w = find_in(dlg, name);
    CHECK(w != NULL);
    if (w) gtk_combo_box_set_active(GTK_COMBO_BOX(w), idx);
}

static int get_combo(GtkWidget *dlg, const char *name) {
    GtkWidget *w = find_in(dlg, name);
    return w ? gtk_combo_box_get_active(GTK_COMBO_BOX(w)) : -2;
}

static void set_check(GtkWidget *dlg, const char *name, bool on) {
    GtkWidget *w = find_in(dlg, name);
    CHECK(w != NULL);
    if (w) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), on);
}

static bool get_check(GtkWidget *dlg, const char *name) {
    GtkWidget *w = find_in(dlg, name);
    return w && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w));
}

static bool is_sensitive(GtkWidget *root, const char *name) {
    GtkWidget *w = find_in(root, name);
    return w && gtk_widget_get_sensitive(w);
}

static void select_row(const char *tree_name, int idx) {
    GtkWidget *t = find_named(tree_name);
    CHECK(t != NULL);
    if (!t) return;
    GtkTreePath *p = gtk_tree_path_new_from_indices(idx, -1);
    gtk_tree_selection_select_path(gtk_tree_view_get_selection(GTK_TREE_VIEW(t)), p);
    gtk_tree_path_free(p);
}

static void unselect_all(const char *tree_name) {
    GtkWidget *t = find_named(tree_name);
    if (t) gtk_tree_selection_unselect_all(gtk_tree_view_get_selection(GTK_TREE_VIEW(t)));
}

static int model_rows(const char *tree_name) {
    GtkWidget *t = find_named(tree_name);
    return t ? gtk_tree_model_iter_n_children(gtk_tree_view_get_model(GTK_TREE_VIEW(t)), NULL) : -1;
}

static bool select_by_first_column(const char *tree_name, const char *text) {
    GtkWidget *t = find_named(tree_name);
    if (!t) return false;
    GtkTreeModel *m = gtk_tree_view_get_model(GTK_TREE_VIEW(t));
    GtkTreeIter it;
    bool ok = gtk_tree_model_get_iter_first(m, &it);
    while (ok) {
        char *v = NULL;
        gtk_tree_model_get(m, &it, 0, &v, -1);
        bool hit = v && strcmp(v, text) == 0;
        g_free(v);
        if (hit) { gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(t)), &it); return true; }
        ok = gtk_tree_model_iter_next(m, &it);
    }
    return false;
}

static void show_profiles(const char *when) {
    printf("    profiles %s:", when);
    for (GList *l = g_profiles; l; l = l->next) printf(" [%s]", ((Profile *)l->data)->name);
    printf("  active=%s\n", g_active_profile);
    fflush(stdout);
}

// ---- the profile file on disk ---------------------------------------------------------------------------------------------
static bool load_disk(const char *profile, struct pbp_profile *p) {
    char *file = pbp_filename_for(profile);
    char *path = g_strdup_printf("%s/profiles/%s", pbp_config_dir(), file);
    char err[200];
    bool ok = pbp_load_file(path, p, err, sizeof err) == 0;
    free(file);
    g_free(path);
    return ok;
}

static char *tmp_path(const char *name) { return g_strdup_printf("%s/%s", pbp_config_dir(), name); }

static void choose_file(GtkWidget *d, gpointer arg) {
    const char *path = arg;
    if (gtk_file_chooser_get_action(GTK_FILE_CHOOSER(d)) == GTK_FILE_CHOOSER_ACTION_SAVE) {
        char *dir = g_path_get_dirname(path), *base = g_path_get_basename(path);
        gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(d), dir);
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(d), base);
        g_free(dir); g_free(base);
    } else {
        gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(d), path);
    }
    pump(400);          // the chooser loads its folder asynchronously; answering at once can be vetoed by its response handler
}

// ================================================================================================================================
// Proxy Settings
// ================================================================================================================================
typedef struct { const char *name, *host, *port, *user, *pass; int type; bool dns; const char *error; } PxForm;

static void fill_px(GtkWidget *d, gpointer arg) {
    PxForm *f = arg;
    set_text(d, "px_name", f->name); set_text(d, "px_host", f->host); set_text(d, "px_port", f->port);
    set_text(d, "px_user", f->user); set_text(d, "px_pass", f->pass);
    set_combo(d, "px_type", f->type);
    set_check(d, "px_dns", f->dns);
}

static PxForm *px(const char *name, int type, const char *host, const char *port, const char *user, const char *pass, bool dns) {
    PxForm *f = g_malloc0(sizeof *f);
    f->name = name; f->type = type; f->host = host; f->port = port; f->user = user; f->pass = pass; f->dns = dns;
    return f;
}

static char *seen_error;
static void see_error_then_cancel(GtkWidget *d, gpointer arg) { (void)arg; g_free(seen_error); seen_error = get_text(d, "px_error"); }
// first pass: submit the bad form (the dialog stays open and shows why); the second pass is armed from here, after the answer
static void submit_bad_px(GtkWidget *d, gpointer arg) {
    fill_px(d, arg);
    arm("dlg_proxy", see_error_then_cancel, NULL, GTK_RESPONSE_CANCEL);
}

static ProxyData *proxy_named(const char *name) { return find_proxy_by_name(name); }

static void proxies_body(GtkWidget *dlg, gpointer arg) {
    (void)arg;
    STEP("proxy dialog open");
    CHECK(model_rows("proxy_tree") == 0);

    arm("dlg_proxy", fill_px, px("p1", 1, "127.0.0.1", "19080", "", "", false), GTK_RESPONSE_ACCEPT);
    click("px_add");
    ProxyData *p1 = proxy_named("p1");
    CHECK(p1 && p1->type == PROXY_TYPE_SOCKS5 && p1->port == 19080 && !p1->send_domain && p1->id != 0);
    CHECK_STR(g_default_proxy, "p1");
    CHECK(model_rows("proxy_tree") == 1);

    STEP("p1 added; validation cases");
    struct { PxForm *bad; const char *error; } cases[] = {
        { px("", 1, "h", "1", "", "", true), "Name cannot be empty." },
        { px("p1", 1, "h", "1", "", "", true), "A proxy with this name already exists." },
        { px("x", 1, "", "1", "", "", true), "Host (IP/Domain) cannot be empty." },
        { px("x", 1, "h", "0", "", "", true), "Port must be a number between 1 and 65535." },
        { px("x", 1, "h", "70000", "", "", true), "Port must be a number between 1 and 65535." },
        { px("x", 1, "h", "80x", "", "", true), "Port must be a number between 1 and 65535." },
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        g_free(seen_error); seen_error = NULL;
        arm("dlg_proxy", submit_bad_px, cases[i].bad, GTK_RESPONSE_ACCEPT);
        click("px_add");
        CHECK_STR(seen_error, cases[i].error);
        CHECK(g_list_length(g_proxies_list) == 1);
    }

    STEP("validation done; adding p2");
    arm("dlg_proxy", fill_px, px("p2", 0, "10.9.9.9", "8080", "bob", "pw", true), GTK_RESPONSE_ACCEPT);
    click("px_add");
    ProxyData *p2 = proxy_named("p2");
    CHECK(p2 && p2->type == PROXY_TYPE_HTTP && p2->send_domain && strcmp(p2->username, "bob") == 0 && strcmp(p2->password, "pw") == 0);
    CHECK(model_rows("proxy_tree") == 2);

    STEP("editing p1");
    // edit shows the stored values first; renaming keeps the default pointing at the proxy
    select_row("proxy_tree", 0);
    arm("dlg_proxy", fill_px, px("p1x", 1, "127.0.0.1", "19080", "", "", true), GTK_RESPONSE_ACCEPT);
    click("px_edit");
    CHECK(proxy_named("p1") == NULL && proxy_named("p1x") && proxy_named("p1x")->send_domain);
    CHECK_STR(g_default_proxy, "p1x");

    select_row("proxy_tree", 1);
    click("px_default");
    CHECK_STR(g_default_proxy, "p2");
    select_row("proxy_tree", 1);
    arm_msg(GTK_RESPONSE_NO);
    click("px_delete");
    CHECK_HAS(last_msg, "Delete proxy 'p2'");
    CHECK(proxy_named("p2") != NULL);                          // "No" keeps it
    arm_msg(GTK_RESPONSE_YES);
    click("px_delete");
    CHECK(proxy_named("p2") == NULL && g_list_length(g_proxies_list) == 1);
    CHECK_STR(g_default_proxy, "p1x");

    STEP("deleting / empty selection");
    unselect_all("proxy_tree");
    arm_msg(GTK_RESPONSE_OK); click("px_edit");    CHECK_HAS(last_msg, "Select a proxy first");
    arm_msg(GTK_RESPONSE_OK); click("px_delete");  CHECK_HAS(last_msg, "Select a proxy first");
    arm_msg(GTK_RESPONSE_OK); click("px_default"); CHECK_HAS(last_msg, "Select a proxy first");
    click("px_test");
    char *out = get_text(dlg, "px_test_output");
    CHECK_HAS(out, "Select a proxy to test");
    g_free(out);

    STEP("connection test");
    // the connection test runs on a worker thread and re-enables the button when it is done
    select_row("proxy_tree", 0);
    set_text(dlg, "px_test_host", "203.0.113.5");
    set_text(dlg, "px_test_port", "80");
    click("px_test");
    CHECK(!is_sensitive(dlg, "px_test"));
    for (int i = 0; i < 150 && !is_sensitive(dlg, "px_test"); i++) pump(100);
    CHECK(is_sensitive(dlg, "px_test"));
    out = get_text(dlg, "px_test_output");
    CHECK_HAS(out, "[1/5] Connecting to the proxy");           // the steps stream into the window
    CHECK_HAS(out, "Result: PASSED");
    g_free(out);

    gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE);
}

// ================================================================================================================================
// Rules
// ================================================================================================================================
typedef struct { const char *name, *proc, *hosts, *ports; int proto, action, proxy_idx; bool localhost; } RuleForm;

static RuleForm *rf(const char *name, const char *proc, const char *hosts, const char *ports, int proto, int action, int proxy_idx, bool lo) {
    RuleForm *f = g_malloc0(sizeof *f);
    f->name = name; f->proc = proc; f->hosts = hosts; f->ports = ports; f->proto = proto; f->action = action; f->proxy_idx = proxy_idx; f->localhost = lo;
    return f;
}

static void fill_rule(GtkWidget *d, gpointer arg) {
    RuleForm *f = arg;
    set_text(d, "rule_name", f->name); set_text(d, "rule_process", f->proc); set_text(d, "rule_hosts", f->hosts);
    set_text(d, "rule_ports", f->ports);
    set_combo(d, "rule_proto", f->proto); set_combo(d, "rule_proxy", f->proxy_idx);
    set_check(d, "rule_localhost", f->localhost);
    set_combo(d, "rule_action", f->action);                    // last: the localhost option follows the action
}

static char *rule_error;
static void see_rule_error(GtkWidget *d, gpointer arg) { (void)arg; g_free(rule_error); rule_error = get_text(d, "rule_error"); }
static void submit_bad_rule(GtkWidget *d, gpointer arg) {
    fill_rule(d, arg);
    arm("dlg_rule", see_rule_error, NULL, GTK_RESPONSE_CANCEL);
}

static RuleData *rule_at(int i) { return g_list_nth_data(g_rules_list, i); }

static void check_dialog_shows_web(GtkWidget *d, gpointer arg) {
    (void)arg;
    char *name = get_text(d, "rule_name"), *proc = get_text(d, "rule_process"), *ports = get_text(d, "rule_ports");
    CHECK_STR(name, "Web"); CHECK_STR(proc, "curl"); CHECK_STR(ports, "80;443");
    CHECK(get_check(d, "rule_localhost") && is_sensitive(d, "rule_localhost"));
    CHECK(get_combo(d, "rule_proto") == RULE_PROTOCOL_TCP && get_combo(d, "rule_action") == RULE_ACTION_PROXY && get_combo(d, "rule_proxy") == 1);
    g_free(name); g_free(proc); g_free(ports);
    set_text(d, "rule_name", "Web2");
    set_check(d, "rule_localhost", false);
}

static void check_localhost_follows_action(GtkWidget *d, gpointer arg) {
    RuleForm *f = arg;
    set_combo(d, "rule_action", RULE_ACTION_PROXY);
    CHECK(is_sensitive(d, "rule_localhost") && is_sensitive(d, "rule_proxy"));
    set_combo(d, "rule_action", RULE_ACTION_DIRECT);
    CHECK(!is_sensitive(d, "rule_localhost") && !is_sensitive(d, "rule_proxy"));
    set_combo(d, "rule_action", RULE_ACTION_BLOCK);
    CHECK(!is_sensitive(d, "rule_localhost"));
    fill_rule(d, f);
}

static void rules_scenario(void) {
    GtkWidget *win = find_named("win_rules");
    CHECK(win != NULL);
    STEP("rules window: add r1");

    arm("dlg_rule", fill_rule, rf("Web", "curl", "10.0.0.0/8;\nexample.com", "80;443", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 1, true), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    RuleData *r1 = rule_at(0);
    CHECK(g_list_length(g_rules_list) == 1 && r1 && r1->id != 0);
    CHECK(r1 && strcmp(r1->name, "Web") == 0 && strcmp(r1->process_name, "curl") == 0 && r1->localhost && r1->enabled);
    CHECK_STR(r1 ? r1->proxy_name : NULL, "p1x");
    CHECK_HAS(r1 ? r1->target_hosts : NULL, "example.com");
    CHECK(r1 && strchr(r1->target_hosts, '\n') == NULL);       // line breaks in the editor are only for reading

    STEP("rule validation");
    // a rule the engine rejects: the dialog stays open and shows the reason
    g_free(rule_error); rule_error = NULL;
    arm("dlg_rule", submit_bad_rule, rf("Bad", "curl", "bad host!", "80", RULE_PROTOCOL_TCP, RULE_ACTION_DIRECT, 0, false), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    CHECK(rule_error && strlen(rule_error) > 0);
    CHECK(g_list_length(g_rules_list) == 1);
    g_free(rule_error); rule_error = NULL;
    arm("dlg_rule", submit_bad_rule, rf("Bad", "curl", "*", "99999", RULE_PROTOCOL_TCP, RULE_ACTION_DIRECT, 0, false), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    CHECK(rule_error && strlen(rule_error) > 0 && g_list_length(g_rules_list) == 1);

    // "Also proxy localhost traffic" only exists for PROXY rules; a DIRECT rule never keeps it
    RuleForm *direct = rf("Local", "wget", "192.168.0.0/16", "*", RULE_PROTOCOL_UDP, RULE_ACTION_DIRECT, 0, true);
    arm("dlg_rule", check_localhost_follows_action, direct, GTK_RESPONSE_ACCEPT);
    click("rules_add");
    RuleData *r2 = rule_at(1);
    CHECK(r2 && r2->action == RULE_ACTION_DIRECT && r2->protocol == RULE_PROTOCOL_UDP && !r2->localhost);

    arm("dlg_rule", fill_rule, rf("", "*", "*", "53", RULE_PROTOCOL_UDP, RULE_ACTION_BLOCK, 0, false), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    RuleData *r3 = rule_at(2);
    CHECK(r3 && r3->action == RULE_ACTION_BLOCK && strcmp(r3->name, "") == 0);

    STEP("enable/disable and reorder");
    // enable/disable, reorder
    GtkWidget *en2 = find_named("rule_enable_2");
    CHECK(en2 != NULL);
    if (en2) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(en2), FALSE);
    CHECK(!r2->enabled);
    CHECK(!is_sensitive(win, "rule_up_1") && is_sensitive(win, "rule_up_3") && !is_sensitive(win, "rule_down_3"));
    click("rule_up_3");
    CHECK(rule_at(0) == r1 && rule_at(1) == r3 && rule_at(2) == r2);
    click("rule_down_2");
    CHECK(rule_at(1) == r2 && rule_at(2) == r3);

    // edit shows the stored values
    arm("dlg_rule", check_dialog_shows_web, NULL, GTK_RESPONSE_ACCEPT);
    click("rule_edit_1");
    CHECK_STR(r1->name, "Web2");
    CHECK(!r1->localhost && r1->id != 0);
    struct pbp_profile disk;
    CHECK(load_disk("Default", &disk));
    CHECK(disk.nrules == 3 && strcmp(disk.rules[0].name, "Web2") == 0 && !disk.rules[0].localhost && !disk.rules[1].enabled);
    CHECK(disk.rules[0].proxy_id != 0 && strcmp(disk.rules[0].hosts, "10.0.0.0/8;example.com") == 0);
    pbp_free(&disk);

    STEP("export / import");
    // export two rules, delete them, import them back
    char *file = tmp_path("rules_export.json");
    unlink(file);
    arm_msg(GTK_RESPONSE_OK);
    click("rules_export");                                      // nothing selected yet
    CHECK_HAS(last_msg, "select at least one rule");
    GtkWidget *s1 = find_named("rule_select_1"), *s3 = find_named("rule_select_3");
    CHECK(s1 && s3);
    if (s1) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s1), TRUE);
    s3 = find_named("rule_select_3");
    if (s3) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s3), TRUE);
    arm("chooser", choose_file, file, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    click("rules_export");
    CHECK_HAS(last_msg, "exported");
    char *json = NULL;
    CHECK(g_file_get_contents(file, &json, NULL, NULL));
    CHECK_HAS(json, "Web2"); CHECK_HAS(json, "\"localhostViaProxy\"");
    g_free(json);

    click("rules_delete_selected");
    CHECK(g_list_length(g_rules_list) == 1 && rule_at(0) == r2);
    arm("chooser", choose_file, file, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    click("rules_import");
    CHECK_HAS(last_msg, "Imported 2 rules");
    CHECK(g_list_length(g_rules_list) == 3);
    CHECK_STR(rule_at(1)->name, "Web2");

    char *bad = tmp_path("not_rules.json");
    g_file_set_contents(bad, "this is not json", -1, NULL);
    arm("chooser", choose_file, bad, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    click("rules_import");
    CHECK_HAS(last_msg, "No rules found");
    CHECK(g_list_length(g_rules_list) == 3);

    click("rule_delete_1");
    CHECK(g_list_length(g_rules_list) == 2);
    click("rules_select_all");
    click("rules_delete_selected");
    CHECK(g_rules_list == NULL);
    g_free(file); g_free(bad);

    STEP("rules done");
    // leave one rule behind for the profile scenario
    arm("dlg_rule", fill_rule, rf("Keep", "firefox", "*", "443", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 0, false), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    CHECK(g_list_length(g_rules_list) == 1);
    gtk_widget_destroy(win);
    pump(50);
    CHECK(find_named("win_rules") == NULL);
}

// ================================================================================================================================
// Profiles
// ================================================================================================================================
static void fill_name(GtkWidget *d, gpointer arg) { set_text(d, "profile_name_entry", arg); }
static void cancel_name_dialog(GtkWidget *d, gpointer arg) { (void)d; (void)arg; }

// submit a name the dialog refuses, read the message, then cancel (the cancel is armed after the message so it cannot answer early)
static const char *refused_name;
static void msg_then_arm_cancel(GtkWidget *d, gpointer arg) {
    remember_msg(d, arg);
    arm("dlg_profile_name", cancel_name_dialog, NULL, GTK_RESPONSE_CANCEL);
}
static void submit_refused(GtkWidget *d, gpointer arg) {
    (void)arg;
    set_text(d, "profile_name_entry", refused_name);
    arm("msg", msg_then_arm_cancel, NULL, GTK_RESPONSE_OK);
}

static void profiles_body(GtkWidget *dlg, gpointer arg) {
    (void)arg;
    STEP("profiles dialog open");
    CHECK(model_rows("profile_tree") == 1);

    arm("dlg_profile_name", fill_name, (gpointer)"Work", GTK_RESPONSE_ACCEPT);
    click("pf_new");
    CHECK(profile_find("Work") && model_rows("profile_tree") == 2);
    struct pbp_profile disk;
    CHECK(load_disk("Work", &disk) && disk.nrules == 0 && disk.nproxies == 0);
    pbp_free(&disk);

    refused_name = "";
    arm("dlg_profile_name", submit_refused, NULL, GTK_RESPONSE_ACCEPT);
    click("pf_new");
    CHECK_HAS(last_msg, "cannot be empty");
    refused_name = "Work";
    arm("dlg_profile_name", submit_refused, NULL, GTK_RESPONSE_ACCEPT);
    click("pf_new");
    CHECK_HAS(last_msg, "already exists");
    CHECK(model_rows("profile_tree") == 2);

    STEP("duplicate");
    // duplicate copies proxies, rules and switches
    CHECK(select_by_first_column("profile_tree", "Default"));
    arm("dlg_profile_name", fill_name, (gpointer)"Home", GTK_RESPONSE_ACCEPT);
    click("pf_duplicate");
    Profile *home = profile_find("Home");
    CHECK(home && g_list_length(home->proxies) == 1 && g_list_length(home->rules) == 1);

    // rename
    CHECK(select_by_first_column("profile_tree", "Home"));
    arm("dlg_profile_name", fill_name, (gpointer)"Office", GTK_RESPONSE_ACCEPT);
    click("pf_rename");
    CHECK(profile_find("Home") == NULL && profile_find("Office"));
    struct pbp_profile d2;
    CHECK(load_disk("Office", &d2));
    pbp_free(&d2);
    CHECK(!load_disk("Home", &d2));                              // the old file is gone

    STEP("switch");
    // switch: the window title, the engine's rules and the profile's own switches follow
    GtkWidget *log_item = menu_item("Enable Traffic Logging"), *dns_item = menu_item("DNS via Proxy");
    CHECK(log_item && dns_item);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(log_item), FALSE);        // Default: logging off
    CHECK(!g_chk_logging);
    CHECK(select_by_first_column("profile_tree", "Work"));
    click("pf_switch");
    CHECK_STR(g_active_profile, "Work");
    CHECK_HAS(gtk_window_get_title(GTK_WINDOW(window)), "ProxyBridge - Work");
    CHECK(g_chk_logging && gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(log_item)));   // Work has its own, default-on switches
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(dns_item), FALSE);                   // Work: DNS off
    CHECK(select_by_first_column("profile_tree", "Default"));
    click("pf_switch");
    CHECK_STR(g_active_profile, "Default");
    CHECK(!gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(log_item)) && gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(dns_item)));
    CHECK(load_disk("Work", &d2) && !d2.dns_via_proxy && d2.logging);
    pbp_free(&d2);

    STEP("profile export / import");
    // export and import through the file chooser
    char *file = tmp_path("exported.pbprofile");
    unlink(file);
    CHECK(select_by_first_column("profile_tree", "Office"));
    arm("chooser", choose_file, file, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    click("pf_export");
    CHECK_HAS(last_msg, "exported");
    struct stat st;
    CHECK(stat(file, &st) == 0 && (st.st_mode & 0777) == 0600);
    arm("chooser", choose_file, file, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    click("pf_import");
    CHECK_HAS(last_msg, "Imported as profile");
    CHECK(profile_find("Office (2)") != NULL);
    char *junk = tmp_path("junk.pbprofile");
    g_file_set_contents(junk, "{ nope", -1, NULL);
    arm("chooser", choose_file, junk, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    click("pf_import");
    CHECK_HAS(last_msg, "Import failed");
    g_free(file); g_free(junk);

    STEP("profile delete");
    // delete: asks first; the last profile stays
    CHECK(select_by_first_column("profile_tree", "Office (2)"));
    show_profiles("before deleting");
    arm_msg(GTK_RESPONSE_NO);
    click("pf_delete");
    CHECK(profile_find("Office (2)") != NULL);
    arm_msg(GTK_RESPONSE_YES);
    click("pf_delete");
    CHECK(profile_find("Office (2)") == NULL);
    CHECK(select_by_first_column("profile_tree", "Office"));
    arm_msg(GTK_RESPONSE_YES);
    click("pf_delete");
    show_profiles("after deleting Office");
    CHECK(select_by_first_column("profile_tree", "Work"));
    arm_msg(GTK_RESPONSE_YES);
    click("pf_delete");
    show_profiles("after deleting Work");
    CHECK(g_list_length(g_profiles) == 1);
    CHECK(select_by_first_column("profile_tree", "Default"));
    arm_msg(GTK_RESPONSE_OK);
    click("pf_delete");
    CHECK_HAS(last_msg, "last profile");
    CHECK(profile_find("Default") != NULL);
    gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE);
}

// ================================================================================================================================
static void ui_main(void) {
    pump(300);
    CHECK_HAS(gtk_window_get_title(GTK_WINDOW(window)), "ProxyBridge - Default");
    CHECK(menu_item("Proxy Settings...") && menu_item("Proxy Rules...") && menu_item("Profiles..."));

    printf("== proxy settings\n");
    arm("dlg_proxies", proxies_body, NULL, 0);
    activate("Proxy Settings...");
    struct pbp_profile disk;
    CHECK(load_disk("Default", &disk));
    CHECK(disk.nproxies == 1 && strcmp(disk.proxies[0].name, "p1x") == 0 && disk.proxies[0].send_domain);
    pbp_free(&disk);

    printf("== rules\n");
    activate("Proxy Rules...");
    pump(100);
    rules_scenario();

    printf("== profiles\n");
    arm("dlg_profiles", profiles_body, NULL, 0);
    activate("Profiles...");

    printf("== menus and engine\n");
    GtkWidget *start = menu_item("Start Engine"), *stop = menu_item("Stop Engine");
    CHECK(start && stop);
    for (int i = 0; i < 40 && !gtk_widget_get_sensitive(stop); i++) pump(100);
    CHECK(gtk_widget_get_sensitive(stop) && !gtk_widget_get_sensitive(start));
    activate("Stop Engine");
    for (int i = 0; i < 40 && !gtk_widget_get_sensitive(start); i++) pump(100);
    CHECK(gtk_widget_get_sensitive(start) && !gtk_widget_get_sensitive(stop));
    activate("Start Engine");
    for (int i = 0; i < 40 && !gtk_widget_get_sensitive(stop); i++) pump(100);
    CHECK(gtk_widget_get_sensitive(stop));
    arm("dlg_about", NULL, NULL, GTK_RESPONSE_OK);
    activate("About");
    pump(100);

    // what is on screen and in the files is what a restart would load
    config_free_all();
    load_config();
    CHECK_STR(g_active_profile, "Default");
    CHECK(g_list_length(g_profiles) == 1 && g_list_length(g_proxies_list) == 1 && g_list_length(g_rules_list) == 1);
    CHECK(strcmp(((RuleData *)g_rules_list->data)->name, "Keep") == 0);

    printf("ui_test: %d checks, %d failed\n", checks, fails);
}

static void watchdog(int sig) {
    (void)sig;
    printf("FAIL the UI test hung (watchdog)\n");
    fflush(stdout);
    _exit(2);
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    pb_gui_ready_hook = ui_main;
    signal(SIGALRM, watchdog);
    alarm(280);
    int rc = pb_gui_main(argc, argv);
    return rc ? rc : (fails ? 1 : 0);
}
