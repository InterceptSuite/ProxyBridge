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

// The single Action combo lists Direct, Block, then one entry per proxy.
static int action_idx(int action, int proxy_idx) {
    return action == RULE_ACTION_DIRECT ? 0 : action == RULE_ACTION_BLOCK ? 1 : 2 + (proxy_idx > 0 ? proxy_idx - 1 : 0);
}

static bool label_with_text(GtkWidget *w, const char *text) {
    if (GTK_IS_LABEL(w) && strcmp(gtk_label_get_text(GTK_LABEL(w)), text) == 0) return true;
    if (GTK_IS_CONTAINER(w)) {
        GList *kids = gtk_container_get_children(GTK_CONTAINER(w));
        bool found = false;
        for (GList *l = kids; l && !found; l = l->next) found = label_with_text(l->data, text);
        g_list_free(kids);
        return found;
    }
    return false;
}

static int combo_count(GtkWidget *d, const char *name) {
    GtkWidget *w = find_in(d, name);
    return w ? gtk_tree_model_iter_n_children(gtk_combo_box_get_model(GTK_COMBO_BOX(w)), NULL) : -1;
}

static char *combo_text_at(GtkWidget *d, const char *name, int idx) {
    GtkWidget *w = find_in(d, name);
    GtkTreeIter it;
    char *t = NULL;
    GtkTreeModel *m = w ? gtk_combo_box_get_model(GTK_COMBO_BOX(w)) : NULL;
    if (m && gtk_tree_model_iter_nth_child(m, &it, NULL, idx)) gtk_tree_model_get(m, &it, 0, &t, -1);
    return t;
}

static void fill_rule(GtkWidget *d, gpointer arg) {
    RuleForm *f = arg;
    set_text(d, "rule_name", f->name); set_text(d, "rule_process", f->proc); set_text(d, "rule_hosts", f->hosts);
    set_text(d, "rule_ports", f->ports);
    set_combo(d, "rule_proto", f->proto);
    set_check(d, "rule_localhost", f->localhost);
    set_combo(d, "rule_action", action_idx(f->action, f->proxy_idx));   // last: the localhost option follows the action
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
    CHECK(get_combo(d, "rule_proto") == RULE_PROTOCOL_TCP && get_combo(d, "rule_action") == 2);   // Direct, Block, Proxy: p1x
    g_free(name); g_free(proc); g_free(ports);
    set_text(d, "rule_name", "Web2");
    set_check(d, "rule_localhost", false);
}

static void check_localhost_follows_action(GtkWidget *d, gpointer arg) {
    RuleForm *f = arg;
    set_combo(d, "rule_action", action_idx(RULE_ACTION_PROXY, 1));
    CHECK(is_sensitive(d, "rule_localhost"));
    set_combo(d, "rule_action", 0);
    CHECK(!is_sensitive(d, "rule_localhost"));
    set_combo(d, "rule_action", 1);
    CHECK(!is_sensitive(d, "rule_localhost"));
    fill_rule(d, f);
}

// a new rule: Direct, Block and the proxy; the default proxy is preselected
static void check_new_rule_choices(GtkWidget *d, gpointer arg) {
    (void)arg;
    CHECK(combo_count(d, "rule_action") == 3);
    char *t0 = combo_text_at(d, "rule_action", 0), *t1 = combo_text_at(d, "rule_action", 1), *t2 = combo_text_at(d, "rule_action", 2);
    CHECK_STR(t0, "Direct"); CHECK_STR(t1, "Block"); CHECK_STR(t2, "Proxy: p1x");
    g_free(t0); g_free(t1); g_free(t2);
    CHECK(get_combo(d, "rule_action") == 2 && is_sensitive(d, "rule_localhost"));
    CHECK(find_in(d, "rule_proxy") == NULL);                                  // there is no second combo any more
}

// no proxy configured: only Direct and Block
static void check_no_proxy_choices(GtkWidget *d, gpointer arg) {
    (void)arg;
    CHECK(combo_count(d, "rule_action") == 2 && get_combo(d, "rule_action") == 0 && !is_sensitive(d, "rule_localhost"));
}

static void rules_scenario(void) {
    GtkWidget *win = find_named("win_rules");
    CHECK(win != NULL);
    STEP("rule action choices");
    arm("dlg_rule", check_new_rule_choices, NULL, GTK_RESPONSE_CANCEL);
    click("rules_add");
    {
        GList *saved = g_proxies_list;
        g_proxies_list = NULL;
        arm("dlg_rule", check_no_proxy_choices, NULL, GTK_RESPONSE_CANCEL);
        click("rules_add");
        g_proxies_list = saved;
    }
    STEP("rules window: add r1");

    arm("dlg_rule", fill_rule, rf("Web", "curl", "10.0.0.0/8;\nexample.com", "80;443", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 1, true), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    RuleData *r1 = rule_at(0);
    CHECK(g_list_length(g_rules_list) == 1 && r1 && r1->id != 0);
    CHECK(r1 && strcmp(r1->name, "Web") == 0 && strcmp(r1->process_name, "curl") == 0 && r1->localhost && r1->enabled);
    CHECK_STR(r1 ? r1->proxy_name : NULL, "p1x");
    CHECK(label_with_text(win, "Proxy: p1x (+localhost)"));        // the list says which proxy the rule uses, like the Windows app
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

// Profile > Switch Profile > <name>. The submenu is rebuilt in an idle callback after every change, hence the pumps.
static void switch_to_profile(const char *name) {
    pump(150);
    GtkWidget *sw = menu_item("Switch Profile");
    CHECK(sw != NULL);
    GtkWidget *sub = sw ? gtk_menu_item_get_submenu(GTK_MENU_ITEM(sw)) : NULL;
    GtkWidget *hit = NULL;
    GList *kids = sub ? gtk_container_get_children(GTK_CONTAINER(sub)) : NULL;
    for (GList *k = kids; k; k = k->next)
        if (strcmp(gtk_menu_item_get_label(GTK_MENU_ITEM(k->data)), name) == 0) hit = k->data;
    g_list_free(kids);
    CHECK(hit != NULL);
    if (hit) gtk_menu_item_activate(GTK_MENU_ITEM(hit));
    pump(150);
}

// the names in Profile > Switch Profile, in order, and which one is checked
static char *switch_menu_text(void) {
    pump(150);
    GtkWidget *sw = menu_item("Switch Profile");
    GtkWidget *sub = sw ? gtk_menu_item_get_submenu(GTK_MENU_ITEM(sw)) : NULL;
    GString *out = g_string_new("");
    GList *kids = sub ? gtk_container_get_children(GTK_CONTAINER(sub)) : NULL;
    for (GList *k = kids; k; k = k->next)
        g_string_append_printf(out, "%s%s;", gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(k->data)) ? "*" : "", gtk_menu_item_get_label(GTK_MENU_ITEM(k->data)));
    g_list_free(kids);
    return g_string_free(out, FALSE);
}

static void profiles_scenario(void) {
    STEP("profile menu");
    // like the Windows app: Profile is a menu of its own, and there is no list dialog any more
    CHECK(menu_item("New Profile...") && menu_item("Duplicate Profile...") && menu_item("Rename Profile...") && menu_item("Delete Profile...") &&
          menu_item("Import Profile...") && menu_item("Export Profile...") && menu_item("Switch Profile"));
    CHECK(menu_item("Profiles...") == NULL);
    char *shown = switch_menu_text();
    CHECK_STR(shown, "*Default;");
    g_free(shown);

    arm("dlg_profile_name", fill_name, (gpointer)"Work", GTK_RESPONSE_ACCEPT);
    activate("New Profile...");
    pump(150);
    CHECK(profile_find("Work") != NULL);
    CHECK_STR(g_active_profile, "Work");                      // a new profile becomes the active one at once
    CHECK_HAS(gtk_window_get_title(GTK_WINDOW(window)), "ProxyBridge - Work");
    struct pbp_profile disk;
    CHECK(load_disk("Work", &disk) && disk.nrules == 0 && disk.nproxies == 0);
    pbp_free(&disk);
    shown = switch_menu_text();
    CHECK_STR(shown, "Default;*Work;");                       // the check follows the active profile
    g_free(shown);

    refused_name = "";
    arm("dlg_profile_name", submit_refused, NULL, GTK_RESPONSE_ACCEPT);
    activate("New Profile...");
    CHECK_HAS(last_msg, "cannot be empty");
    refused_name = "Work";
    arm("dlg_profile_name", submit_refused, NULL, GTK_RESPONSE_ACCEPT);
    activate("New Profile...");
    CHECK_HAS(last_msg, "already exists");
    CHECK(g_list_length(g_profiles) == 2);

    STEP("switch");
    // switch: the window title, the engine's rules and the profile's own switches follow
    switch_to_profile("Default");
    CHECK_STR(g_active_profile, "Default");
    GtkWidget *log_item = menu_item("Enable Traffic Logging");
    CHECK(log_item && menu_item("DNS via Proxy") == NULL);     // DNS via proxy is a per-proxy option, not a menu switch
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(log_item), FALSE);        // Default: logging off
    CHECK(!g_chk_logging);
    switch_to_profile("Work");
    CHECK_STR(g_active_profile, "Work");
    CHECK_HAS(gtk_window_get_title(GTK_WINDOW(window)), "ProxyBridge - Work");
    CHECK(g_chk_logging && gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(log_item)));   // Work has its own, default-on switches
    g_chk_dns = false; save_config();                                                       // Work: DNS routing off (profile field)
    switch_to_profile("Default");
    CHECK_STR(g_active_profile, "Default");
    CHECK(!gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(log_item)) && g_chk_dns);
    struct pbp_profile d2;
    CHECK(load_disk("Work", &d2) && !d2.dns_via_proxy && d2.logging);
    pbp_free(&d2);
    switch_to_profile("Default");                              // choosing the active profile again changes nothing
    CHECK_STR(g_active_profile, "Default");

    STEP("duplicate");
    // duplicate copies proxies, rules and switches of the active profile, and the copy becomes the active one
    arm("dlg_profile_name", fill_name, (gpointer)"Home", GTK_RESPONSE_ACCEPT);
    activate("Duplicate Profile...");
    pump(150);
    Profile *home = profile_find("Home");
    CHECK(home && g_list_length(home->proxies) == 1 && g_list_length(home->rules) == 1);
    CHECK_STR(g_active_profile, "Home");

    // rename: the active profile
    arm("dlg_profile_name", fill_name, (gpointer)"Office", GTK_RESPONSE_ACCEPT);
    activate("Rename Profile...");
    pump(150);
    CHECK(profile_find("Home") == NULL && profile_find("Office"));
    CHECK_STR(g_active_profile, "Office");
    CHECK_HAS(gtk_window_get_title(GTK_WINDOW(window)), "ProxyBridge - Office");
    CHECK(load_disk("Office", &d2));
    pbp_free(&d2);
    CHECK(!load_disk("Home", &d2));                              // the old file is gone
    shown = switch_menu_text();
    CHECK_STR(shown, "Default;Work;*Office;");
    g_free(shown);

    STEP("profile export / import");
    // export the active profile and import it again: the import becomes the active profile
    char *file = tmp_path("exported.pbprofile");
    unlink(file);
    arm("chooser", choose_file, file, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    activate("Export Profile...");
    CHECK_HAS(last_msg, "exported");
    struct stat st;
    CHECK(stat(file, &st) == 0 && (st.st_mode & 0777) == 0600);
    arm("chooser", choose_file, file, GTK_RESPONSE_ACCEPT);
    activate("Import Profile...");
    pump(150);
    CHECK(profile_find("Office (2)") != NULL);
    CHECK_STR(g_active_profile, "Office (2)");
    char *junk = tmp_path("junk.pbprofile");
    g_file_set_contents(junk, "{ nope", -1, NULL);
    arm("chooser", choose_file, junk, GTK_RESPONSE_ACCEPT);
    arm_msg(GTK_RESPONSE_OK);
    activate("Import Profile...");
    CHECK_HAS(last_msg, "Import failed");
    CHECK_STR(g_active_profile, "Office (2)");
    g_free(file); g_free(junk);

    STEP("profile delete");
    // delete the active profile: asks first, another profile becomes active; the last profile stays
    arm_msg(GTK_RESPONSE_NO);
    activate("Delete Profile...");
    CHECK(profile_find("Office (2)") != NULL);
    arm_msg(GTK_RESPONSE_YES);
    activate("Delete Profile...");
    pump(150);
    CHECK(profile_find("Office (2)") == NULL);
    CHECK(g_active_profile && profile_find(g_active_profile) != NULL);          // an existing profile is active
    switch_to_profile("Office");
    arm_msg(GTK_RESPONSE_YES);
    activate("Delete Profile...");
    pump(150);
    switch_to_profile("Work");
    arm_msg(GTK_RESPONSE_YES);
    activate("Delete Profile...");
    pump(150);
    CHECK(g_list_length(g_profiles) == 1);
    CHECK_STR(g_active_profile, "Default");
    shown = switch_menu_text();
    CHECK_STR(shown, "*Default;");
    g_free(shown);
    arm_msg(GTK_RESPONSE_OK);
    activate("Delete Profile...");
    CHECK_HAS(last_msg, "last profile");
    CHECK(profile_find("Default") != NULL);
}


// ================================================================================================================================
// Update check (the feed is a local file; only the UI test build honours PB_UPDATE_FEED)
// ================================================================================================================================
static char *first_msg;
static void msg_then_ok(GtkWidget *d, gpointer arg) {
    remember_msg(d, arg);
    g_free(first_msg);
    first_msg = g_strdup(last_msg);
    arm_msg(GTK_RESPONSE_OK);
}

static void feed_case(const char *name, const char *content, int first_response, const char *want, bool second_ok) {
    char *path = tmp_path(name);
    char *url = g_strdup_printf("file://%s", path);
    if (content) g_file_set_contents(path, content, -1, NULL);
    setenv("PB_UPDATE_FEED", url, 1);
    g_free(last_msg); last_msg = NULL;
    if (second_ok) arm("msg", msg_then_ok, NULL, first_response);
    else arm_msg(first_response);
    activate("Check for Updates...");
    CHECK_HAS(second_ok ? first_msg : last_msg, want);
    g_free(path); g_free(url);
}

static GtkWidget *find_menubar(GtkWidget *w) {
    if (GTK_IS_MENU_BAR(w)) return w;
    if (!GTK_IS_CONTAINER(w)) return NULL;
    GList *kids = gtk_container_get_children(GTK_CONTAINER(w));
    GtkWidget *hit = NULL;
    for (GList *k = kids; k && !hit; k = k->next) hit = find_menubar(k->data);
    g_list_free(kids);
    return hit;
}

// labels of a menu's items joined with ";" (separators as "-"), or of the menu bar's menus
static char *menu_labels(GtkWidget *shell) {
    GString *out = g_string_new("");
    GList *kids = gtk_container_get_children(GTK_CONTAINER(shell));
    for (GList *k = kids; k; k = k->next) {
        if (GTK_IS_SEPARATOR_MENU_ITEM(k->data)) g_string_append(out, "-;");
        else g_string_append_printf(out, "%s;", gtk_menu_item_get_label(GTK_MENU_ITEM(k->data)));
    }
    g_list_free(kids);
    return g_string_free(out, FALSE);
}

static char *submenu_labels(const char *top) {
    GtkWidget *bar = find_menubar(window);
    char *res = NULL;
    GList *kids = bar ? gtk_container_get_children(GTK_CONTAINER(bar)) : NULL;
    for (GList *k = kids; k && !res; k = k->next)
        if (strcmp(gtk_menu_item_get_label(GTK_MENU_ITEM(k->data)), top) == 0)
            res = menu_labels(gtk_menu_item_get_submenu(GTK_MENU_ITEM(k->data)));
    g_list_free(kids);
    return res ? res : g_strdup("(missing)");
}

// the menu bar is laid out like the Windows app's: Proxy, Profile, Settings, Help
static void menus_scenario(void) {
    STEP("menu bar");
    GtkWidget *bar = find_menubar(window);
    CHECK(bar != NULL);
    char *top = bar ? menu_labels(bar) : g_strdup("");
    CHECK_STR(top, "Proxy;Profile;Settings;Help;");
    g_free(top);
    char *m = submenu_labels("Proxy");
    CHECK_STR(m, "Enable ProxyBridge;Start Engine;Stop Engine;-;Proxy Settings...;Proxy Rules...;Log Filters...;-;Exit;");
    g_free(m);
    m = submenu_labels("Profile");
    CHECK_STR(m, "New Profile...;Duplicate Profile...;Rename Profile...;Delete Profile...;-;Import Profile...;Export Profile...;-;Switch Profile;");
    g_free(m);
    m = submenu_labels("Settings");
    CHECK_STR(m, "Enable Traffic Logging;Start at Boot (systemd service);Auto-clear Logs;Log Every Connection;Check for Updates on Startup;-;Zoom In;Zoom Out;Reset Zoom;");
    g_free(m);
    m = submenu_labels("Help");
    CHECK_STR(m, "Documentation;Check for Updates...;-;About;");
    g_free(m);

    // Help > Documentation opens the same page as the Windows app (the test build records the address instead of starting a browser)
    char *log = tmp_path("opened_urls.txt");
    unlink(log);
    setenv("PB_OPEN_URL_LOG", log, 1);
    activate("Documentation");
    char *seen = NULL;
    CHECK(g_file_get_contents(log, &seen, NULL, NULL));
    CHECK_STR(seen, "https://proxybridge.interceptsuite.com/docs/\n");
    g_free(seen);
    g_free(log);
    unsetenv("PB_OPEN_URL_LOG");
}

static void updates_scenario(void) {
    STEP("update check");
    feed_case("feed_missing.json", NULL, GTK_RESPONSE_OK, "Update check failed", false);
    feed_case("feed_empty.json", "", GTK_RESPONSE_OK, "Update check failed", false);
    feed_case("feed_nolinux.json", "{\"windows\": {\"version\": \"9.0.0\"}}", GTK_RESPONSE_OK, "Could not parse linux update info", false);
    feed_case("feed_noversion.json", "{\"linux\": {\"download\": \"https://example.test/d\"}}", GTK_RESPONSE_OK, "Could not parse", false);
    feed_case("feed_escape.json", "{\"linux\": {\"version\": \"9.9.9\\u001b[31m\"}}", GTK_RESPONSE_OK, "Could not parse", false);   // remote text never reaches a dialog raw
    feed_case("feed_same.json", "{\"linux\": {\"version\": \"" PROXYBRIDGE_VERSION "\"}}", GTK_RESPONSE_OK, "latest version", false);
    feed_case("feed_beta_suffix.json", "{\"linux\": {\"version\": \"4.0.0\"}}", GTK_RESPONSE_OK, "latest version", false);
    feed_case("feed_older.json", "{\"linux\": {\"version\": \"3.2.0\"}}", GTK_RESPONSE_OK, "latest version", false);
    feed_case("feed_newer.json", "{\"linux\": {\"version\": \"9.9.9\", \"download\": \"https://example.test/d\", \"release_notes\": \"https://example.test/n\"}}",
              GTK_RESPONSE_CANCEL, "Version 9.9.9 is available", false);
    feed_case("feed_patch.json", "{\"linux\": {\"version\": \"4.0.1\", \"download\": \"https://example.test/d\"}}", GTK_RESPONSE_CANCEL, "Version 4.0.1 is available", false);
    // a feed must never make the program open anything but an https page
    feed_case("feed_unsafe.json", "{\"linux\": {\"version\": \"9.9.9\", \"download\": \"http://insecure.test/x\", \"release_notes\": \"javascript:alert(1)\"}}",
              GTK_RESPONSE_ACCEPT, "Version 9.9.9 is available", true);
    CHECK_HAS(last_msg, "No safe https url");
    // a feed that points at the project's release page: "Open in Browser" opens exactly that page
    {
        char *log = tmp_path("opened_release.txt");
        unlink(log);
        setenv("PB_OPEN_URL_LOG", log, 1);
        feed_case("feed_project.json", "{\"linux\": {\"version\": \"9.9.9\", \"download\": \"https://github.com/InterceptSuite/ProxyBridge/releases/download/v9.9.9/x.tar.gz\", \"release_notes\": \"https://github.com/InterceptSuite/ProxyBridge/releases/tag/v9.9.9\"}}",
                  GTK_RESPONSE_ACCEPT, "Version 9.9.9 is available", false);
        pump(100);
        char *seen = NULL;
        CHECK(g_file_get_contents(log, &seen, NULL, NULL));
        CHECK_STR(seen, "https://github.com/InterceptSuite/ProxyBridge/releases/tag/v9.9.9\n");
        g_free(seen);
        g_free(log);
        unsetenv("PB_OPEN_URL_LOG");
    }
    // ...and, since the browser runs as root, only the project's own pages: a feed pointing elsewhere is not opened
    feed_case("feed_foreign.json", "{\"linux\": {\"version\": \"9.9.9\", \"download\": \"https://evil.example/x\", \"release_notes\": \"https://evil.example/n\"}}",
              GTK_RESPONSE_ACCEPT, "Version 9.9.9 is available", true);
    CHECK_HAS(last_msg, "No safe https url");
    unsetenv("PB_UPDATE_FEED");
}

// ================================================================================================================================
// Connection and activity logs
// ================================================================================================================================
static char *buffer_of(const char *view_name) {
    GtkWidget *v = find_named(view_name);
    if (!v) return g_strdup("");
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(v));
    GtkTextIter s, e;
    gtk_text_buffer_get_bounds(b, &s, &e);
    return gtk_text_buffer_get_text(b, &s, &e, FALSE);
}

static int visible_lines_with(const char *view_name, const char *needle) {
    GtkWidget *v = find_named(view_name);
    if (!v) return -1;
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(v));
    GtkTextTag *hidden = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(b), "hidden");
    int n = 0;
    for (int line = 0; line < gtk_text_buffer_get_line_count(b); line++) {
        GtkTextIter s, e;
        gtk_text_buffer_get_iter_at_line(b, &s, line);
        e = s;
        if (!gtk_text_iter_ends_line(&e)) gtk_text_iter_forward_to_line_end(&e);
        char *text = gtk_text_buffer_get_text(b, &s, &e, FALSE);
        if (strstr(text, needle) && !gtk_text_iter_has_tag(&s, hidden)) n++;
        g_free(text);
    }
    return n;
}

static void connect_once(const char *ip) {
    char *script = tmp_path("conn.py");
    g_file_set_contents(script, "import socket, sys\ns = socket.socket(); s.settimeout(3)\n"
                                "try:\n    s.connect((sys.argv[1], 80)); s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); s.recv(100)\nexcept OSError:\n    pass\n", -1, NULL);
    char *argv[] = { (char *)"python3", script, (char *)ip, NULL };
    g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    g_free(script);
}

static void logs_scenario(void) {
    STEP("connection and activity logs");
    GtkWidget *log_item = menu_item("Enable Traffic Logging");
    if (log_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(log_item), TRUE);     // the profile scenario left it off for Default
    ProxyData *p = proxy_named("p1x");
    CHECK(p != NULL);
    char err[200] = "";
    uint32_t rule = p ? ProxyBridge_AddRule("python3*", "192.0.2.40-192.0.2.49", "80", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, p->id, err, sizeof err) : 0;
    CHECK(rule != 0);

    connect_once("192.0.2.40");
    connect_once("192.0.2.41");
    pump(900);
    char *conns = buffer_of("conn_view");
    CHECK_HAS(conns, "192.0.2.40:80");
    CHECK_HAS(conns, "192.0.2.41:80");
    CHECK_HAS(conns, "via SOCKS5 127.0.0.1:19080");
    g_free(conns);
    char *logs = buffer_of("log_view");
    CHECK_HAS(logs, "ProxyBridge started");
    g_free(logs);

    // search hides the lines that do not match, and shows them again
    set_text(find_named("conn_search"), "conn_search", "192.0.2.41");
    pump(500);
    CHECK(visible_lines_with("conn_view", "192.0.2.41") == 1 && visible_lines_with("conn_view", "192.0.2.40") == 0);
    set_text(find_named("conn_search"), "conn_search", "");
    pump(500);
    CHECK(visible_lines_with("conn_view", "192.0.2.40") == 1 && visible_lines_with("conn_view", "192.0.2.41") == 1);
    set_text(find_named("log_search"), "log_search", "started");
    pump(500);
    CHECK(visible_lines_with("log_view", "ProxyBridge started") >= 1);
    set_text(find_named("log_search"), "log_search", "");
    pump(300);

    // pause keeps new lines back until it is released
    GtkWidget *pause = find_named("conn_pause");
    CHECK(pause != NULL);
    if (pause) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(pause), TRUE);
    connect_once("192.0.2.42");
    pump(900);
    conns = buffer_of("conn_view");
    CHECK(strstr(conns, "192.0.2.42") == NULL);
    g_free(conns);
    if (pause) gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(pause), FALSE);
    pump(600);
    conns = buffer_of("conn_view");
    CHECK_HAS(conns, "192.0.2.42:80");
    g_free(conns);

    // the live connections tab is a view of the engine too
    gui_refresh_flows();
    GtkWidget *flows = find_named("flows_tree");
    CHECK(flows != NULL);

    click("conn_clear");
    conns = buffer_of("conn_view");
    CHECK(strlen(conns) == 0);
    g_free(conns);
    click("log_clear");
    logs = buffer_of("log_view");
    CHECK(strlen(logs) == 0);
    g_free(logs);
    ProxyBridge_DeleteRule(rule);
}


// ================================================================================================================================
// Font zoom, auto-clear, log filters, start at boot, update check on start-up
// ================================================================================================================================
static int buffer_lines(const char *view_name)
{
    GtkWidget *v = find_named(view_name);
    return v ? gtk_text_buffer_get_line_count(gtk_text_view_get_buffer(GTK_TEXT_VIEW(v))) - 1 : -1;
}

static void fire_logs(int n)
{
    for (int i = 0; i < n; i++) gui_log("filler line %d", i);
    pump(900);
}

static void zoom_scenario(void)
{
    STEP("font zoom");
    struct pbp_profile disk;
    CHECK(g_zoom == 100);
    activate("Zoom In"); activate("Zoom In");
    CHECK(g_zoom == 120 && strstr(gui_zoom_css(), "120%") != NULL);
    CHECK(load_disk("Default", &disk) && disk.font_zoom == 120);
    pbp_free(&disk);
    activate("Zoom Out");
    CHECK(g_zoom == 110 && strstr(gui_zoom_css(), "110%") != NULL);
    activate("Reset Zoom");
    CHECK(g_zoom == 100 && strstr(gui_zoom_css(), "100%") != NULL);

    gui_set_zoom(1000); CHECK(g_zoom == 300);
    activate("Zoom In"); CHECK(g_zoom == 300);                 // clamped at both ends
    gui_set_zoom(5); CHECK(g_zoom == 60);
    activate("Zoom Out"); CHECK(g_zoom == 60);
    gui_set_zoom(-40); CHECK(g_zoom == 60);

    // the zoom belongs to the profile
    gui_set_zoom(130);
    CHECK(profile_create("Zoomed", false) != NULL);
    CHECK(profile_activate("Zoomed"));
    gui_refresh_profile_menu();                                  // (the menu items do this themselves; here the engine calls are used directly)
    gui_sync_switches();
    CHECK(g_zoom == 100 && strstr(gui_zoom_css(), "100%") != NULL);
    gui_set_zoom(180);
    CHECK(profile_activate("Default"));
    gui_sync_switches();
    CHECK(g_zoom == 130 && strstr(gui_zoom_css(), "130%") != NULL);
    CHECK(profile_activate("Zoomed"));
    gui_sync_switches();
    CHECK(g_zoom == 180);
    CHECK(profile_activate("Default"));
    gui_sync_switches();
    gui_set_zoom(100);
    save_config();
}

static void autoclear_scenario(void)
{
    STEP("auto-clear logs");
    GtkWidget *item = menu_item("Auto-clear Logs");
    CHECK(item && gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(item)) && g_chk_auto_clear);
    click("log_clear");
    fire_logs(600);                                           // past 500 lines the log is wiped
    int n = buffer_lines("log_view");
    CHECK(n >= 0 && n < 500);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), FALSE);
    CHECK(!g_chk_auto_clear);
    struct pbp_profile disk;
    CHECK(load_disk("Default", &disk) && !disk.auto_clear);
    pbp_free(&disk);
    click("log_clear");
    fire_logs(700);                                           // switched off: the log keeps its history
    n = buffer_lines("log_view");
    CHECK(n >= 700);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), TRUE);
    CHECK(g_chk_auto_clear && load_disk("Default", &disk) && disk.auto_clear);
    pbp_free(&disk);
    click("log_clear");
}

typedef struct { const char *mode, *proc, *ip, *port, *proto, *action; } FltForm;

static void fill_flt(GtkWidget *d, gpointer arg)
{
    FltForm *f = arg;
    set_combo(d, "flt_mode", !strcmp(f->mode, "Exclude") ? 1 : 0);
    set_text(d, "flt_process", f->proc); set_text(d, "flt_ip", f->ip); set_text(d, "flt_port", f->port);
    set_combo(d, "flt_proto", !strcmp(f->proto, "TCP") ? 1 : !strcmp(f->proto, "UDP") ? 2 : 0);
    set_combo(d, "flt_action", !strcmp(f->action, "Direct") ? 1 : !strcmp(f->action, "Proxy") ? 2 : !strcmp(f->action, "Blocked") ? 3 : 0);
}

static FltForm *ff(const char *mode, const char *proc, const char *ip, const char *port, const char *proto, const char *action)
{
    FltForm *f = g_malloc0(sizeof *f);
    f->mode = mode; f->proc = proc; f->ip = ip; f->port = port; f->proto = proto; f->action = action;
    return f;
}

static char *flt_error;
static void see_flt_error(GtkWidget *d, gpointer arg) { (void)arg; g_free(flt_error); flt_error = get_text(d, "flt_error"); }
static void submit_bad_flt(GtkWidget *d, gpointer arg)
{
    fill_flt(d, arg);
    arm("dlg_filter", see_flt_error, NULL, GTK_RESPONSE_CANCEL);
}

static void filters_add_exclude(GtkWidget *dlg, gpointer arg)
{
    (void)arg;
    CHECK(model_rows("filter_tree") == 0);
    arm("dlg_filter", fill_flt, ff("Exclude", "python3*", "", "", "All", "All"), GTK_RESPONSE_ACCEPT);
    click("flt_add");
    CHECK(model_rows("filter_tree") == 1);
    size_t n = 0;
    struct pbp_filter *fl = gui_filters(&n);
    CHECK(n == 1 && fl[0].exclude && !strcmp(fl[0].process, "python3*") && !strcmp(fl[0].protocol, "All"));
    gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE);
}

static void filters_manage(GtkWidget *dlg, gpointer arg)
{
    (void)arg;
    size_t n = 0;
    CHECK(model_rows("filter_tree") == 1);                    // the filter added earlier is listed

    g_free(flt_error); flt_error = NULL;
    arm("dlg_filter", submit_bad_flt, ff("Include", "x", "", "80x", "All", "All"), GTK_RESPONSE_ACCEPT);
    click("flt_add");
    CHECK_HAS(flt_error, "Port must be digits");
    CHECK(model_rows("filter_tree") == 1);

    arm("dlg_filter", fill_flt, ff("Include", "ignored", "", "", "All", "All"), GTK_RESPONSE_CANCEL);       // cancel changes nothing
    click("flt_add");
    CHECK(model_rows("filter_tree") == 1);

    unselect_all("filter_tree");
    arm_msg(GTK_RESPONSE_OK); click("flt_edit");   CHECK_HAS(last_msg, "Select a filter first");
    arm_msg(GTK_RESPONSE_OK); click("flt_delete"); CHECK_HAS(last_msg, "Select a filter first");

    select_row("filter_tree", 0);
    arm("dlg_filter", fill_flt, ff("Include", "curl", "192.0.2.4*", "80", "TCP", "Proxy"), GTK_RESPONSE_ACCEPT);
    click("flt_edit");
    struct pbp_filter *fl = gui_filters(&n);
    CHECK(n == 1 && !fl[0].exclude && !strcmp(fl[0].process, "curl") && !strcmp(fl[0].ip, "192.0.2.4*") && !strcmp(fl[0].port, "80") &&
          !strcmp(fl[0].protocol, "TCP") && !strcmp(fl[0].action, "Proxy"));
    struct pbp_profile disk;
    CHECK(load_disk("Default", &disk) && disk.nfilters == 1 && !disk.filters[0].exclude && !strcmp(disk.filters[0].ip, "192.0.2.4*"));
    pbp_free(&disk);

    arm("dlg_filter", fill_flt, ff("Exclude", "*", "", "53", "UDP", "Blocked"), GTK_RESPONSE_ACCEPT);
    click("flt_add");
    CHECK(model_rows("filter_tree") == 2);
    select_row("filter_tree", 0);
    click("flt_delete");
    fl = gui_filters(&n);
    CHECK(n == 1 && fl[0].exclude && !strcmp(fl[0].port, "53"));
    select_row("filter_tree", 0);
    click("flt_delete");
    gui_filters(&n);
    CHECK(n == 0 && model_rows("filter_tree") == 0);
    CHECK(load_disk("Default", &disk) && disk.nfilters == 0);
    pbp_free(&disk);
    gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE);
}

static void filters_delete_all(GtkWidget *dlg, gpointer arg)
{
    (void)arg;
    while (model_rows("filter_tree") > 0) { select_row("filter_tree", 0); click("flt_delete"); }
    gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE);
}

static void filters_scenario(void)
{
    STEP("log filters");
    ProxyData *p = proxy_named("p1x");
    char err[200];
    uint32_t rule = p ? ProxyBridge_AddRule("python3*", "192.0.2.40-192.0.2.60", "80", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, p->id, err, sizeof err) : 0;
    CHECK(rule != 0);
    GtkWidget *log_item = menu_item("Enable Traffic Logging");
    if (log_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(log_item), TRUE);
    click("conn_clear");

    // an Exclude filter hides new connections of that process
    arm("dlg_filters", filters_add_exclude, NULL, 0);
    activate("Log Filters...");
    connect_once("192.0.2.43");
    pump(900);
    char *conns = buffer_of("conn_view");
    CHECK(strstr(conns, "192.0.2.43") == NULL);
    g_free(conns);

    // the dialog edits, validates and deletes
    arm("dlg_filters", filters_manage, NULL, 0);
    activate("Log Filters...");

    // Include filters show only what matches
    arm("dlg_filters", filters_delete_all, NULL, 0);
    activate("Log Filters...");
    connect_once("192.0.2.44");
    pump(900);
    conns = buffer_of("conn_view");
    CHECK_HAS(conns, "192.0.2.44:80");                          // with the filter gone the connection shows again
    g_free(conns);
    click("conn_clear");

    size_t n = 0;
    struct pbp_filter inc = { false, strdup(""), strdup("192.0.2.45"), strdup(""), strdup("All"), strdup("All") };
    struct pbp_filter *fl = calloc(1, sizeof *fl);
    fl[0] = pbp_filter_dup(&inc);
    pbp_filter_clear(&inc);
    gui_filters_replace(fl, 1);
    connect_once("192.0.2.45");
    connect_once("192.0.2.46");
    pump(900);
    conns = buffer_of("conn_view");
    CHECK(strstr(conns, "192.0.2.45:80") != NULL && strstr(conns, "192.0.2.46") == NULL);
    g_free(conns);
    gui_filters_replace(NULL, 0);
    gui_filters(&n);
    CHECK(n == 0);

    // the filters follow the profile
    fl = calloc(1, sizeof *fl);
    struct pbp_filter ex = { true, strdup("python3*"), strdup(""), strdup(""), strdup("All"), strdup("All") };
    fl[0] = pbp_filter_dup(&ex);
    pbp_filter_clear(&ex);
    gui_filters_replace(fl, 1);
    CHECK(profile_activate("Zoomed"));
    gui_filters(&n);
    CHECK(n == 0);
    CHECK(profile_activate("Default"));
    gui_filters(&n);
    CHECK(n == 1);
    gui_filters_replace(NULL, 0);
    save_config();
    ProxyBridge_DeleteRule(rule);
    click("conn_clear");
}

static void make_fake_systemctl(const char *path, const char *log)
{
    char *script = g_strdup_printf("#!/bin/sh\necho \"$@\" >> %s\n[ \"$FAKE_FAIL\" = \"$1\" ] && { echo \"boom: $1\" >&2; exit 1; }\nexit 0\n", log);
    g_file_set_contents(path, script, -1, NULL);
    chmod(path, 0755);
    g_free(script);
}

// With the service, Start at Boot is a setting the service keeps in settings.json: it applies the active profile when it starts and
// keeps routing after the window closes. The unit itself is installed (and enabled) by the installer.
static bool settings_boot_flag(void)
{
    char *p = g_build_filename(getenv("PROXYBRIDGE_CONFIG_DIR"), "settings.json", NULL), *text = NULL;
    bool on = g_file_get_contents(p, &text, NULL, NULL) && strstr(text, "\"StartAtBoot\": true");
    g_free(text); g_free(p);
    return on;
}

static void boot_service_scenario(void)
{
    STEP("start at boot (through the service)");
    GtkWidget *item = menu_item("Start at Boot (systemd service)");
    CHECK(item != NULL && !gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(item)) && !settings_boot_flag());
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), TRUE);
    CHECK(g_chk_boot && settings_boot_flag());
    CHECK_STR(g_active_profile, g_active_profile);            // the active profile is kept in the same file
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), FALSE);
    CHECK(!g_chk_boot && !settings_boot_flag());
    switch_to_profile("Zoomed");
    switch_to_profile("Default");
    CHECK(!settings_boot_flag());                              // switching profiles does not touch it
}

static void boot_scenario(void)
{
    if (pbc_is_service()) { boot_service_scenario(); return; }
    STEP("start at boot");
    char *units = tmp_path("units"), *fake = tmp_path("systemctl"), *calls = tmp_path("systemctl.log");
    g_mkdir_with_parents(units, 0755);
    make_fake_systemctl(fake, calls);
    setenv("PROXYBRIDGE_SYSTEMD_DIR", units, 1);
    setenv("PROXYBRIDGE_SYSTEMCTL", fake, 1);
    setenv("PROXYBRIDGE_CLI", "/usr/local/bin/ProxyBridge", 1);
    char *unit = g_build_filename(units, "proxybridge.service", NULL);

    GtkWidget *item = menu_item("Start at Boot (systemd service)");
    CHECK(item != NULL && !gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(item)));
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), TRUE);
    char *text = NULL;
    CHECK(g_file_get_contents(unit, &text, NULL, NULL));
    // the unit runs the service; which profile it starts is the one the window saved as active (settings.json), so the unit itself
    // never changes when profiles are switched
    CHECK_HAS(text, "ExecStart=\"/usr/local/bin/ProxyBridge\" --daemon\n");
    CHECK(!strstr(text, "--profile") && strstr(text, "LimitNOFILE=1048576") && strstr(text, "NoNewPrivileges=yes") && strstr(text, "RuntimeDirectory=proxybridge"));
    g_free(text);
    char *log = NULL;
    g_file_get_contents(calls, &log, NULL, NULL);
    CHECK_HAS(log, "enable proxybridge.service");
    g_free(log);

    char *before = NULL, *after = NULL;
    CHECK(g_file_get_contents(unit, &before, NULL, NULL));
    switch_to_profile("Zoomed");
    CHECK_STR(g_active_profile, "Zoomed");
    switch_to_profile("Default");
    CHECK(g_file_get_contents(unit, &after, NULL, NULL) && strcmp(before, after) == 0);
    g_free(before); g_free(after);

    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), FALSE);
    CHECK(!g_file_test(unit, G_FILE_TEST_EXISTS));

    // a failing systemctl: say so and leave the box unchecked
    setenv("FAKE_FAIL", "enable", 1);
    arm_msg(GTK_RESPONSE_OK);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), TRUE);
    CHECK_HAS(last_msg, "Could not enable starting at boot");
    CHECK(!gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(item)) && !g_file_test(unit, G_FILE_TEST_EXISTS));
    unsetenv("FAKE_FAIL");
    unsetenv("PROXYBRIDGE_SYSTEMD_DIR"); unsetenv("PROXYBRIDGE_SYSTEMCTL"); unsetenv("PROXYBRIDGE_CLI");
    g_free(units); g_free(fake); g_free(calls); g_free(unit);
}

static bool any_message_dialog(void) { return visible_dialog("msg") != NULL; }

static void startup_update_scenario(void)
{
    STEP("update check on start-up");
    GtkWidget *item = menu_item("Check for Updates on Startup");
    CHECK(item && gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(item)) && g_chk_updates);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), FALSE);
    CHECK(!g_chk_updates);
    char *settings = tmp_path("settings.json"), *text = NULL;
    CHECK(g_file_get_contents(settings, &text, NULL, NULL));
    CHECK_HAS(text, "\"CheckForUpdatesOnStartup\": false");
    g_free(text);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), TRUE);
    CHECK(g_chk_updates && g_file_get_contents(settings, &text, NULL, NULL));
    CHECK_HAS(text, "\"CheckForUpdatesOnStartup\": true");
    g_free(text); g_free(settings);

    // a start-up check says nothing unless there is a newer version
    const char *quiet[][2] = {
        { "su_same.json", "{\"linux\": {\"version\": \"" PROXYBRIDGE_VERSION "\"}}" },
        { "su_older.json", "{\"linux\": {\"version\": \"1.0.0\"}}" },
        { "su_broken.json", "not json at all" },
        { "su_nolinux.json", "{\"windows\": {}}" },
    };
    for (size_t i = 0; i < sizeof quiet / sizeof *quiet; i++) {
        char *path = tmp_path(quiet[i][0]);
        g_file_set_contents(path, quiet[i][1], -1, NULL);
        char *url = g_strdup_printf("file://%s", path);
        setenv("PB_UPDATE_FEED", url, 1);
        gui_check_updates_on_startup();
        pump(1500);
        CHECK(!any_message_dialog());
        g_free(path); g_free(url);
    }
    setenv("PB_UPDATE_FEED", "file:///nonexistent/feed.json", 1);
    gui_check_updates_on_startup();
    pump(1500);
    CHECK(!any_message_dialog());

    // news: the user is asked, and can turn the start-up check off for good
    char *path = tmp_path("su_newer.json");
    g_file_set_contents(path, "{\"linux\": {\"version\": \"9.9.9\", \"download\": \"https://example.test/d\", \"release_notes\": \"https://example.test/n\"}}", -1, NULL);
    char *url = g_strdup_printf("file://%s", path);
    setenv("PB_UPDATE_FEED", url, 1);
    g_free(last_msg); last_msg = NULL;
    arm_msg(GTK_RESPONSE_CANCEL);
    gui_check_updates_on_startup();
    for (int i = 0; i < 60 && !last_msg; i++) pump(100);
    CHECK_HAS(last_msg, "Version 9.9.9 is available");
    CHECK(g_chk_updates);                                      // Close leaves the setting alone
    g_free(last_msg); last_msg = NULL;
    arm_msg(GTK_RESPONSE_REJECT);                              // "Don't Check at Startup"
    gui_check_updates_on_startup();
    for (int i = 0; i < 60 && !last_msg; i++) pump(100);
    CHECK_HAS(last_msg, "Version 9.9.9 is available");
    pump(300);
    CHECK(!g_chk_updates);
    GtkWidget *it2 = menu_item("Check for Updates on Startup");
    CHECK(it2 && !gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(it2)));
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(it2), TRUE);
    g_free(path); g_free(url);
    unsetenv("PB_UPDATE_FEED");
}

// ================================================================================================================================
// Documentation screenshots: only with PB_SCREENSHOT_DIR set (tests/gui_shots.sh). A demo profile is built through the real
// dialogs and every window is rendered to a PNG, so the pictures in the documentation are the program's own.
// ================================================================================================================================
static const char *shot_dir;

// renders a widget to <dir>/<name>.png; a window gets a plain title bar (Broadway has no window manager to draw one)
static void snap_titled(GtkWidget *w, const char *name, const char *title) {
    if (!shot_dir || !w) return;
    pump(400);
    int width = gtk_widget_get_allocated_width(w), height = gtk_widget_get_allocated_height(w);
    int bar = title ? 34 : 0;
    cairo_surface_t *surf = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height + bar);
    cairo_t *cr = cairo_create(surf);
    if (title) {
        cairo_set_source_rgb(cr, 0.90, 0.89, 0.88);
        cairo_rectangle(cr, 0, 0, width, bar);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.80, 0.79, 0.78);
        cairo_rectangle(cr, 0, bar - 1, width, 1);
        cairo_fill(cr);
        cairo_set_source_rgb(cr, 0.15, 0.15, 0.15);
        cairo_select_font_face(cr, "sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 14);
        cairo_text_extents_t te;
        cairo_text_extents(cr, title, &te);
        cairo_move_to(cr, (width - te.width) / 2, 22);
        cairo_show_text(cr, title);
        cairo_translate(cr, 0, bar);
    }
    gtk_widget_draw(w, cr);
    char *path = g_strdup_printf("%s/%s.png", shot_dir, name);
    cairo_status_t st = cairo_surface_write_to_png(surf, path);
    printf("  screenshot %s (%dx%d)%s\n", path, width, height + bar, st == CAIRO_STATUS_SUCCESS ? "" : "  FAILED");
    g_free(path);
    cairo_destroy(cr);
    cairo_surface_destroy(surf);
}

// Broadway draws the window decorations itself, so a window is captured as it is
static void snap(GtkWidget *w, const char *name) {
    snap_titled(w, name, NULL);
}

static GtkWidget *find_notebook(GtkWidget *w) {
    if (GTK_IS_NOTEBOOK(w)) return w;
    if (!GTK_IS_CONTAINER(w)) return NULL;
    GList *kids = gtk_container_get_children(GTK_CONTAINER(w));
    GtkWidget *hit = NULL;
    for (GList *k = kids; k && !hit; k = k->next) hit = find_notebook(k->data);
    g_list_free(kids);
    return hit;
}

typedef struct { void *form; const char *shot; } ShotForm;
static void fill_px_shot(GtkWidget *d, gpointer arg) { ShotForm *s = arg; fill_px(d, s->form); if (s->shot) snap(d, s->shot); }
static void fill_rule_shot(GtkWidget *d, gpointer arg) { ShotForm *s = arg; fill_rule(d, s->form); if (s->shot) snap(d, s->shot); }
static void fill_flt_shot(GtkWidget *d, gpointer arg) { ShotForm *s = arg; fill_flt(d, s->form); if (s->shot) snap(d, s->shot); }
static ShotForm *shot_form(void *form, const char *shot) { ShotForm *s = g_malloc0(sizeof *s); s->form = form; s->shot = shot; return s; }

static void shots_proxies_body(GtkWidget *dlg, gpointer arg) {
    (void)arg;
    arm("dlg_proxy", fill_px_shot, shot_form(px("Corporate SOCKS5", 1, "proxy.corp.example.com", "1080", "alice", "s3cret", true), "proxy-editor"), GTK_RESPONSE_ACCEPT);
    click("px_add");
    arm("dlg_proxy", fill_px_shot, shot_form(px("Burp Suite", 0, "127.0.0.1", "8080", "", "", true), NULL), GTK_RESPONSE_ACCEPT);
    click("px_add");
    arm("dlg_proxy", fill_px_shot, shot_form(px("Tor", 1, "127.0.0.1", "9050", "", "", true), NULL), GTK_RESPONSE_ACCEPT);
    click("px_add");
    arm("dlg_proxy", fill_px_shot, shot_form(px("Local SOCKS5", 1, "127.0.0.1", "19080", "", "", true), NULL), GTK_RESPONSE_ACCEPT);
    click("px_add");
    select_row("proxy_tree", 3);                                 // Local SOCKS5 answers the test
    set_text(dlg, "px_test_host", "example.com");
    set_text(dlg, "px_test_port", "80");
    click("px_test");
    for (int i = 0; i < 80; i++) {
        char *out = buffer_of("px_test_output");
        bool done = strstr(out, "Result:") != NULL;
        g_free(out);
        if (done) break;
        pump(150);
    }
    GtkWidget *out_view = find_named("px_test_output");
    if (out_view) {                                              // show the end of the report
        GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(out_view));
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(tb, &end);
        gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(out_view), &end, 0.0, FALSE, 0, 0);
        pump(300);
    }
    snap(dlg, "proxy-settings");
    gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE);
}

static void shots_filters_body(GtkWidget *dlg, gpointer arg) {
    (void)arg;
    arm("dlg_filter", fill_flt_shot, shot_form(ff("Exclude", "systemd-resolved", "", "", "All", "All"), "log-filter-editor"), GTK_RESPONSE_ACCEPT);
    click("flt_add");
    arm("dlg_filter", fill_flt_shot, shot_form(ff("Include", "firefox*", "", "443", "TCP", "Proxy"), NULL), GTK_RESPONSE_ACCEPT);
    click("flt_add");
    snap(dlg, "log-filters");
    gtk_dialog_response(GTK_DIALOG(dlg), GTK_RESPONSE_CLOSE);
}

static void shots_scenario(void) {
    shot_dir = getenv("PB_SCREENSHOT_DIR");
    if (!shot_dir || !*shot_dir) return;
    printf("== documentation screenshots\n");
    g_object_set(gtk_settings_get_default(), "gtk-application-prefer-dark-theme", FALSE, NULL);    // the documentation is light
    gtk_window_resize(GTK_WINDOW(window), 1000, 600);

    // a clean demo profile with proxies and rules made through the dialogs
    arm("dlg_profile_name", fill_name, (gpointer)"Pentest lab", GTK_RESPONSE_ACCEPT);
    activate("New Profile...");
    pump(300);
    arm("dlg_proxies", shots_proxies_body, NULL, 0);
    activate("Proxy Settings...");
    pump(300);

    activate("Proxy Rules...");
    pump(300);
    // proxies are listed in the order they were added: 1 Corporate SOCKS5, 2 Burp Suite, 3 Tor, 4 Local SOCKS5
    arm("dlg_rule", fill_rule_shot, shot_form(rf("Browsers through Burp", "firefox;chromium;google-chrome", "*", "80;443", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 2, false), "rule-editor"), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    arm("dlg_rule", fill_rule_shot, shot_form(rf("Company network", "*", "10.0.0.0/8;*.corp.example.com", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 1, false), "rule-editor-domains"), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    arm("dlg_rule", fill_rule_shot, shot_form(rf("curl and wget through Tor", "curl;wget", "*", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 3, false), NULL), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    arm("dlg_rule", fill_rule_shot, shot_form(rf("Block telemetry", "telemetry*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, false), NULL), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    arm("dlg_rule", fill_rule_shot, shot_form(rf("Keep git and ssh direct", "ssh;git", "*", "22;9418", RULE_PROTOCOL_TCP, RULE_ACTION_DIRECT, 0, false), NULL), GTK_RESPONSE_ACCEPT);
    click("rules_add");
    pump(500);
    snap(find_named("win_rules"), "rules-window");
    gtk_widget_destroy(find_named("win_rules"));
    pump(300);

    GtkWidget *nb = find_notebook(window);
    // Live Connections: connections that really go through the proxy
    char err[256] = "";
    ProxyData *lab = proxy_named("Local SOCKS5");
    uint32_t live_rule = lab ? ProxyBridge_AddRule("python3*", "192.0.2.40-192.0.2.60", "80", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, lab->id, err, sizeof err) : 0;
    if (live_rule) {
        g_spawn_command_line_async("python3 -c \"import socket,time; a=socket.create_connection(('192.0.2.40',80)); b=socket.create_connection(('192.0.2.41',80)); a.sendall(b'x'*40000); time.sleep(40)\"", NULL);
        if (nb) gtk_notebook_set_current_page(GTK_NOTEBOOK(nb), 2);
        pump(3500);
        snap(window, "live-connections");
        ProxyBridge_DeleteRule(live_rule);
    }

    // the main window: connection lines like the engine reports them. Traffic logging is switched off and the logs cleared first,
    // so that the real traffic of this machine does not mix with the demo lines
    ProxyBridge_SetTrafficLoggingEnabled(false);                 // the engine stays up, it just reports nothing
    pump(800);
    click("conn_clear");
    click("log_clear");
    pump(300);
    lib_connection_callback_ex("firefox", 21408, "104.18.32.47 (example.com)", 443, "TCP", "HTTP 127.0.0.1:8080");
    lib_connection_callback_ex("firefox", 21408, "151.101.1.69 (static.example.org)", 443, "TCP", "HTTP 127.0.0.1:8080");
    lib_connection_callback_ex("curl", 22117, "93.184.216.34 (example.com)", 80, "TCP", "SOCKS5 127.0.0.1:9050");
    lib_connection_callback_ex("curl", 22140, "140.82.112.3 (github.com)", 443, "TCP", "SOCKS5 127.0.0.1:9050");
    lib_connection_callback_ex("chromium", 20977, "10.12.4.20 (intranet.corp.example.com)", 443, "TCP", "SOCKS5 proxy.corp.example.com:1080");
    lib_connection_callback_ex("chromium", 20977, "142.250.74.14", 443, "UDP", "SOCKS5 proxy.corp.example.com:1080");
    lib_connection_callback_ex("git", 22301, "140.82.112.3 (github.com)", 22, "TCP", "DIRECT");
    lib_connection_callback_ex("telemetry-agent", 1984, "198.51.100.23 (metrics.vendor.example)", 443, "TCP", "BLOCK");
    lib_connection_callback_ex("ssh", 22290, "192.168.1.20", 22, "TCP", "DIRECT");
    gui_log("Rule 'Browsers through Burp' loaded");
    gui_log("Proxy 'Local SOCKS5' reachable");
    pump(1500);
    if (nb) gtk_notebook_set_current_page(GTK_NOTEBOOK(nb), 0);
    snap(window, "connections");
    if (nb) gtk_notebook_set_current_page(GTK_NOTEBOOK(nb), 1);
    pump(300);
    snap(window, "activity-log");

    arm("dlg_filters", shots_filters_body, NULL, 0);
    activate("Log Filters...");
    pump(300);

    printf("  screenshots written to %s\n", shot_dir);
}

// ================================================================================================================================
static void ui_main(void) {
    pump(300);
    CHECK_HAS(gtk_window_get_title(GTK_WINDOW(window)), "ProxyBridge - Default");
    CHECK(menu_item("Proxy Settings...") && menu_item("Proxy Rules..."));

    menus_scenario();

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
    profiles_scenario();

    printf("== update check\n");
    updates_scenario();

    printf("== logs\n");
    logs_scenario();

    printf("== zoom, auto-clear, filters, boot, start-up update check\n");
    zoom_scenario();
    autoclear_scenario();
    filters_scenario();
    boot_scenario();
    startup_update_scenario();
    CHECK(profile_delete(profile_find("Zoomed")));            // the scenarios made it; the end state below expects only Default
    save_config();

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

    shots_scenario();                                            // only with PB_SCREENSHOT_DIR

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
