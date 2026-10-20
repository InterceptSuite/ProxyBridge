#include "gui.h"
#include "gui_boot.h"

GList *g_proxies_list = NULL;
char *g_default_proxy = NULL;

enum { COL_NAME, COL_TYPE, COL_ADDR, COL_AUTH, COL_DEFAULT, COL_PTR, N_COLS };

typedef struct {
    GtkWidget *dialog;
    GtkWidget *tree;
    GtkListStore *store;
    GtkWidget *test_host;
    GtkWidget *test_port;
    GtkTextBuffer *output_buffer;
    GtkWidget *test_btn;
} ConfigInfo;

// refs on buffer/btn keep them valid if the dialog closes mid-test
typedef struct {
    uint32_t proxy_id;
    char *host;
    uint16_t port;
    GtkTextBuffer *buffer;
    GtkWidget *btn;
    int result;
} TestJob;

typedef struct { GtkTextBuffer *buffer; char *line; } TestLine;

void free_proxy_data(ProxyData *p) {
    if (!p) return;
    g_free(p->name);
    g_free(p->host);
    g_free(p->username);
    if (p->password) memset(p->password, 0, strlen(p->password));
    g_free(p->password);
    g_free(p);
}

ProxyData *find_proxy_by_name(const char *name) {
    if (!name || !*name) return NULL;
    for (GList *l = g_proxies_list; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        if (p->name && strcmp(p->name, name) == 0) return p;
    }
    return NULL;
}

// 0 = default proxy (empty or unknown name)
uint32_t resolve_proxy_id(const char *name) {
    ProxyData *p = find_proxy_by_name(name);
    return p ? p->id : 0;
}

void apply_proxies_to_lib() {
    ProxyBridge_ClearProxies();
    for (GList *l = g_proxies_list; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        char err[256] = "";
        p->id = ProxyBridge_AddProxy(p->name, p->type, p->host, p->port, p->username, p->password, err, sizeof(err));
        if (p->id == 0) gui_log("Proxy '%s' rejected: %s", p->name, err[0] ? err : "unknown error");
        else if (!p->send_domain) ProxyBridge_SetProxySendDomain(p->id, false);
    }
    ProxyBridge_SetDefaultProxy(resolve_proxy_id(g_default_proxy));
}

static bool confirm(GtkWindow *parent, const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *msg = g_strdup_vprintf(format, args);
    va_end(args);
    GtkWidget *q = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", msg);
    int resp = gtk_dialog_run(GTK_DIALOG(q));
    gtk_widget_destroy(q);
    g_free(msg);
    return resp == GTK_RESPONSE_YES;
}

static bool port_text_valid(const char *text, int *port_out) {
    size_t n = strlen(text);
    if (n == 0 || n > 5 || strspn(text, "0123456789") != n) return false;
    int p = (int)parse_long(text);
    if (p < 1 || p > 65535) return false;
    *port_out = p;
    return true;
}

// the first line replaces the "Testing..." placeholder, later lines are appended
static gboolean on_test_line(gpointer user_data) {
    TestLine *tl = (TestLine *)user_data;
    char *text = g_utf8_make_valid(tl->line, -1);
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(tl->buffer, &end);
    gtk_text_buffer_insert(tl->buffer, &end, text, -1);
    gtk_text_buffer_insert(tl->buffer, &end, "\n", 1);
    g_free(text);
    g_object_unref(tl->buffer);
    g_free(tl->line);
    g_free(tl);
    return FALSE;
}

static gboolean on_test_done(gpointer user_data) {
    TestJob *job = (TestJob *)user_data;
    gtk_widget_set_sensitive(job->btn, TRUE);
    g_object_unref(job->buffer);
    g_object_unref(job->btn);
    g_free(job->host);
    g_free(job);
    return FALSE;
}

static void test_progress(const char *line, void *user) {
    TestJob *job = (TestJob *)user;
    TestLine *tl = g_malloc0(sizeof *tl);
    tl->buffer = g_object_ref(job->buffer);
    tl->line = g_strdup(line);
    g_idle_add(on_test_line, tl);
}

static gpointer run_test_thread(gpointer user_data) {
    TestJob *job = (TestJob *)user_data;
    job->result = ProxyBridge_TestProxyEx(job->proxy_id, job->host, job->port, test_progress, job);
    g_idle_add(on_test_done, job);
    return NULL;
}

static ProxyData *get_selected_proxy(ConfigInfo *info) {
    GtkTreeModel *model;
    GtkTreeIter iter;
    gpointer ptr = NULL;
    if (gtk_tree_selection_get_selected(gtk_tree_view_get_selection(GTK_TREE_VIEW(info->tree)), &model, &iter))
        gtk_tree_model_get(model, &iter, COL_PTR, &ptr, -1);
    return (ProxyData *)ptr;
}

static void on_start_test_clicked(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;
    ProxyData *px = get_selected_proxy(info);
    const char *err = !px ? "Error: Select a proxy to test."
                    : px->id == 0 ? "Error: This proxy was rejected by the engine, edit and save it again." : NULL;
    if (err) {
        gtk_text_buffer_set_text(info->output_buffer, err, -1);
        return;
    }

    const char *t_host = gtk_entry_get_text(GTK_ENTRY(info->test_host));
    int t_port = (int)parse_long(gtk_entry_get_text(GTK_ENTRY(info->test_port)));
    if (t_port <= 0 || t_port > 65535) t_port = 80;

    gtk_text_buffer_set_text(info->output_buffer, "", -1);
    gtk_widget_set_sensitive(info->test_btn, FALSE);

    TestJob *job = g_malloc0(sizeof(TestJob));
    job->proxy_id = px->id;
    job->host = g_strdup(*t_host ? t_host : "google.com");
    job->port = (uint16_t)t_port;
    job->buffer = g_object_ref(info->output_buffer);
    job->btn = g_object_ref(info->test_btn);
    g_thread_unref(g_thread_new("test_conn", run_test_thread, job));
}

static void refresh_proxy_store(ConfigInfo *info) {
    gtk_list_store_clear(info->store);
    for (GList *l = g_proxies_list; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        char *addr = g_strdup_printf("%s:%u", p->host, p->port);
        bool is_def = g_default_proxy && strcmp(g_default_proxy, p->name) == 0;
        GtkTreeIter iter;
        gtk_list_store_append(info->store, &iter);
        gtk_list_store_set(info->store, &iter,
            COL_NAME, p->name,
            COL_TYPE, p->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5",
            COL_ADDR, addr,
            COL_AUTH, (p->username && *p->username) ? "Yes" : "No",
            COL_DEFAULT, is_def ? "Yes" : "",
            COL_PTR, p,
            -1);
        g_free(addr);
    }
}

static void select_proxy_row(ConfigInfo *info, ProxyData *target) {
    GtkTreeModel *model = GTK_TREE_MODEL(info->store);
    GtkTreeIter iter;
    if (!target || !gtk_tree_model_get_iter_first(model, &iter)) return;
    do {
        gpointer ptr = NULL;
        gtk_tree_model_get(model, &iter, COL_PTR, &ptr, -1);
        if (ptr == target) {
            gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(info->tree)), &iter);
            return;
        }
    } while (gtk_tree_model_iter_next(model, &iter));
}

static void set_str(char **dst, const char *src) {
    g_free(*dst);
    *dst = g_strdup(src);
}

// renaming keeps the default proxy and the rules pointing at it
static void rename_proxy_refs(const char *old_name, const char *new_name) {
    if (g_default_proxy && strcmp(g_default_proxy, old_name) == 0) set_str(&g_default_proxy, new_name);
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        RuleData *r = (RuleData *)l->data;
        if (r->proxy_name && strcmp(r->proxy_name, old_name) == 0) set_str(&r->proxy_name, new_name);
    }
}

// existing == NULL adds. returns the saved proxy or NULL
static ProxyData *proxy_edit_dialog(GtkWindow *parent, ProxyData *existing) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons(existing ? "Edit Proxy" : "Add Proxy", parent,
                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                         "Cancel", GTK_RESPONSE_CANCEL, "Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 420, -1);
    gtk_widget_set_name(dialog, "dlg_proxy");
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), grid, TRUE, TRUE, 0);

    GtkWidget *name_entry = gtk_entry_new();
    GtkWidget *type_combo = combo_new("HTTP", "SOCKS5", NULL);
    GtkWidget *ip_entry = gtk_entry_new();
    GtkWidget *port_entry = gtk_entry_new();
    GtkWidget *user_entry = gtk_entry_new();
    GtkWidget *pass_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(pass_entry), FALSE);
    grid_row(grid, 0, "Name:", name_entry);
    grid_row(grid, 1, "Type:", type_combo);
    grid_row(grid, 2, "Host:", ip_entry);
    grid_row(grid, 3, "Port:", port_entry);
    grid_row(grid, 4, "Username:", user_entry);
    grid_row(grid, 5, "Password:", pass_entry);
    GtkWidget *dns_check = gtk_check_button_new_with_label("DNS via proxy (the proxy resolves host names)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(dns_check), existing ? existing->send_domain : TRUE);
    gtk_grid_attach(GTK_GRID(grid), dns_check, 1, 6, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), hint_label("On: connections to a name the application resolved are sent to the proxy by name. Off: the IP address is sent. UDP always uses the IP."), 1, 7, 1, 1);
    GtkWidget *err_label = hint_label("");
    gtk_widget_set_name(name_entry, "px_name"); gtk_widget_set_name(type_combo, "px_type"); gtk_widget_set_name(ip_entry, "px_host");
    gtk_widget_set_name(port_entry, "px_port"); gtk_widget_set_name(user_entry, "px_user"); gtk_widget_set_name(pass_entry, "px_pass");
    gtk_widget_set_name(dns_check, "px_dns"); gtk_widget_set_name(err_label, "px_error");
    gtk_grid_attach(GTK_GRID(grid), err_label, 0, 8, 2, 1);

    gtk_combo_box_set_active(GTK_COMBO_BOX(type_combo), 1);
    if (existing) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%u", existing->port);
        gtk_entry_set_text(GTK_ENTRY(name_entry), existing->name);
        gtk_combo_box_set_active(GTK_COMBO_BOX(type_combo), existing->type == PROXY_TYPE_HTTP ? 0 : 1);
        gtk_entry_set_text(GTK_ENTRY(ip_entry), existing->host);
        if (existing->port) gtk_entry_set_text(GTK_ENTRY(port_entry), port_str);
        gtk_entry_set_text(GTK_ENTRY(user_entry), existing->username ? existing->username : "");
        gtk_entry_set_text(GTK_ENTRY(pass_entry), existing->password ? existing->password : "");
    } else if (!g_proxies_list) {
        gtk_entry_set_text(GTK_ENTRY(name_entry), "default");
    }
    gtk_widget_show_all(dialog);

    ProxyData *result = NULL;
    while (!result && gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *port_text = gtk_entry_get_text(GTK_ENTRY(port_entry));
        const char *user = gtk_entry_get_text(GTK_ENTRY(user_entry));
        const char *pass = gtk_entry_get_text(GTK_ENTRY(pass_entry));
        ProxyType type = gtk_combo_box_get_active(GTK_COMBO_BOX(type_combo)) == 0 ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
        char *name = g_strstrip(g_strdup(gtk_entry_get_text(GTK_ENTRY(name_entry))));
        char *host = g_strstrip(g_strdup(gtk_entry_get_text(GTK_ENTRY(ip_entry))));
        ProxyData *dup = find_proxy_by_name(name);
        int port = 0;
        char err[256] = "";

        const char *msg = !*name ? "Name cannot be empty."
            : (dup && dup != existing) ? "A proxy with this name already exists."
            : !*host ? "Host (IP/Domain) cannot be empty."
            : !port_text_valid(port_text, &port) ? "Port must be a number between 1 and 65535." : NULL;

        uint32_t id = existing ? existing->id : 0;
        if (!msg) {
            bool ok;
            if (id) {
                ok = ProxyBridge_EditProxy(id, name, type, host, (uint16_t)port, user, pass, err, sizeof(err));
            } else {
                id = ProxyBridge_AddProxy(name, type, host, (uint16_t)port, user, pass, err, sizeof(err));
                ok = id != 0;
            }
            if (ok) ProxyBridge_SetProxySendDomain(id, gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(dns_check)));
            else msg = err[0] ? err : "Engine rejected the proxy settings.";
        }
        if (msg) {
            set_error_label(err_label, msg);
            g_free(name);
            g_free(host);
            continue;
        }

        ProxyData *p = existing;
        if (!p) {
            p = g_malloc0(sizeof(ProxyData));
            g_proxies_list = g_list_append(g_proxies_list, p);
        } else if (strcmp(p->name, name) != 0) {
            rename_proxy_refs(p->name, name);
        }
        p->id = id;
        g_free(p->name); p->name = name;
        g_free(p->host); p->host = host;
        set_str(&p->username, user);
        if (p->password) memset(p->password, 0, strlen(p->password));
        set_str(&p->password, pass);
        p->type = type;
        p->port = (uint16_t)port;
        p->send_domain = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(dns_check));

        if (!find_proxy_by_name(g_default_proxy)) {
            set_str(&g_default_proxy, p->name);
            ProxyBridge_SetDefaultProxy(p->id);
        }
        result = p;
    }
    gtk_widget_destroy(dialog);
    return result;
}

static void commit_proxy_change(ConfigInfo *info, ProxyData *p) {
    if (!p) return;
    save_config();
    refresh_proxy_store(info);
    select_proxy_row(info, p);
}

static void on_proxy_add(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;
    commit_proxy_change(info, proxy_edit_dialog(GTK_WINDOW(info->dialog), NULL));
}

static void on_proxy_edit(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;
    ProxyData *sel = get_selected_proxy(info);
    if (!sel) {
        show_message(GTK_WINDOW(info->dialog), GTK_MESSAGE_WARNING, "Select a proxy first.");
        return;
    }
    commit_proxy_change(info, proxy_edit_dialog(GTK_WINDOW(info->dialog), sel));
}

static void on_proxy_row_activated(GtkTreeView *tree, GtkTreePath *path, GtkTreeViewColumn *col, gpointer data) {
    on_proxy_edit(NULL, data);
}

static void on_proxy_delete(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;
    ProxyData *p = get_selected_proxy(info);
    if (!p) {
        show_message(GTK_WINDOW(info->dialog), GTK_MESSAGE_WARNING, "Select a proxy first.");
        return;
    }
    if (!confirm(GTK_WINDOW(info->dialog), "Delete proxy '%s'?\nRules using it will fall back to the default proxy.", p->name)) return;

    if (p->id) ProxyBridge_DeleteProxy(p->id);
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        RuleData *r = (RuleData *)l->data;
        if (r->proxy_name && strcmp(r->proxy_name, p->name) == 0) set_str(&r->proxy_name, NULL);
    }

    bool was_default = g_default_proxy && strcmp(g_default_proxy, p->name) == 0;
    g_proxies_list = g_list_remove(g_proxies_list, p);
    free_proxy_data(p);
    if (was_default) {
        set_str(&g_default_proxy, g_proxies_list ? ((ProxyData *)g_proxies_list->data)->name : NULL);
        ProxyBridge_SetDefaultProxy(resolve_proxy_id(g_default_proxy));
    }
    save_config();
    refresh_proxy_store(info);
}

static void on_proxy_set_default(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;
    ProxyData *p = get_selected_proxy(info);
    if (!p) {
        show_message(GTK_WINDOW(info->dialog), GTK_MESSAGE_WARNING, "Select a proxy first.");
        return;
    }
    set_str(&g_default_proxy, p->name);
    ProxyBridge_SetDefaultProxy(p->id);
    commit_proxy_change(info, p);

    char *status_msg = g_strdup_printf("Default proxy: %s (%s:%u)", p->name, p->host, p->port);
    gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, status_msg);
    g_free(status_msg);
}

void on_proxy_configure(GtkWidget *widget, gpointer data) {
    ConfigInfo info = {0};
    info.dialog = gtk_dialog_new_with_buttons("Proxy Settings", GTK_WINDOW(window),
                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                         "Close", GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(info.dialog), 650, 560);
    gtk_widget_set_name(info.dialog, "dlg_proxies");

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(info.dialog))), grid, TRUE, TRUE, 0);

    info.store = gtk_list_store_new(N_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
    info.tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(info.store));
    g_object_unref(info.store);
    const char *titles[] = {"Name", "Type", "Host:Port", "Auth", "Default"};
    for (int i = 0; i < 5; i++) {
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(titles[i], gtk_cell_renderer_text_new(), "text", i, NULL);
        gtk_tree_view_column_set_resizable(c, TRUE);
        gtk_tree_view_column_set_expand(c, i == 2);
        gtk_tree_view_append_column(GTK_TREE_VIEW(info.tree), c);
    }
    gtk_widget_set_name(info.tree, "proxy_tree");
    g_signal_connect(info.tree, "row-activated", G_CALLBACK(on_proxy_row_activated), &info);
    GtkWidget *tree_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(tree_scroll, -1, 180);
    gtk_widget_set_hexpand(tree_scroll, TRUE);
    gtk_widget_set_vexpand(tree_scroll, TRUE);
    gtk_container_add(GTK_CONTAINER(tree_scroll), info.tree);
    gtk_grid_attach(GTK_GRID(grid), tree_scroll, 0, 0, 4, 1);

    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    const char *labels[] = {"Add", "Edit", "Delete", "Set Default"};
    void (*cbs[])(GtkWidget *, gpointer) = {on_proxy_add, on_proxy_edit, on_proxy_delete, on_proxy_set_default};
    const char *bnames[] = {"px_add", "px_edit", "px_delete", "px_default"};
    for (int i = 0; i < 4; i++) {
        GtkWidget *b = gtk_button_new_with_label(labels[i]);
        gtk_widget_set_name(b, bnames[i]);
        g_signal_connect(b, "clicked", G_CALLBACK(cbs[i]), &info);
        gtk_box_pack_start(GTK_BOX(btn_box), b, FALSE, FALSE, 0);
    }
    gtk_grid_attach(GTK_GRID(grid), btn_box, 0, 1, 4, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), 0, 2, 4, 1);

    GtkWidget *test_label = gtk_label_new("<b>Test Selected Proxy</b>");
    gtk_label_set_use_markup(GTK_LABEL(test_label), TRUE);
    gtk_widget_set_halign(test_label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), test_label, 0, 3, 4, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Target:"), 0, 4, 1, 1);
    info.test_host = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(info.test_host), "google.com");
    gtk_widget_set_hexpand(info.test_host, TRUE);
    gtk_grid_attach(GTK_GRID(grid), info.test_host, 1, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Port:"), 2, 4, 1, 1);
    info.test_port = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(info.test_port), "80");
    gtk_widget_set_size_request(info.test_port, 80, -1);
    gtk_grid_attach(GTK_GRID(grid), info.test_port, 3, 4, 1, 1);

    gtk_widget_set_name(info.test_host, "px_test_host"); gtk_widget_set_name(info.test_port, "px_test_port");
    info.test_btn = gtk_button_new_with_label("Start Test");
    gtk_widget_set_name(info.test_btn, "px_test");
    g_signal_connect(info.test_btn, "clicked", G_CALLBACK(on_start_test_clicked), &info);
    gtk_grid_attach(GTK_GRID(grid), info.test_btn, 0, 5, 4, 1);

    GtkWidget *out_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(out_scroll, -1, 150);
    GtkWidget *out_view = gtk_text_view_new();
    gtk_widget_set_name(out_view, "px_test_output");
    gtk_text_view_set_editable(GTK_TEXT_VIEW(out_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(out_view), TRUE);
    info.output_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(out_view));
    gtk_container_add(GTK_CONTAINER(out_scroll), out_view);
    gtk_grid_attach(GTK_GRID(grid), out_scroll, 0, 6, 4, 1);

    refresh_proxy_store(&info);
    ProxyData *def = find_proxy_by_name(g_default_proxy);
    if (!def && g_proxies_list) def = (ProxyData *)g_proxies_list->data;
    select_proxy_row(&info, def);

    gtk_widget_show_all(info.dialog);
    gtk_dialog_run(GTK_DIALOG(info.dialog));
    gtk_widget_destroy(info.dialog);
}

static void update_profile_ui() {
    char *title = g_strdup_printf("ProxyBridge - %s", g_active_profile);
    gtk_window_set_title(GTK_WINDOW(window), title);
    g_free(title);
    title = g_strdup_printf("Active profile: %s", g_active_profile);
    gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, title);
    g_free(title);
    gui_refresh_profile_menu();                         // the checkmark in Profile > Switch follows the active profile
}

// engine keeps running, only its proxies and rules are replaced
static void reapply_active_profile() {
    ProxyBridge_BeginBatch();                  // the datapath sees the new profile all at once, never a half-built one
    ProxyBridge_ClearRules();
    apply_proxies_to_lib();
    apply_rules_to_lib();
    ProxyBridge_EndBatch();
    gui_sync_switches();
    save_config();
    refresh_rules_window();
    update_profile_ui();
}

// NULL on cancel
static char *ask_profile_name(GtkWindow *parent, const char *title, const char *initial) {
    GtkWidget *d = gtk_dialog_new_with_buttons(title, parent, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                               "Cancel", GTK_RESPONSE_CANCEL, "OK", GTK_RESPONSE_ACCEPT, NULL);
    gtk_widget_set_name(d, "dlg_profile_name");
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *entry = gtk_entry_new();
    gtk_widget_set_name(entry, "profile_name_entry");
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_entry_set_text(GTK_ENTRY(entry), initial);
    gtk_box_pack_start(GTK_BOX(box), gtk_label_new("Profile name:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 5);
    gtk_dialog_set_default_response(GTK_DIALOG(d), GTK_RESPONSE_ACCEPT);
    gtk_widget_show_all(d);

    char *result = NULL;
    while (!result && gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *name = g_strstrip(g_strdup(gtk_entry_get_text(GTK_ENTRY(entry))));
        if (!*name) show_message(GTK_WINDOW(d), GTK_MESSAGE_ERROR, "Profile name cannot be empty.");
        else if (profile_find(name) && strcmp(initial, name) != 0) show_message(GTK_WINDOW(d), GTK_MESSAGE_ERROR, "A profile with this name already exists.");
        else { result = name; continue; }
        g_free(name);
    }
    gtk_widget_destroy(d);
    return result;
}

// ---- the Profile menu: every item acts on the active profile, like in the Windows app ----

static GtkWindow *profile_parent() { return GTK_WINDOW(window); }

static void profile_switch_to(const char *name) {
    if (name && strcmp(name, g_active_profile) != 0 && profile_activate(name)) reapply_active_profile();
}

// Profile > Switch > <name>
void on_profile_switch_item(GtkWidget *item, gpointer data) {
    if (!gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(item))) return;       // the item that just lost its check
    profile_switch_to((const char *)data);
}

void on_profile_new(GtkWidget *widget, gpointer data) {
    char *name = ask_profile_name(profile_parent(), "New Profile", "");
    if (name && profile_create(name, false)) {
        profile_switch_to(name);                          // like the Windows app: the new profile is the active one
        save_config();
    }
    g_free(name);
}

void on_profile_duplicate(GtkWidget *widget, gpointer data) {
    char *initial = g_strdup_printf("%s copy", g_active_profile);
    char *name = ask_profile_name(profile_parent(), "Duplicate Profile", initial);
    if (name && profile_create(name, true)) {             // a copy of the active profile
        profile_switch_to(name);
        save_config();
    }
    g_free(initial);
    g_free(name);
}

void on_profile_rename(GtkWidget *widget, gpointer data) {
    char *name = ask_profile_name(profile_parent(), "Rename Profile", g_active_profile);
    if (name && profile_rename(profile_find(g_active_profile), name)) {
        save_config();
        update_profile_ui();
    }
    g_free(name);
}

void on_profile_delete(GtkWidget *widget, gpointer data) {
    if (!g_profiles || !g_profiles->next) {
        show_message(profile_parent(), GTK_MESSAGE_WARNING, "The last profile cannot be deleted.");
    } else if (confirm(profile_parent(), "Delete profile '%s' with all its proxies and rules?", g_active_profile)) {
        // the active profile goes: another one becomes active
        if (profile_delete(profile_find(g_active_profile))) reapply_active_profile();
    }
}

void on_profile_import(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Import Profile", profile_parent(), GTK_FILE_CHOOSER_ACTION_OPEN,
                                                    "Cancel", GTK_RESPONSE_CANCEL, "Import", GTK_RESPONSE_ACCEPT, NULL);
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "ProxyBridge profiles (*.pbprofile)");
    gtk_file_filter_add_pattern(filter, "*.pbprofile");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);
    GtkFileFilter *all = gtk_file_filter_new();
    gtk_file_filter_set_name(all, "All files");
    gtk_file_filter_add_pattern(all, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), all);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char err[256];
        Profile *p = filename ? profile_import(filename, err, sizeof err) : NULL;
        if (p) {
            char *name = g_strdup(p->name);
            save_config();
            profile_switch_to(name);                      // like the Windows app: the imported profile becomes the active one
            gui_refresh_profile_menu();
            g_free(name);
        } else {
            show_message(profile_parent(), GTK_MESSAGE_ERROR, "Import failed: %s", filename ? err : "no file selected");
        }
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

void on_profile_export(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Export Profile", profile_parent(), GTK_FILE_CHOOSER_ACTION_SAVE,
                                                    "Cancel", GTK_RESPONSE_CANCEL, "Export", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
    char *suggested = g_strdup_printf("%s.pbprofile", g_active_profile);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), suggested);
    g_free(suggested);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char err[256];
        if (filename && profile_export(profile_find(g_active_profile), filename, err, sizeof err))
            show_message(profile_parent(), GTK_MESSAGE_INFO,
                         "Profile '%s' exported to %s.\nThe file contains your proxy credentials, so it is readable by you only.", g_active_profile, filename);
        else
            show_message(profile_parent(), GTK_MESSAGE_ERROR, "Export failed: %s", filename ? err : "no file selected");
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}


// ---- connection log filters ----
typedef struct {
    GtkWidget *dialog, *tree;
    GtkListStore *store;
    struct pbp_filter *work;     // working copy; every change is applied at once
    size_t n;
} FiltersInfo;

static void filters_commit(FiltersInfo *fi) {
    struct pbp_filter *copy = calloc(fi->n ? fi->n : 1, sizeof *copy);
    for (size_t i = 0; copy && i < fi->n; i++) copy[i] = pbp_filter_dup(&fi->work[i]);
    gui_filters_replace(copy, copy ? fi->n : 0);
    save_config();
}

static void filters_refresh(FiltersInfo *fi) {
    gtk_list_store_clear(fi->store);
    for (size_t i = 0; i < fi->n; i++) {
        const struct pbp_filter *f = &fi->work[i];
        GtkTreeIter it;
        gtk_list_store_append(fi->store, &it);
        gtk_list_store_set(fi->store, &it, 0, f->exclude ? "Exclude" : "Include", 1, f->process, 2, f->ip, 3, f->port, 4, f->protocol, 5, f->action, -1);
    }
}

static bool port_pattern_ok(const char *p) {
    if (!*p || strcasecmp(p, "All") == 0) return true;
    for (; *p; p++) if (!g_ascii_isdigit(*p) && *p != '*' && *p != '?') return false;
    return true;
}

// edits *f in place; false when cancelled
static bool filter_edit_dialog(GtkWindow *parent, struct pbp_filter *f) {
    GtkWidget *d = gtk_dialog_new_with_buttons("Log Filter", parent, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                               "Cancel", GTK_RESPONSE_CANCEL, "Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_widget_set_name(d, "dlg_filter");
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(d))), grid, TRUE, TRUE, 0);
    GtkWidget *mode = combo_new("Include", "Exclude", NULL), *proto = combo_new("All", "TCP", "UDP", NULL);
    GtkWidget *action = combo_new("All", "Direct", "Proxy", "Blocked", NULL);
    GtkWidget *proc = gtk_entry_new(), *ip = gtk_entry_new(), *port = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(proc), 255);
    gtk_entry_set_max_length(GTK_ENTRY(ip), 63);
    gtk_entry_set_max_length(GTK_ENTRY(port), 15);
    GtkWidget *err = hint_label("");
    gtk_widget_set_name(mode, "flt_mode"); gtk_widget_set_name(proc, "flt_process"); gtk_widget_set_name(ip, "flt_ip");
    gtk_widget_set_name(port, "flt_port"); gtk_widget_set_name(proto, "flt_proto"); gtk_widget_set_name(action, "flt_action");
    gtk_widget_set_name(err, "flt_error");
    grid_row(grid, 0, "Mode:", mode);
    grid_row(grid, 1, "Process:", proc);
    grid_row(grid, 2, "IP address:", ip);
    grid_row(grid, 3, "Port:", port);
    grid_row(grid, 4, "Protocol:", proto);
    grid_row(grid, 5, "Action:", action);
    gtk_grid_attach(GTK_GRID(grid), hint_label("Include shows only matching connections, Exclude hides them (Exclude wins). Patterns are case-insensitive: * and ? match anything, empty matches all."), 0, 6, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), err, 0, 7, 2, 1);
    gtk_combo_box_set_active(GTK_COMBO_BOX(mode), f->exclude ? 1 : 0);
    gtk_entry_set_text(GTK_ENTRY(proc), f->process ? f->process : "");
    gtk_entry_set_text(GTK_ENTRY(ip), f->ip ? f->ip : "");
    gtk_entry_set_text(GTK_ENTRY(port), f->port ? f->port : "");
    const char *protos[] = {"All", "TCP", "UDP"}, *actions[] = {"All", "Direct", "Proxy", "Blocked"};
    int pi = 0, ai = 0;
    for (int i = 0; i < 3; i++) if (f->protocol && !strcasecmp(f->protocol, protos[i])) pi = i;
    for (int i = 0; i < 4; i++) if (f->action && !strcasecmp(f->action, actions[i])) ai = i;
    gtk_combo_box_set_active(GTK_COMBO_BOX(proto), pi);
    gtk_combo_box_set_active(GTK_COMBO_BOX(action), ai);
    gtk_widget_show_all(d);

    bool saved = false;
    while (!saved && gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        const char *pt = gtk_entry_get_text(GTK_ENTRY(port));
        if (!port_pattern_ok(pt)) { set_error_label(err, "Port must be digits, * or ? (or empty)."); continue; }
        pbp_filter_clear(f);
        f->exclude = gtk_combo_box_get_active(GTK_COMBO_BOX(mode)) == 1;
        f->process = strdup(gtk_entry_get_text(GTK_ENTRY(proc)));
        f->ip = strdup(gtk_entry_get_text(GTK_ENTRY(ip)));
        f->port = strdup(pt);
        int p2 = gtk_combo_box_get_active(GTK_COMBO_BOX(proto)), a2 = gtk_combo_box_get_active(GTK_COMBO_BOX(action));
        f->protocol = strdup(protos[p2 < 0 ? 0 : p2]);
        f->action = strdup(actions[a2 < 0 ? 0 : a2]);
        saved = true;
    }
    gtk_widget_destroy(d);
    return saved;
}

static int filters_selected(FiltersInfo *fi) {
    GtkTreeModel *model;
    GtkTreeIter it;
    if (!gtk_tree_selection_get_selected(gtk_tree_view_get_selection(GTK_TREE_VIEW(fi->tree)), &model, &it)) return -1;
    GtkTreePath *path = gtk_tree_model_get_path(model, &it);
    int idx = gtk_tree_path_get_indices(path)[0];
    gtk_tree_path_free(path);
    return idx;
}

static void on_filter_add(GtkWidget *w, gpointer data) {
    FiltersInfo *fi = data;
    if (fi->n >= PBP_MAX_FILTERS) {
        show_message(GTK_WINDOW(fi->dialog), GTK_MESSAGE_WARNING, "At most %d filters are supported.", PBP_MAX_FILTERS);
        return;
    }
    struct pbp_filter f = { false, strdup(""), strdup(""), strdup(""), strdup("All"), strdup("All") };
    if (filter_edit_dialog(GTK_WINDOW(fi->dialog), &f)) {
        fi->work = realloc(fi->work, (fi->n + 1) * sizeof *fi->work);
        fi->work[fi->n++] = f;
        filters_commit(fi);
        filters_refresh(fi);
    } else {
        pbp_filter_clear(&f);
    }
}

static void on_filter_edit(GtkWidget *w, gpointer data) {
    FiltersInfo *fi = data;
    int i = filters_selected(fi);
    if (i < 0) { show_message(GTK_WINDOW(fi->dialog), GTK_MESSAGE_WARNING, "Select a filter first."); return; }
    struct pbp_filter f = pbp_filter_dup(&fi->work[i]);
    if (filter_edit_dialog(GTK_WINDOW(fi->dialog), &f)) {
        pbp_filter_clear(&fi->work[i]);
        fi->work[i] = f;
        filters_commit(fi);
        filters_refresh(fi);
    } else {
        pbp_filter_clear(&f);
    }
}

static void on_filter_delete(GtkWidget *w, gpointer data) {
    FiltersInfo *fi = data;
    int i = filters_selected(fi);
    if (i < 0) { show_message(GTK_WINDOW(fi->dialog), GTK_MESSAGE_WARNING, "Select a filter first."); return; }
    pbp_filter_clear(&fi->work[i]);
    memmove(&fi->work[i], &fi->work[i + 1], (fi->n - (size_t)i - 1) * sizeof *fi->work);
    fi->n--;
    filters_commit(fi);
    filters_refresh(fi);
}

static void on_filter_row_activated(GtkTreeView *tree, GtkTreePath *path, GtkTreeViewColumn *col, gpointer data) {
    on_filter_edit(NULL, data);
}

void on_log_filters_clicked(GtkWidget *widget, gpointer data) {
    FiltersInfo fi = {0};
    size_t n = 0;
    struct pbp_filter *cur = gui_filters(&n);
    fi.work = calloc(n ? n : 1, sizeof *fi.work);
    for (size_t i = 0; i < n; i++) fi.work[i] = pbp_filter_dup(&cur[i]);
    fi.n = n;

    fi.dialog = gtk_dialog_new_with_buttons("Connection Log Filters", GTK_WINDOW(window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                            "Close", GTK_RESPONSE_CLOSE, NULL);
    gtk_widget_set_name(fi.dialog, "dlg_filters");
    gtk_window_set_default_size(GTK_WINDOW(fi.dialog), 640, 380);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(fi.dialog));
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    fi.store = gtk_list_store_new(6, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    fi.tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(fi.store));
    gtk_widget_set_name(fi.tree, "filter_tree");
    g_object_unref(fi.store);
    const char *titles[] = {"Mode", "Process", "IP address", "Port", "Protocol", "Action"};
    for (int i = 0; i < 6; i++) {
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(titles[i], gtk_cell_renderer_text_new(), "text", i, NULL);
        gtk_tree_view_column_set_resizable(c, TRUE);
        gtk_tree_view_column_set_expand(c, i == 1 || i == 2);
        gtk_tree_view_append_column(GTK_TREE_VIEW(fi.tree), c);
    }
    g_signal_connect(fi.tree, "row-activated", G_CALLBACK(on_filter_row_activated), &fi);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), fi.tree);
    gtk_box_pack_start(GTK_BOX(box), hint_label("Filters hide or show lines of the connection log for new connections. They belong to the active profile."), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 5);
    GtkWidget *btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    const char *labels[] = {"Add", "Edit", "Delete"}, *names[] = {"flt_add", "flt_edit", "flt_delete"};
    void (*cbs[])(GtkWidget *, gpointer) = {on_filter_add, on_filter_edit, on_filter_delete};
    for (int i = 0; i < 3; i++) {
        GtkWidget *b = gtk_button_new_with_label(labels[i]);
        gtk_widget_set_name(b, names[i]);
        g_signal_connect(b, "clicked", G_CALLBACK(cbs[i]), &fi);
        gtk_box_pack_start(GTK_BOX(btns), b, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(box), btns, FALSE, FALSE, 5);
    filters_refresh(&fi);
    gtk_widget_show_all(fi.dialog);
    gtk_dialog_run(GTK_DIALOG(fi.dialog));
    gtk_widget_destroy(fi.dialog);
    for (size_t i = 0; i < fi.n; i++) pbp_filter_clear(&fi.work[i]);
    free(fi.work);
}
