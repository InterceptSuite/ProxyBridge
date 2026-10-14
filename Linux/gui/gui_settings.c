#include "gui.h"

// settings stuff, proxy list manager

GList *g_proxies_list = NULL;
char *g_default_proxy = NULL;

enum {
    COL_NAME = 0,
    COL_TYPE,
    COL_ADDR,
    COL_AUTH,
    COL_DEFAULT,
    COL_PTR,
    N_COLS
};

void free_proxy_data(ProxyData *p) {
    if (!p) return;
    g_free(p->name);
    g_free(p->host);
    g_free(p->username);
    // dont leave passwords lying around in freed memory
    if (p->password) {
        memset(p->password, 0, strlen(p->password));
        g_free(p->password);
    }
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

// name -> library id, 0 means default proxy (empty or unknown name)
uint32_t resolve_proxy_id(const char *name) {
    ProxyData *p = find_proxy_by_name(name);
    return p ? p->id : 0;
}

// push the stored proxies to the library, call before ProxyBridge_Start
void apply_proxies_to_lib() {
    ProxyBridge_ClearProxies();
    for (GList *l = g_proxies_list; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        char err[256] = "";
        p->id = ProxyBridge_AddProxy(p->name, p->type, p->host, p->port, p->username, p->password, err, sizeof(err));
        if (p->id == 0) gui_log("Proxy '%s' rejected: %s", p->name, err[0] ? err : "unknown error");
    }
    ProxyBridge_SetDefaultProxy(resolve_proxy_id(g_default_proxy));
}

static bool port_text_valid(const char *port_text, int *port_out) {
    if (!port_text || !*port_text || strspn(port_text, "0123456789") != strlen(port_text) || strlen(port_text) > 5) return false;
    int p = (int)safe_strtol(port_text);
    if (p < 1 || p > 65535) return false;
    if (port_out) *port_out = p;
    return true;
}

// ---- test ----

static gboolean on_test_done(gpointer user_data) {
    TestResultData *data = (TestResultData *)user_data;
    gtk_text_buffer_set_text(data->buffer, data->result_text, -1);
    gtk_widget_set_sensitive(data->btn, TRUE);

    g_object_unref(data->buffer);
    g_object_unref(data->btn);
    g_free(data->result_text);
    g_free(data);
    return FALSE;
}

static gpointer run_test_thread(gpointer user_data) {
    struct TestRunnerData *req = (struct TestRunnerData *)user_data;

    char *buffer = g_malloc0(4096);

    // run test
    ProxyBridge_TestProxy(req->proxy_id, req->host, req->port, buffer, 4096);
    buffer[4095] = '\0';
    if (!g_utf8_validate(buffer, -1, NULL)) {
        char *fixed = g_utf8_make_valid(buffer, -1);
        g_free(buffer);
        buffer = fixed;
    }

    TestResultData *res = g_malloc0(sizeof(TestResultData));
    res->result_text = buffer;
    res->buffer = req->buffer;
    res->btn = req->btn;

    g_idle_add(on_test_done, res);

    g_free(req->host);
    g_free(req);
    return NULL;
}

static ProxyData *get_selected_proxy(ConfigInfo *info) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(info->tree));
    GtkTreeModel *model;
    GtkTreeIter iter;
    if (!gtk_tree_selection_get_selected(sel, &model, &iter)) return NULL;
    gpointer ptr = NULL;
    gtk_tree_model_get(model, &iter, COL_PTR, &ptr, -1);
    return (ProxyData *)ptr;
}

static void on_start_test_clicked(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;

    ProxyData *px = get_selected_proxy(info);
    if (!px) {
        gtk_text_buffer_set_text(info->output_buffer, "Error: Select a proxy to test.", -1);
        return;
    }
    if (px->id == 0) {
        gtk_text_buffer_set_text(info->output_buffer, "Error: This proxy was rejected by the engine, edit and save it again.", -1);
        return;
    }

    // get target
    const char *t_host = gtk_entry_get_text(GTK_ENTRY(info->test_host));
    const char *t_port_s = gtk_entry_get_text(GTK_ENTRY(info->test_port));

    if (!t_host || strlen(t_host) == 0) t_host = "google.com";
    int t_port = (int)safe_strtol(t_port_s);
    if (t_port <= 0 || t_port > 65535) t_port = 80;

    // update gui
    gtk_text_buffer_set_text(info->output_buffer, "Testing connection... Please wait...", -1);
    gtk_widget_set_sensitive(info->test_btn, FALSE);

    // start thread, widgets are ref'd because the dialog can close before the test ends
    struct TestRunnerData *req = g_malloc0(sizeof(struct TestRunnerData));
    req->proxy_id = px->id;
    req->host = g_strdup(t_host);
    req->port = (uint16_t)t_port;
    req->buffer = g_object_ref(info->output_buffer);
    req->btn = g_object_ref(info->test_btn);

    GThread *thread = g_thread_new("test_conn", run_test_thread, req);
    g_thread_unref(thread);
}

// ---- list ----

static void refresh_proxy_store(ConfigInfo *info) {
    gtk_list_store_clear(info->store);
    for (GList *l = g_proxies_list; l != NULL; l = l->next) {
        ProxyData *p = (ProxyData *)l->data;
        char *addr = g_strdup_printf("%s:%u", p->host, p->port);
        bool is_def = g_default_proxy && p->name && strcmp(g_default_proxy, p->name) == 0;
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

// add/edit dialog. existing == NULL adds a new one. returns the proxy that was saved or NULL
static ProxyData *proxy_edit_dialog(GtkWindow *parent, ProxyData *existing) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons(existing ? "Edit Proxy" : "Add Proxy",
                                         parent,
                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                         "Cancel", GTK_RESPONSE_CANCEL,
                                         "Save", GTK_RESPONSE_ACCEPT,
                                         NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 420, -1);
    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
    gtk_box_pack_start(GTK_BOX(content_area), grid, TRUE, TRUE, 0);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Name:"), 0, 0, 1, 1);
    GtkWidget *name_entry = gtk_entry_new();
    gtk_widget_set_hexpand(name_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), name_entry, 1, 0, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Type:"), 0, 1, 1, 1);
    GtkWidget *type_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(type_combo), "HTTP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(type_combo), "SOCKS5");
    gtk_combo_box_set_active(GTK_COMBO_BOX(type_combo), 1);
    gtk_grid_attach(GTK_GRID(grid), type_combo, 1, 1, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Host:"), 0, 2, 1, 1);
    GtkWidget *ip_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), ip_entry, 1, 2, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Port:"), 0, 3, 1, 1);
    GtkWidget *port_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), port_entry, 1, 3, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Username:"), 0, 4, 1, 1);
    GtkWidget *user_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), user_entry, 1, 4, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Password:"), 0, 5, 1, 1);
    GtkWidget *pass_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(pass_entry), FALSE);
    gtk_grid_attach(GTK_GRID(grid), pass_entry, 1, 5, 1, 1);

    GtkWidget *err_label = gtk_label_new("");
    gtk_widget_set_halign(err_label, GTK_ALIGN_START);
    gtk_label_set_line_wrap(GTK_LABEL(err_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(err_label), 0);
    gtk_grid_attach(GTK_GRID(grid), err_label, 0, 6, 2, 1);

    if (existing) {
        gtk_entry_set_text(GTK_ENTRY(name_entry), existing->name);
        gtk_combo_box_set_active(GTK_COMBO_BOX(type_combo), existing->type == PROXY_TYPE_HTTP ? 0 : 1);
        gtk_entry_set_text(GTK_ENTRY(ip_entry), existing->host);
        if (existing->port != 0) {
            char port_str[16];
            snprintf(port_str, sizeof(port_str), "%u", existing->port);
            gtk_entry_set_text(GTK_ENTRY(port_entry), port_str);
        }
        gtk_entry_set_text(GTK_ENTRY(user_entry), existing->username ? existing->username : "");
        gtk_entry_set_text(GTK_ENTRY(pass_entry), existing->password ? existing->password : "");
    } else if (!g_proxies_list) {
        gtk_entry_set_text(GTK_ENTRY(name_entry), "default");
    }

    gtk_widget_show_all(dialog);

    ProxyData *result = NULL;
    while (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *name = gtk_entry_get_text(GTK_ENTRY(name_entry));
        const char *ip_text = gtk_entry_get_text(GTK_ENTRY(ip_entry));
        const char *port_text = gtk_entry_get_text(GTK_ENTRY(port_entry));
        const char *user = gtk_entry_get_text(GTK_ENTRY(user_entry));
        const char *pass = gtk_entry_get_text(GTK_ENTRY(pass_entry));
        ProxyType type = (gtk_combo_box_get_active(GTK_COMBO_BOX(type_combo)) == 0) ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
        int port = 0;

        char *name_t = g_strstrip(g_strdup(name));
        char *host_t = g_strstrip(g_strdup(ip_text));
        const char *msg = NULL;

        if (name_t[0] == '\0') msg = "Name cannot be empty.";
        else if (find_proxy_by_name(name_t) && find_proxy_by_name(name_t) != existing) msg = "A proxy with this name already exists.";
        else if (host_t[0] == '\0') msg = "Host (IP/Domain) cannot be empty.";
        else if (!port_text_valid(port_text, &port)) msg = "Port must be a number between 1 and 65535.";

        if (msg) {
            gtk_label_set_markup(GTK_LABEL(err_label), "");
            char *esc = g_markup_printf_escaped("<span foreground='#e5534b'>%s</span>", msg);
            gtk_label_set_markup(GTK_LABEL(err_label), esc);
            g_free(esc);
            g_free(name_t); g_free(host_t);
            continue;
        }

        // library validates too (and keeps the proxy list in sync)
        char err[256] = "";
        uint32_t id = existing ? existing->id : 0;
        bool ok;
        if (id != 0) {
            ok = ProxyBridge_EditProxy(id, name_t, type, host_t, (uint16_t)port, user, pass, err, sizeof(err));
        } else {
            id = ProxyBridge_AddProxy(name_t, type, host_t, (uint16_t)port, user, pass, err, sizeof(err));
            ok = (id != 0);
        }
        if (!ok) {
            char *esc = g_markup_printf_escaped("<span foreground='#e5534b'>%s</span>", err[0] ? err : "Engine rejected the proxy settings.");
            gtk_label_set_markup(GTK_LABEL(err_label), esc);
            g_free(esc);
            g_free(name_t); g_free(host_t);
            continue;
        }

        ProxyData *p = existing;
        if (!p) {
            p = g_malloc0(sizeof(ProxyData));
            g_proxies_list = g_list_append(g_proxies_list, p);
        } else if (p->name && strcmp(p->name, name_t) != 0) {
            // renamed, keep default and rules pointing at it
            if (g_default_proxy && strcmp(g_default_proxy, p->name) == 0) {
                g_free(g_default_proxy);
                g_default_proxy = g_strdup(name_t);
            }
            for (GList *l = g_rules_list; l != NULL; l = l->next) {
                RuleData *r = (RuleData *)l->data;
                if (r->proxy_name && strcmp(r->proxy_name, p->name) == 0) {
                    g_free(r->proxy_name);
                    r->proxy_name = g_strdup(name_t);
                }
            }
        }
        p->id = id;
        g_free(p->name); p->name = name_t;
        g_free(p->host); p->host = host_t;
        g_free(p->username); p->username = g_strdup(user);
        if (p->password) memset(p->password, 0, strlen(p->password));
        g_free(p->password); p->password = g_strdup(pass);
        p->type = type;
        p->port = (uint16_t)port;

        // first proxy becomes the default
        if (!g_default_proxy || !find_proxy_by_name(g_default_proxy)) {
            g_free(g_default_proxy);
            g_default_proxy = g_strdup(p->name);
            ProxyBridge_SetDefaultProxy(p->id);
        }
        result = p;
        break;
    }

    gtk_widget_destroy(dialog);
    return result;
}

static void on_proxy_add(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;
    ProxyData *p = proxy_edit_dialog(GTK_WINDOW(info->dialog), NULL);
    if (!p) return;
    save_config();
    refresh_proxy_store(info);
    select_proxy_row(info, p);
}

static void on_proxy_edit(GtkWidget *widget, gpointer data) {
    ConfigInfo *info = (ConfigInfo *)data;
    ProxyData *sel = get_selected_proxy(info);
    if (!sel) {
        show_message(GTK_WINDOW(info->dialog), GTK_MESSAGE_WARNING, "Select a proxy first.");
        return;
    }
    ProxyData *p = proxy_edit_dialog(GTK_WINDOW(info->dialog), sel);
    if (!p) return;
    save_config();
    refresh_proxy_store(info);
    select_proxy_row(info, p);
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

    GtkWidget *q = gtk_message_dialog_new(GTK_WINDOW(info->dialog), GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION,
                                          GTK_BUTTONS_YES_NO, "Delete proxy '%s'?\nRules using it will fall back to the default proxy.", p->name);
    int resp = gtk_dialog_run(GTK_DIALOG(q));
    gtk_widget_destroy(q);
    if (resp != GTK_RESPONSE_YES) return;

    if (p->id != 0) ProxyBridge_DeleteProxy(p->id);

    // rules that used it now use the default proxy (library does the same)
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        RuleData *r = (RuleData *)l->data;
        if (r->proxy_name && strcmp(r->proxy_name, p->name) == 0) {
            g_free(r->proxy_name);
            r->proxy_name = NULL;
        }
    }

    bool was_default = g_default_proxy && strcmp(g_default_proxy, p->name) == 0;
    g_proxies_list = g_list_remove(g_proxies_list, p);
    free_proxy_data(p);

    if (was_default) {
        g_free(g_default_proxy);
        g_default_proxy = g_proxies_list ? g_strdup(((ProxyData *)g_proxies_list->data)->name) : NULL;
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
    g_free(g_default_proxy);
    g_default_proxy = g_strdup(p->name);
    ProxyBridge_SetDefaultProxy(p->id);
    save_config();
    refresh_proxy_store(info);
    select_proxy_row(info, p);

    char *status_msg = g_strdup_printf("Default proxy: %s (%s:%u)", p->name, p->host, p->port);
    gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, status_msg);
    g_free(status_msg);
}

void on_proxy_configure(GtkWidget *widget, gpointer data) {
    ConfigInfo info;
    memset(&info, 0, sizeof(info));

    GtkWidget *content_area;
    GtkWidget *grid;

    info.dialog = gtk_dialog_new_with_buttons("Proxy Settings",
                                         GTK_WINDOW(window),
                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                         "Close", GTK_RESPONSE_CLOSE,
                                         NULL);
    // wider window
    gtk_window_set_default_size(GTK_WINDOW(info.dialog), 650, 560);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG(info.dialog));
    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
    gtk_box_pack_start(GTK_BOX(content_area), grid, TRUE, TRUE, 0);

    // proxy list
    info.store = gtk_list_store_new(N_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
    info.tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(info.store));
    g_object_unref(info.store); // tree holds it now
    const char *titles[] = {"Name", "Type", "Host:Port", "Auth", "Default"};
    for (int i = 0; i < 5; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(titles[i], r, "text", i, NULL);
        gtk_tree_view_column_set_resizable(c, TRUE);
        if (i == 2) gtk_tree_view_column_set_expand(c, TRUE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(info.tree), c);
    }
    g_signal_connect(info.tree, "row-activated", G_CALLBACK(on_proxy_row_activated), &info);
    GtkWidget *tree_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(tree_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(tree_scroll, -1, 180);
    gtk_widget_set_hexpand(tree_scroll, TRUE);
    gtk_widget_set_vexpand(tree_scroll, TRUE);
    gtk_container_add(GTK_CONTAINER(tree_scroll), info.tree);
    gtk_grid_attach(GTK_GRID(grid), tree_scroll, 0, 0, 4, 1);

    // list buttons
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *add_btn = gtk_button_new_with_label("Add");
    GtkWidget *edit_btn = gtk_button_new_with_label("Edit");
    GtkWidget *del_btn = gtk_button_new_with_label("Delete");
    GtkWidget *def_btn = gtk_button_new_with_label("Set Default");
    g_signal_connect(add_btn, "clicked", G_CALLBACK(on_proxy_add), &info);
    g_signal_connect(edit_btn, "clicked", G_CALLBACK(on_proxy_edit), &info);
    g_signal_connect(del_btn, "clicked", G_CALLBACK(on_proxy_delete), &info);
    g_signal_connect(def_btn, "clicked", G_CALLBACK(on_proxy_set_default), &info);
    gtk_box_pack_start(GTK_BOX(btn_box), add_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), edit_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), del_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), def_btn, FALSE, FALSE, 0);
    gtk_grid_attach(GTK_GRID(grid), btn_box, 0, 1, 4, 1);

    // test section
    gtk_grid_attach(GTK_GRID(grid), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), 0, 2, 4, 1);

    GtkWidget *test_label = gtk_label_new("<b>Test Selected Proxy</b>");
    gtk_label_set_use_markup(GTK_LABEL(test_label), TRUE);
    gtk_widget_set_halign(test_label, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), test_label, 0, 3, 4, 1);

    // target
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Target:"), 0, 4, 1, 1);
    info.test_host = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(info.test_host), "google.com");
    gtk_widget_set_hexpand(info.test_host, TRUE);
    gtk_grid_attach(GTK_GRID(grid), info.test_host, 1, 4, 1, 1);

    // target port
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Port:"), 2, 4, 1, 1);
    info.test_port = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(info.test_port), "80");
    gtk_widget_set_size_request(info.test_port, 80, -1);
    gtk_grid_attach(GTK_GRID(grid), info.test_port, 3, 4, 1, 1);

    // test button
    info.test_btn = gtk_button_new_with_label("Start Test");
    g_signal_connect(info.test_btn, "clicked", G_CALLBACK(on_start_test_clicked), &info);
    gtk_grid_attach(GTK_GRID(grid), info.test_btn, 0, 5, 4, 1);

    // output log
    GtkWidget *out_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(out_scroll, -1, 150);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(out_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

    GtkWidget *out_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(out_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(out_view), TRUE);
    info.output_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(out_view));

    gtk_container_add(GTK_CONTAINER(out_scroll), out_view);
    gtk_grid_attach(GTK_GRID(grid), out_scroll, 0, 6, 4, 1);

    refresh_proxy_store(&info);
    if (g_proxies_list) select_proxy_row(&info, find_proxy_by_name(g_default_proxy) ? find_proxy_by_name(g_default_proxy) : (ProxyData *)g_proxies_list->data);

    gtk_widget_show_all(info.dialog);
    gtk_dialog_run(GTK_DIALOG(info.dialog));
    gtk_widget_destroy(info.dialog);
}

// ---- profiles ----

static void update_profile_ui() {
    char *title = g_strdup_printf("ProxyBridge - %s", g_active_profile ? g_active_profile : "");
    gtk_window_set_title(GTK_WINDOW(window), title);
    g_free(title);
    char *msg = g_strdup_printf("Active profile: %s", g_active_profile ? g_active_profile : "");
    gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, msg);
    g_free(msg);
}

// push the active profile to the running engine: no Stop/Start needed
static void reapply_active_profile() {
    ProxyBridge_ClearRules();
    ProxyBridge_ClearProxies();
    apply_proxies_to_lib();
    apply_rules_to_lib();
    save_config();
    refresh_rules_window();
    update_profile_ui();
}

typedef struct {
    GtkWidget *dialog;
    GtkWidget *tree;
    GtkListStore *store;
} ProfilesInfo;

static void refresh_profile_store(ProfilesInfo *pi) {
    gtk_list_store_clear(pi->store);
    for (GList *l = g_profiles; l != NULL; l = l->next) {
        Profile *p = (Profile *)l->data;
        bool act = g_active_profile && strcmp(p->name, g_active_profile) == 0;
        GtkTreeIter iter;
        gtk_list_store_append(pi->store, &iter);
        gtk_list_store_set(pi->store, &iter, 0, p->name, 1, act ? "Active" : "", -1);
    }
}

// name of the selected row, caller frees
static char *selected_profile_name(ProfilesInfo *pi) {
    GtkTreeModel *model;
    GtkTreeIter iter;
    if (!gtk_tree_selection_get_selected(gtk_tree_view_get_selection(GTK_TREE_VIEW(pi->tree)), &model, &iter)) return NULL;
    char *name = NULL;
    gtk_tree_model_get(model, &iter, 0, &name, -1);
    return name;
}

// asks for a profile name, returns NULL on cancel. caller frees
static char *ask_profile_name(GtkWindow *parent, const char *title, const char *initial) {
    GtkWidget *d = gtk_dialog_new_with_buttons(title, parent, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                               "Cancel", GTK_RESPONSE_CANCEL, "OK", GTK_RESPONSE_ACCEPT, NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_entry_set_text(GTK_ENTRY(entry), initial ? initial : "");
    gtk_box_pack_start(GTK_BOX(box), gtk_label_new("Profile name:"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box), entry, FALSE, FALSE, 5);
    gtk_dialog_set_default_response(GTK_DIALOG(d), GTK_RESPONSE_ACCEPT);
    gtk_widget_show_all(d);

    char *result = NULL;
    while (gtk_dialog_run(GTK_DIALOG(d)) == GTK_RESPONSE_ACCEPT) {
        char *name = g_strstrip(g_strdup(gtk_entry_get_text(GTK_ENTRY(entry))));
        if (name[0] == '\0') {
            show_message(GTK_WINDOW(d), GTK_MESSAGE_ERROR, "Profile name cannot be empty.");
        } else if (profile_find(name) && !(initial && strcmp(initial, name) == 0)) {
            show_message(GTK_WINDOW(d), GTK_MESSAGE_ERROR, "A profile with this name already exists.");
        } else {
            result = name;
            break;
        }
        g_free(name);
    }
    gtk_widget_destroy(d);
    return result;
}

static void do_switch(ProfilesInfo *pi, const char *name) {
    if (!name || (g_active_profile && strcmp(name, g_active_profile) == 0)) return;
    if (!profile_activate(name)) return;
    reapply_active_profile();
    refresh_profile_store(pi);
}

static void on_profile_switch(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *name = selected_profile_name(pi);
    if (name) do_switch(pi, name);
    g_free(name);
}

static void on_profile_new(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *name = ask_profile_name(GTK_WINDOW(pi->dialog), "New Profile", "");
    if (!name) return;
    if (profile_create(name, false)) { save_config(); refresh_profile_store(pi); }
    g_free(name);
}

static void on_profile_duplicate(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *src = selected_profile_name(pi);
    if (!src) return;
    // duplicates the selected profile: make it active data-wise only for the copy, then switch back
    char *initial = g_strdup_printf("%s copy", src);
    char *name = ask_profile_name(GTK_WINDOW(pi->dialog), "Duplicate Profile", initial);
    g_free(initial);
    if (name) {
        char *prev = g_strdup(g_active_profile);
        if (profile_activate(src)) {
            profile_create(name, true);
            profile_activate(prev); // library state was never touched
            save_config();
            refresh_profile_store(pi);
        }
        g_free(prev);
    }
    g_free(name);
    g_free(src);
}

static void on_profile_rename(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *old = selected_profile_name(pi);
    if (!old) return;
    char *name = ask_profile_name(GTK_WINDOW(pi->dialog), "Rename Profile", old);
    if (name && profile_rename(profile_find(old), name)) {
        save_config();
        refresh_profile_store(pi);
        update_profile_ui();
    }
    g_free(name);
    g_free(old);
}

static void on_profile_delete(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *name = selected_profile_name(pi);
    if (!name) return;
    if (!g_profiles || !g_profiles->next) {
        show_message(GTK_WINDOW(pi->dialog), GTK_MESSAGE_WARNING, "The last profile cannot be deleted.");
        g_free(name);
        return;
    }
    GtkWidget *q = gtk_message_dialog_new(GTK_WINDOW(pi->dialog), GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION,
                                          GTK_BUTTONS_YES_NO, "Delete profile '%s' with all its proxies and rules?", name);
    int resp = gtk_dialog_run(GTK_DIALOG(q));
    gtk_widget_destroy(q);
    if (resp == GTK_RESPONSE_YES) {
        bool was_active = g_active_profile && strcmp(g_active_profile, name) == 0;
        if (profile_delete(profile_find(name))) {
            if (was_active) reapply_active_profile();
            else save_config();
            refresh_profile_store(pi);
        }
    }
    g_free(name);
}

static void on_profile_row_activated(GtkTreeView *tree, GtkTreePath *path, GtkTreeViewColumn *col, gpointer data) {
    on_profile_switch(NULL, data);
}

void on_profiles_clicked(GtkWidget *widget, gpointer data) {
    ProfilesInfo pi;
    memset(&pi, 0, sizeof(pi));
    pi.dialog = gtk_dialog_new_with_buttons("Profiles", GTK_WINDOW(window), GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                            "Close", GTK_RESPONSE_CLOSE, NULL);
    gtk_window_set_default_size(GTK_WINDOW(pi.dialog), 420, 360);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(pi.dialog));
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);

    pi.store = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
    pi.tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(pi.store));
    g_object_unref(pi.store);
    const char *titles[] = {"Profile", "Status"};
    for (int i = 0; i < 2; i++) {
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(titles[i], gtk_cell_renderer_text_new(), "text", i, NULL);
        if (i == 0) gtk_tree_view_column_set_expand(c, TRUE);
        gtk_tree_view_append_column(GTK_TREE_VIEW(pi.tree), c);
    }
    g_signal_connect(pi.tree, "row-activated", G_CALLBACK(on_profile_row_activated), &pi);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), pi.tree);
    gtk_box_pack_start(GTK_BOX(box), scroll, TRUE, TRUE, 0);

    GtkWidget *btns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    const char *labels[] = {"Switch", "New", "Duplicate", "Rename", "Delete"};
    void (*cbs[])(GtkWidget *, gpointer) = {on_profile_switch, on_profile_new, on_profile_duplicate, on_profile_rename, on_profile_delete};
    for (int i = 0; i < 5; i++) {
        GtkWidget *b = gtk_button_new_with_label(labels[i]);
        g_signal_connect(b, "clicked", G_CALLBACK(cbs[i]), &pi);
        gtk_box_pack_start(GTK_BOX(btns), b, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(box), btns, FALSE, FALSE, 5);

    refresh_profile_store(&pi);
    gtk_widget_show_all(pi.dialog);
    gtk_dialog_run(GTK_DIALOG(pi.dialog));
    gtk_widget_destroy(pi.dialog);
}
