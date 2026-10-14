#include "gui.h"

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
    char result[4096];
} TestJob;

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

static gboolean on_test_done(gpointer user_data) {
    TestJob *job = (TestJob *)user_data;
    char *text = g_utf8_make_valid(job->result, -1);
    gtk_text_buffer_set_text(job->buffer, text, -1);
    gtk_widget_set_sensitive(job->btn, TRUE);
    g_free(text);
    g_object_unref(job->buffer);
    g_object_unref(job->btn);
    g_free(job->host);
    g_free(job);
    return FALSE;
}

static gpointer run_test_thread(gpointer user_data) {
    TestJob *job = (TestJob *)user_data;
    ProxyBridge_TestProxy(job->proxy_id, job->host, job->port, job->result, sizeof(job->result));
    job->result[sizeof(job->result) - 1] = '\0';
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

    gtk_text_buffer_set_text(info->output_buffer, "Testing connection... Please wait...", -1);
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
    GtkWidget *err_label = hint_label("");
    gtk_grid_attach(GTK_GRID(grid), err_label, 0, 6, 2, 1);

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
            if (!ok) msg = err[0] ? err : "Engine rejected the proxy settings.";
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
    for (int i = 0; i < 4; i++) {
        GtkWidget *b = gtk_button_new_with_label(labels[i]);
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

    info.test_btn = gtk_button_new_with_label("Start Test");
    g_signal_connect(info.test_btn, "clicked", G_CALLBACK(on_start_test_clicked), &info);
    gtk_grid_attach(GTK_GRID(grid), info.test_btn, 0, 5, 4, 1);

    GtkWidget *out_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(out_scroll, -1, 150);
    GtkWidget *out_view = gtk_text_view_new();
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

typedef struct {
    GtkWidget *dialog;
    GtkWidget *tree;
    GtkListStore *store;
} ProfilesInfo;

static void update_profile_ui() {
    char *title = g_strdup_printf("ProxyBridge - %s", g_active_profile);
    gtk_window_set_title(GTK_WINDOW(window), title);
    g_free(title);
    title = g_strdup_printf("Active profile: %s", g_active_profile);
    gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, title);
    g_free(title);
}

// engine keeps running, only its proxies and rules are replaced
static void reapply_active_profile() {
    ProxyBridge_ClearRules();
    apply_proxies_to_lib();
    apply_rules_to_lib();
    save_config();
    refresh_rules_window();
    update_profile_ui();
}

static void refresh_profile_store(ProfilesInfo *pi) {
    gtk_list_store_clear(pi->store);
    for (GList *l = g_profiles; l != NULL; l = l->next) {
        Profile *p = (Profile *)l->data;
        GtkTreeIter iter;
        gtk_list_store_append(pi->store, &iter);
        gtk_list_store_set(pi->store, &iter, 0, p->name, 1, strcmp(p->name, g_active_profile) == 0 ? "Active" : "", -1);
    }
}

static char *selected_profile_name(ProfilesInfo *pi) {
    GtkTreeModel *model;
    GtkTreeIter iter;
    char *name = NULL;
    if (gtk_tree_selection_get_selected(gtk_tree_view_get_selection(GTK_TREE_VIEW(pi->tree)), &model, &iter))
        gtk_tree_model_get(model, &iter, 0, &name, -1);
    return name;
}

// NULL on cancel
static char *ask_profile_name(GtkWindow *parent, const char *title, const char *initial) {
    GtkWidget *d = gtk_dialog_new_with_buttons(title, parent, GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                               "Cancel", GTK_RESPONSE_CANCEL, "OK", GTK_RESPONSE_ACCEPT, NULL);
    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gtk_container_set_border_width(GTK_CONTAINER(box), 10);
    GtkWidget *entry = gtk_entry_new();
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

static void on_profile_switch(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *name = selected_profile_name(pi);
    if (name && strcmp(name, g_active_profile) != 0 && profile_activate(name)) {
        reapply_active_profile();
        refresh_profile_store(pi);
    }
    g_free(name);
}

static void on_profile_new(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *name = ask_profile_name(GTK_WINDOW(pi->dialog), "New Profile", "");
    if (name && profile_create(name, false)) {
        save_config();
        refresh_profile_store(pi);
    }
    g_free(name);
}

static void on_profile_duplicate(GtkWidget *widget, gpointer data) {
    ProfilesInfo *pi = (ProfilesInfo *)data;
    char *src = selected_profile_name(pi);
    if (!src) return;
    char *initial = g_strdup_printf("%s copy", src);
    char *name = ask_profile_name(GTK_WINDOW(pi->dialog), "Duplicate Profile", initial);
    char *prev = g_strdup(g_active_profile);
    // copies the active profile, so make the source active for a moment (library state is untouched)
    if (name && profile_activate(src)) {
        profile_create(name, true);
        profile_activate(prev);
        save_config();
        refresh_profile_store(pi);
    }
    g_free(prev); g_free(initial); g_free(name); g_free(src);
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
    if (!g_profiles->next) {
        show_message(GTK_WINDOW(pi->dialog), GTK_MESSAGE_WARNING, "The last profile cannot be deleted.");
    } else if (confirm(GTK_WINDOW(pi->dialog), "Delete profile '%s' with all its proxies and rules?", name)) {
        bool was_active = strcmp(g_active_profile, name) == 0;
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
    ProfilesInfo pi = {0};
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
        gtk_tree_view_column_set_expand(c, i == 0);
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
