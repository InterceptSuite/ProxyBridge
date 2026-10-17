#include "gui.h"

static GtkWidget *rules_window = NULL;
static GtkWidget *rules_list_box = NULL;
static GtkWidget *btn_select_all_header = NULL;

static void refresh_rules_ui();

void free_rule_data(RuleData *rule) {
    if (!rule) return;
    g_free(rule->process_name);
    g_free(rule->target_hosts);
    g_free(rule->target_ports);
    g_free(rule->proxy_name);
    g_free(rule);
}

static GtkWindow *parent_window() {
    return GTK_WINDOW(rules_window ? rules_window : window);
}

// position in the library list, rules it rejected (id 0) are not in it
static int lib_index_of(RuleData *rule) {
    int idx = 0;
    for (GList *l = g_rules_list; l != NULL && l->data != rule; l = l->next)
        if (((RuleData *)l->data)->id != 0) idx++;
    return idx;
}

static uint32_t rule_proxy_id(RuleAction action, const char *proxy_name) {
    return action == RULE_ACTION_PROXY ? resolve_proxy_id(proxy_name) : 0;
}

void apply_rules_to_lib() {
    int n = 1;
    for (GList *l = g_rules_list; l != NULL; l = l->next, n++) {
        RuleData *r = (RuleData *)l->data;
        char err[256] = "";
        r->id = ProxyBridge_AddRule(r->process_name, r->target_hosts, r->target_ports, r->protocol, r->action,
                                    rule_proxy_id(r->action, r->proxy_name), err, sizeof(err));
        if (r->id == 0) gui_log("Rule #%d (%s) not loaded: %s", n, r->process_name, err[0] ? err : "rejected");
        else if (!r->enabled) ProxyBridge_DisableRule(r->id);
    }
}

static void on_rule_delete(GtkWidget *widget, gpointer data) {
    RuleData *rule = (RuleData *)data;
    if (rule->id != 0) ProxyBridge_DeleteRule(rule->id);
    g_rules_list = g_list_remove(g_rules_list, rule);
    free_rule_data(rule);
    save_config();
    refresh_rules_ui();
}

static void on_rule_toggle(GtkToggleButton *btn, gpointer data) {
    RuleData *rule = (RuleData *)data;
    rule->enabled = gtk_toggle_button_get_active(btn);
    if (rule->id != 0) {
        if (rule->enabled) ProxyBridge_EnableRule(rule->id);
        else ProxyBridge_DisableRule(rule->id);
    }
    save_config();
}

static void on_rule_move(RuleData *rule, int dir) {
    GList *link = g_list_find(g_rules_list, rule);
    GList *other = link ? (dir < 0 ? link->prev : link->next) : NULL;
    if (!other) return;

    // swap payloads so the list head stays valid
    link->data = other->data;
    other->data = rule;

    if (rule->id != 0 && !ProxyBridge_MoveRule(rule->id, lib_index_of(rule)))
        gui_log("Could not reorder rule %u in the engine", rule->id);
    save_config();
    refresh_rules_ui();
}

static void on_rule_move_up(GtkWidget *widget, gpointer data) { on_rule_move((RuleData *)data, -1); }
static void on_rule_move_down(GtkWidget *widget, gpointer data) { on_rule_move((RuleData *)data, 1); }

static void on_browse_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Application", NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
                                      "_Cancel", GTK_RESPONSE_CANCEL, "_Select", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if (filename) {
            char *base = g_path_get_basename(filename);
            gtk_entry_set_text(GTK_ENTRY(data), base);
            g_free(base);
            g_free(filename);
        }
    }
    gtk_widget_destroy(dialog);
}

static void on_action_changed(GtkComboBox *combo, gpointer data) {
    gtk_widget_set_sensitive(GTK_WIDGET(data), gtk_combo_box_get_active(combo) == RULE_ACTION_PROXY);
}

static void set_str(char **dst, const char *src) {
    g_free(*dst);
    *dst = g_strdup(src);
}

// returns the saved rule, NULL while the engine rejects it (err filled)
static RuleData *save_rule(RuleData *rule, const char *proc, const char *hosts, const char *ports,
                           RuleProtocol proto, RuleAction action, const char *proxy_name, char *err, size_t err_size) {
    if (!ProxyBridge_ValidateRule(proc, hosts, ports, err, err_size)) return NULL;
    uint32_t pid = rule_proxy_id(action, proxy_name);

    if (rule && rule->id != 0) {
        if (!ProxyBridge_EditRule(rule->id, proc, hosts, ports, proto, action, pid, err, err_size)) return NULL;
    } else {
        // new rule, or one the engine rejected at load time
        uint32_t id = ProxyBridge_AddRule(proc, hosts, ports, proto, action, pid, err, err_size);
        if (id == 0) return NULL;
        if (rule && !rule->enabled) ProxyBridge_DisableRule(id);
        if (!rule) {
            rule = g_malloc0(sizeof(RuleData));
            rule->enabled = true;
            g_rules_list = g_list_append(g_rules_list, rule);
        }
        rule->id = id;
        ProxyBridge_MoveRule(id, lib_index_of(rule));
    }
    set_str(&rule->process_name, proc);
    set_str(&rule->target_hosts, hosts);
    set_str(&rule->target_ports, ports);
    set_str(&rule->proxy_name, proxy_name);
    rule->protocol = proto;
    rule->action = action;
    return rule;
}

static void open_rule_dialog(RuleData *rule) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons(rule ? "Edit Rule" : "Add Rule", parent_window(),
                                                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                                    "Cancel", GTK_RESPONSE_CANCEL, "Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 500, 400);
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 15);

    GtkWidget *proc_entry = gtk_entry_new();
    GtkWidget *browse_btn = gtk_button_new_with_label("Browse...");
    g_signal_connect(browse_btn, "clicked", G_CALLBACK(on_browse_clicked), proc_entry);
    GtkWidget *proc_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(proc_box), proc_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(proc_box), browse_btn, FALSE, FALSE, 0);

    // Target Host: multiline for long lists. Line breaks are only for readability and are stripped before
    // the text reaches the engine; ';' stays the separator.
    GtkWidget *host_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(host_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_accepts_tab(GTK_TEXT_VIEW(host_view), FALSE);
    GtkWidget *host_entry = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(host_entry), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(host_entry), GTK_SHADOW_IN);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(host_entry), 90);
    gtk_container_add(GTK_CONTAINER(host_entry), host_view);
    GtkWidget *port_entry = gtk_entry_new();
    GtkWidget *proto_combo = combo_new("TCP", "UDP", "BOTH", NULL);
    GtkWidget *action_combo = combo_new("PROXY", "DIRECT", "BLOCK", NULL);

    // entry 0 = default proxy, then one per proxy in g_proxies_list order
    GtkWidget *proxy_combo = combo_new("Default proxy", NULL);
    int proxy_sel = 0, pi = 1;
    for (GList *l = g_proxies_list; l != NULL; l = l->next, pi++) {
        ProxyData *p = (ProxyData *)l->data;
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(proxy_combo), p->name);
        if (rule && rule->proxy_name && strcmp(rule->proxy_name, p->name) == 0) proxy_sel = pi;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(proxy_combo), proxy_sel);
    g_signal_connect(action_combo, "changed", G_CALLBACK(on_action_changed), proxy_combo);

    gtk_entry_set_text(GTK_ENTRY(proc_entry), rule ? rule->process_name : "");
    {
        char *shown = list_format(rule && rule->target_hosts && *rule->target_hosts ? rule->target_hosts : "*");
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(host_view)), shown, -1);
        g_free(shown);
    }
    gtk_entry_set_text(GTK_ENTRY(port_entry), rule ? rule->target_ports : "*");
    gtk_combo_box_set_active(GTK_COMBO_BOX(proto_combo), rule ? (int)rule->protocol : RULE_PROTOCOL_BOTH);
    gtk_combo_box_set_active(GTK_COMBO_BOX(action_combo), rule ? (int)rule->action : RULE_ACTION_PROXY);

    GtkWidget *err_label = hint_label("");
    grid_row(grid, 0, "Process Name:", proc_box);
    gtk_grid_attach(GTK_GRID(grid), hint_label("Example: firefox; chrome; /usr/bin/wget"), 1, 1, 1, 1);
    grid_row(grid, 2, "Target Host:", host_entry);
    gtk_grid_attach(GTK_GRID(grid), hint_label("Example: 192.168.1.*; 10.0.0.0/8; 10.0.0.1-10.0.0.50; github.com; *.github.com; * (domains are matched via DNS answers). Long lists are fine; line breaks are for readability only, separate entries with ;"), 1, 3, 1, 1);
    grid_row(grid, 4, "Target Port:", port_entry);
    gtk_grid_attach(GTK_GRID(grid), hint_label("Example: 80; 443; 8000-8080; *"), 1, 5, 1, 1);
    grid_row(grid, 6, "Protocol:", proto_combo);
    grid_row(grid, 7, "Action:", action_combo);
    grid_row(grid, 8, "Proxy:", proxy_combo);
    gtk_grid_attach(GTK_GRID(grid), err_label, 0, 9, 2, 1);
    gtk_container_add(GTK_CONTAINER(gtk_dialog_get_content_area(GTK_DIALOG(dialog))), grid);
    gtk_widget_show_all(dialog);
    on_action_changed(GTK_COMBO_BOX(action_combo), proxy_combo);

    bool saved = false;
    while (!saved && gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        int proto = gtk_combo_box_get_active(GTK_COMBO_BOX(proto_combo));
        int action = gtk_combo_box_get_active(GTK_COMBO_BOX(action_combo));
        int psel = gtk_combo_box_get_active(GTK_COMBO_BOX(proxy_combo));
        ProxyData *pd = (action == RULE_ACTION_PROXY && psel > 0) ? g_list_nth_data(g_proxies_list, psel - 1) : NULL;
        char err[256] = "";

        GtkTextBuffer *hbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(host_view));
        GtkTextIter hs, he;
        gtk_text_buffer_get_bounds(hbuf, &hs, &he);
        char *raw_hosts = gtk_text_buffer_get_text(hbuf, &hs, &he, FALSE);
        char *clean_hosts = list_normalize(raw_hosts);
        g_free(raw_hosts);

        saved = save_rule(rule, gtk_entry_get_text(GTK_ENTRY(proc_entry)), clean_hosts,
                          gtk_entry_get_text(GTK_ENTRY(port_entry)), proto < 0 ? RULE_PROTOCOL_BOTH : (RuleProtocol)proto,
                          action < 0 ? RULE_ACTION_PROXY : (RuleAction)action, pd ? pd->name : NULL, err, sizeof(err)) != NULL;
        g_free(clean_hosts);
        if (saved) {
            save_config();
            refresh_rules_ui();
        } else {
            set_error_label(err_label, err[0] ? err : "Invalid rule.");
        }
    }
    gtk_widget_destroy(dialog);
}

static void on_rule_edit(GtkWidget *widget, gpointer data) {
    open_rule_dialog((RuleData *)data);
}

static void on_rule_add_clicked(GtkWidget *widget, gpointer data) {
    open_rule_dialog(NULL);
}

static bool all_rules_selected() {
    if (!g_rules_list) return false;
    for (GList *l = g_rules_list; l != NULL; l = l->next)
        if (!((RuleData *)l->data)->selected) return false;
    return true;
}

static void update_select_all_label() {
    if (btn_select_all_header)
        gtk_button_set_label(GTK_BUTTON(btn_select_all_header), all_rules_selected() ? "Deselect All" : "Select All");
}

static void on_rule_select_toggle(GtkToggleButton *btn, gpointer data) {
    ((RuleData *)data)->selected = gtk_toggle_button_get_active(btn);
    update_select_all_label();
}

static void on_rule_export_clicked(GtkWidget *widget, gpointer data) {
    bool any_selected = false;
    for (GList *l = g_rules_list; l != NULL; l = l->next) any_selected |= ((RuleData *)l->data)->selected;
    if (!any_selected) {
        show_message(parent_window(), GTK_MESSAGE_WARNING, "Please select at least one rule to export.");
        return;
    }
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Export Rules", parent_window(), GTK_FILE_CHOOSER_ACTION_SAVE,
                                                    "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "proxy_rules.json");
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char *json = rules_to_json(g_rules_list, true);
        GError *err = NULL;
        if (filename && g_file_set_contents(filename, json, -1, &err))
            show_message(parent_window(), GTK_MESSAGE_INFO, "Rules exported successfully.");
        else
            show_message(parent_window(), GTK_MESSAGE_ERROR, "Could not write %s: %s", filename ? filename : "file", err ? err->message : "unknown error");
        if (err) g_error_free(err);
        g_free(json);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

typedef struct {
    int imported, failed;
    GString *fail_msg;
} ImportCtx;

static void import_rule_cb(const RuleData *r, int index, void *ud) {
    ImportCtx *ctx = (ImportCtx *)ud;
    char err[256] = "";
    // unknown proxy name -> default proxy
    ProxyData *px = r->action == RULE_ACTION_PROXY ? find_proxy_by_name(r->proxy_name) : NULL;
    uint32_t id = r->process_name ? ProxyBridge_AddRule(r->process_name, r->target_hosts, r->target_ports, r->protocol,
                                                        r->action, px ? px->id : 0, err, sizeof(err)) : 0;
    if (id == 0) {
        ctx->failed++;
        if (ctx->fail_msg->len < 3000)
            g_string_append_printf(ctx->fail_msg, "Rule #%d (%s): %s\n", index, r->process_name ? r->process_name : "?",
                                   !r->process_name ? "missing processNames" : err[0] ? err : "rejected");
        return;
    }
    if (!r->enabled) ProxyBridge_DisableRule(id);
    RuleData *nd = g_malloc0(sizeof(RuleData));
    nd->id = id;
    nd->process_name = g_strdup(r->process_name);
    nd->target_hosts = g_strdup(r->target_hosts);
    nd->target_ports = g_strdup(r->target_ports);
    nd->protocol = r->protocol;
    nd->action = r->action;
    nd->enabled = r->enabled;
    nd->proxy_name = px ? g_strdup(px->name) : NULL;
    g_rules_list = g_list_append(g_rules_list, nd);
    ctx->imported++;
}

static void on_rule_import_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Import Rules", parent_window(), GTK_FILE_CHOOSER_ACTION_OPEN,
                                                    "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char *content = NULL;
        if (filename && g_file_get_contents(filename, &content, NULL, NULL)) {
            ImportCtx ctx = {0, 0, g_string_new("")};
            rules_from_json(content, import_rule_cb, &ctx);
            g_free(content);

            if (ctx.imported > 0) { save_config(); refresh_rules_ui(); }
            if (ctx.failed > 0)
                show_message(parent_window(), GTK_MESSAGE_WARNING, "Imported %d rules, %d failed validation and were skipped:\n\n%s",
                             ctx.imported, ctx.failed, ctx.fail_msg->str);
            else if (ctx.imported > 0)
                show_message(parent_window(), GTK_MESSAGE_INFO, "Imported %d rules.", ctx.imported);
            else
                show_message(parent_window(), GTK_MESSAGE_WARNING, "No rules found in the file.");
            g_string_free(ctx.fail_msg, TRUE);
        } else {
            show_message(parent_window(), GTK_MESSAGE_ERROR, "Could not read the selected file.");
        }
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_bulk_delete_clicked(GtkWidget *widget, gpointer data) {
    GList *l = g_rules_list;
    while (l != NULL) {
        GList *next = l->next;
        RuleData *rule = (RuleData *)l->data;
        if (rule->selected) {
            if (rule->id != 0) ProxyBridge_DeleteRule(rule->id);
            g_rules_list = g_list_delete_link(g_rules_list, l);
            free_rule_data(rule);
        }
        l = next;
    }
    save_config();
    refresh_rules_ui();
}

static void on_select_all_clicked(GtkWidget *widget, gpointer data) {
    bool new_state = !all_rules_selected();
    for (GList *l = g_rules_list; l != NULL; l = l->next) ((RuleData *)l->data)->selected = new_state;
    refresh_rules_ui();
}

static GtkWidget *header_label(const char *text, bool expand) {
    GtkWidget *l = gtk_label_new(text);
    gtk_widget_set_halign(l, GTK_ALIGN_START);
    gtk_widget_set_hexpand(l, expand);
    return l;
}

static GtkWidget *cell_label(const char *text) {
    GtkWidget *l = header_label(text, false);
    gtk_label_set_ellipsize(GTK_LABEL(l), PANGO_ELLIPSIZE_END);
    return l;
}

static GtkWidget *small_button(GtkWidget *box, const char *label, const char *tip, bool sensitive, GCallback cb, gpointer data) {
    GtkWidget *b = gtk_button_new_with_label(label);
    if (tip) gtk_widget_set_tooltip_text(b, tip);
    gtk_widget_set_sensitive(b, sensitive);
    g_signal_connect(b, "clicked", cb, data);
    gtk_box_pack_start(GTK_BOX(box), b, FALSE, FALSE, 0);
    return b;
}

static GtkWidget *check_cell(GtkWidget *grid, int row, int col, bool active, GCallback cb, gpointer data) {
    GtkWidget *c = gtk_check_button_new();
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(c), active);
    g_signal_connect(c, "toggled", cb, data);
    gtk_grid_attach(GTK_GRID(grid), c, col, row, 1, 1);
    return c;
}

static void refresh_rules_ui() {
    if (!rules_list_box) return;
    GList *children = gtk_container_get_children(GTK_CONTAINER(rules_list_box));
    for (GList *c = children; c != NULL; c = c->next) gtk_widget_destroy(GTK_WIDGET(c->data));
    g_list_free(children);
    update_select_all_label();

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 15);
    gtk_container_add(GTK_CONTAINER(rules_list_box), grid);

    const char *heads[] = {"  ", "Enable", "Actions", "SR", "Process", "Target Hosts", "Protocol", "Action", "Proxy"};
    for (int c = 0; c < 9; c++)
        gtk_grid_attach(GTK_GRID(grid), header_label(heads[c], c == 4 || c == 5), c, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), 0, 1, 9, 1);

    const char *proto_strs[] = {"TCP", "UDP", "BOTH"};
    const char *action_strs[] = {"PROXY", "DIRECT", "BLOCK"};
    const char *action_class[] = {"success", "info", "warning"};
    int row = 2, sr = 1;
    for (GList *l = g_rules_list; l != NULL; l = l->next, row += 2) {
        RuleData *r = (RuleData *)l->data;
        check_cell(grid, row, 0, r->selected, G_CALLBACK(on_rule_select_toggle), r);
        check_cell(grid, row, 1, r->enabled, G_CALLBACK(on_rule_toggle), r);

        // list position is the priority, first match wins
        GtkWidget *act_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
        small_button(act_box, "Edit", NULL, true, G_CALLBACK(on_rule_edit), r);
        small_button(act_box, "Delete", NULL, true, G_CALLBACK(on_rule_delete), r);
        small_button(act_box, "▲", "Move up (higher priority)", l->prev != NULL, G_CALLBACK(on_rule_move_up), r);
        small_button(act_box, "▼", "Move down (lower priority)", l->next != NULL, G_CALLBACK(on_rule_move_down), r);
        gtk_grid_attach(GTK_GRID(grid), act_box, 2, row, 1, 1);

        char sr_str[16];
        snprintf(sr_str, sizeof(sr_str), "%d", sr++);
        gtk_grid_attach(GTK_GRID(grid), gtk_label_new(sr_str), 3, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), cell_label(r->process_name), 4, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), cell_label(r->target_hosts), 5, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), gtk_label_new(proto_strs[r->protocol <= RULE_PROTOCOL_BOTH ? r->protocol : RULE_PROTOCOL_BOTH]), 6, row, 1, 1);

        int a = r->action <= RULE_ACTION_BLOCK ? r->action : RULE_ACTION_PROXY;
        GtkWidget *l_act = gtk_label_new(action_strs[a]);
        gtk_style_context_add_class(gtk_widget_get_style_context(l_act), action_class[a]);
        gtk_grid_attach(GTK_GRID(grid), l_act, 7, row, 1, 1);

        const char *proxy_txt = "-";
        if (r->action == RULE_ACTION_PROXY)
            proxy_txt = (r->proxy_name && find_proxy_by_name(r->proxy_name)) ? r->proxy_name : "default";
        gtk_grid_attach(GTK_GRID(grid), cell_label(proxy_txt), 8, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), 0, row + 1, 9, 1);
    }
    gtk_widget_show_all(rules_list_box);
}

void refresh_rules_window() {
    refresh_rules_ui();
}

static void on_rules_window_destroy(GtkWidget *widget, gpointer data) {
    rules_window = NULL;
    rules_list_box = NULL;
    btn_select_all_header = NULL;
}

void on_proxy_rules_clicked(GtkWidget *widget, gpointer data) {
    if (rules_window) {
        gtk_window_present(GTK_WINDOW(rules_window));
        return;
    }
    rules_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    g_signal_connect(rules_window, "destroy", G_CALLBACK(on_rules_window_destroy), NULL);
    gtk_window_set_title(GTK_WINDOW(rules_window), "Process Rules");
    gtk_window_set_default_size(GTK_WINDOW(rules_window), 1000, 500);
    gtk_window_set_transient_for(GTK_WINDOW(rules_window), GTK_WINDOW(window));
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 20);
    gtk_container_add(GTK_CONTAINER(rules_window), vbox);

    GtkWidget *header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='x-large' weight='bold'>Process Rules</span>");
    gtk_box_pack_start(GTK_BOX(header_box), title, FALSE, FALSE, 0);
    GtkWidget *spacer = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(header_box), spacer, TRUE, TRUE, 0);

    btn_select_all_header = gtk_button_new_with_label("Select All");
    GtkWidget *add_btn = gtk_button_new_with_label("+ Add Rule");
    GtkWidget *del_btn = gtk_button_new_with_label("Delete Selected");
    GtkWidget *import_btn = gtk_button_new_with_label("Import");
    GtkWidget *export_btn = gtk_button_new_with_label("Export");
    g_signal_connect(add_btn, "clicked", G_CALLBACK(on_rule_add_clicked), NULL);
    g_signal_connect(btn_select_all_header, "clicked", G_CALLBACK(on_select_all_clicked), NULL);
    g_signal_connect(del_btn, "clicked", G_CALLBACK(on_bulk_delete_clicked), NULL);
    g_signal_connect(import_btn, "clicked", G_CALLBACK(on_rule_import_clicked), NULL);
    g_signal_connect(export_btn, "clicked", G_CALLBACK(on_rule_export_clicked), NULL);
    GtkWidget *right[] = {add_btn, btn_select_all_header, del_btn, export_btn, import_btn};
    for (int i = 0; i < 5; i++) gtk_box_pack_end(GTK_BOX(header_box), right[i], FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), header_box, FALSE, FALSE, 0);

    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    rules_list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(scrolled), rules_list_box);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

    refresh_rules_ui();
    gtk_widget_show_all(rules_window);
}
