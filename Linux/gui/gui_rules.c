#include "gui.h"

static GtkWidget *rules_window = NULL;
static GtkWidget *rules_list_box = NULL;
static GtkWidget *btn_select_all_header = NULL;

// forward
static void refresh_rules_ui();

void free_rule_data(RuleData *rule) {
    if (rule) {
        g_free(rule->process_name);
        g_free(rule->target_hosts);
        g_free(rule->target_ports);
        g_free(rule->proxy_name);
        g_free(rule);
    }
}

// position of the rule in the library list. rules the library rejected (id 0) are not in it
static int lib_index_of(RuleData *rule) {
    int idx = 0;
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        if (l->data == rule) break;
        if (((RuleData *)l->data)->id != 0) idx++;
    }
    return idx;
}

static uint32_t rule_proxy_id(RuleAction action, const char *proxy_name) {
    return action == RULE_ACTION_PROXY ? resolve_proxy_id(proxy_name) : 0;
}

// push the stored rules to the library, call after the proxies were added and before ProxyBridge_Start
void apply_rules_to_lib() {
    ProxyBridge_ClearRules();
    int n = 1;
    for (GList *l = g_rules_list; l != NULL; l = l->next, n++) {
        RuleData *r = (RuleData *)l->data;
        char err[256] = "";
        r->id = ProxyBridge_AddRule(r->process_name, r->target_hosts, r->target_ports, r->protocol, r->action,
                                    rule_proxy_id(r->action, r->proxy_name), err, sizeof(err));
        if (r->id == 0) {
            gui_log("Rule #%d (%s) not loaded: %s", n, r->process_name, err[0] ? err : "rejected");
            continue;
        }
        if (!r->enabled) ProxyBridge_DisableRule(r->id);
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
    if (!link) return;
    GList *other = dir < 0 ? link->prev : link->next;
    if (!other) return;

    // swap the data pointers, keeps the list head valid
    gpointer tmp = link->data;
    link->data = other->data;
    other->data = tmp;

    if (rule->id != 0 && !ProxyBridge_MoveRule(rule->id, lib_index_of(rule)))
        gui_log("Could not reorder rule %u in the engine", rule->id);
    save_config();
    refresh_rules_ui();
}

static void on_rule_move_up(GtkWidget *widget, gpointer data) { on_rule_move((RuleData *)data, -1); }
static void on_rule_move_down(GtkWidget *widget, gpointer data) { on_rule_move((RuleData *)data, 1); }

static void on_browse_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *entry = (GtkWidget *)data;
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Application",
                                      NULL,
                                      GTK_FILE_CHOOSER_ACTION_OPEN,
                                      "_Cancel", GTK_RESPONSE_CANCEL,
                                      "_Select", GTK_RESPONSE_ACCEPT,
                                      NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if (filename) {
            char *base = g_path_get_basename(filename);
            gtk_entry_set_text(GTK_ENTRY(entry), base);
            g_free(base);
            g_free(filename);
        }
    }
    gtk_widget_destroy(dialog);
}

// proxy combo only matters for PROXY rules
static void on_action_changed(GtkComboBox *combo, gpointer data) {
    gtk_widget_set_sensitive(GTK_WIDGET(data), gtk_combo_box_get_active(combo) == RULE_ACTION_PROXY);
}

static void open_rule_dialog(RuleData *rule) {
    GtkWidget *dialog = gtk_dialog_new();
    gtk_window_set_title(GTK_WINDOW(dialog), rule ? "Edit Rule" : "Add Rule");
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(rules_window ? rules_window : window));
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 500, 400);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 15);

    // proc input
    GtkWidget *proc_entry = gtk_entry_new();
    GtkWidget *browse_btn = gtk_button_new_with_label("Browse...");
    g_signal_connect(browse_btn, "clicked", G_CALLBACK(on_browse_clicked), proc_entry);
    GtkWidget *proc_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(proc_box), proc_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(proc_box), browse_btn, FALSE, FALSE, 0);
    gtk_widget_set_hexpand(proc_box, TRUE);

    GtkWidget *host_entry = gtk_entry_new();
    GtkWidget *port_entry = gtk_entry_new();

    // protocol list
    GtkWidget *proto_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(proto_combo), "TCP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(proto_combo), "UDP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(proto_combo), "BOTH");

    // action list
    GtkWidget *action_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(action_combo), "PROXY");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(action_combo), "DIRECT");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(action_combo), "BLOCK");

    // proxy list: entry 0 = default proxy, then one per configured proxy (same order as g_proxies_list)
    GtkWidget *proxy_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(proxy_combo), "Default proxy");
    int proxy_sel = 0, pi = 1;
    for (GList *l = g_proxies_list; l != NULL; l = l->next, pi++) {
        ProxyData *p = (ProxyData *)l->data;
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(proxy_combo), p->name);
        if (rule && rule->proxy_name && p->name && strcmp(rule->proxy_name, p->name) == 0) proxy_sel = pi;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(proxy_combo), proxy_sel);
    g_signal_connect(action_combo, "changed", G_CALLBACK(on_action_changed), proxy_combo);

    if (rule) {
        gtk_entry_set_text(GTK_ENTRY(proc_entry), rule->process_name);
        gtk_entry_set_text(GTK_ENTRY(host_entry), rule->target_hosts);
        gtk_entry_set_text(GTK_ENTRY(port_entry), rule->target_ports);
        gtk_combo_box_set_active(GTK_COMBO_BOX(proto_combo), rule->protocol);
        gtk_combo_box_set_active(GTK_COMBO_BOX(action_combo), rule->action);
    } else {
        gtk_entry_set_text(GTK_ENTRY(port_entry), "*");
        gtk_entry_set_text(GTK_ENTRY(host_entry), "*");
        gtk_combo_box_set_active(GTK_COMBO_BOX(proto_combo), 2); // BOTH default
        gtk_combo_box_set_active(GTK_COMBO_BOX(action_combo), 0); // PROXY default
    }

    int row = 0;
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Process Name:"), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), proc_box, 1, row, 1, 1); row++;

    GtkWidget *proc_hint = gtk_label_new("Example: firefox; chrome; /usr/bin/wget");
    gtk_style_context_add_class(gtk_widget_get_style_context(proc_hint), "dim-label");
    gtk_widget_set_halign(proc_hint, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), proc_hint, 1, row, 1, 1); row++;

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Target Host:"), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), host_entry, 1, row, 1, 1); row++;

    GtkWidget *host_hint = gtk_label_new("Example: 192.168.1.*; 10.0.0.0/8; 10.0.0.1-10.0.0.50; github.com; *.github.com; * (domains are matched via DNS answers)");
    gtk_label_set_line_wrap(GTK_LABEL(host_hint), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(host_hint), 60);
    gtk_style_context_add_class(gtk_widget_get_style_context(host_hint), "dim-label");
    gtk_widget_set_halign(host_hint, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), host_hint, 1, row, 1, 1); row++;

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Target Port:"), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), port_entry, 1, row, 1, 1); row++;

    GtkWidget *port_hint = gtk_label_new("Example: 80; 443; 8000-8080; *");
    gtk_style_context_add_class(gtk_widget_get_style_context(port_hint), "dim-label");
    gtk_widget_set_halign(port_hint, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), port_hint, 1, row, 1, 1); row++;

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Protocol:"), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), proto_combo, 1, row, 1, 1); row++;

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Action:"), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), action_combo, 1, row, 1, 1); row++;

    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Proxy:"), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), proxy_combo, 1, row, 1, 1); row++;

    // inline validation error
    GtkWidget *err_label = gtk_label_new("");
    gtk_widget_set_halign(err_label, GTK_ALIGN_START);
    gtk_label_set_xalign(GTK_LABEL(err_label), 0);
    gtk_label_set_line_wrap(GTK_LABEL(err_label), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(err_label), 60);
    gtk_grid_attach(GTK_GRID(grid), err_label, 0, row, 2, 1); row++;

    gtk_container_add(GTK_CONTAINER(content), grid);

    gtk_dialog_add_button(GTK_DIALOG(dialog), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_dialog_add_button(GTK_DIALOG(dialog), "Save", GTK_RESPONSE_ACCEPT);
    gtk_widget_show_all(dialog);
    on_action_changed(GTK_COMBO_BOX(action_combo), proxy_combo);

    while (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *proc = gtk_entry_get_text(GTK_ENTRY(proc_entry));
        const char *hosts = gtk_entry_get_text(GTK_ENTRY(host_entry));
        const char *ports = gtk_entry_get_text(GTK_ENTRY(port_entry));
        int proto_i = gtk_combo_box_get_active(GTK_COMBO_BOX(proto_combo));
        int action_i = gtk_combo_box_get_active(GTK_COMBO_BOX(action_combo));
        if (proto_i < 0) proto_i = RULE_PROTOCOL_BOTH;
        if (action_i < 0) action_i = RULE_ACTION_PROXY;
        RuleProtocol proto = (RuleProtocol)proto_i;
        RuleAction action = (RuleAction)action_i;

        // proxy name from the combo, NULL = default
        const char *proxy_name = NULL;
        int psel = gtk_combo_box_get_active(GTK_COMBO_BOX(proxy_combo));
        if (action == RULE_ACTION_PROXY && psel > 0) {
            ProxyData *pd = (ProxyData *)g_list_nth_data(g_proxies_list, psel - 1);
            if (pd) proxy_name = pd->name;
        }

        char err[256] = "";
        bool ok = ProxyBridge_ValidateRule(proc, hosts, ports, err, sizeof(err));
        uint32_t pid = rule_proxy_id(action, proxy_name);

        if (ok) {
            if (rule && rule->id != 0) {
                ok = ProxyBridge_EditRule(rule->id, proc, hosts, ports, proto, action, pid, err, sizeof(err));
            } else {
                // new rule, or one the engine rejected when it was loaded
                uint32_t new_id = ProxyBridge_AddRule(proc, hosts, ports, proto, action, pid, err, sizeof(err));
                ok = (new_id != 0);
                if (ok) {
                    if (rule && !rule->enabled) ProxyBridge_DisableRule(new_id);
                    if (rule) {
                        rule->id = new_id;
                        ProxyBridge_MoveRule(new_id, lib_index_of(rule));
                    } else {
                        RuleData *new_rule = g_malloc0(sizeof(RuleData));
                        new_rule->id = new_id;
                        new_rule->enabled = true;
                        g_rules_list = g_list_append(g_rules_list, new_rule);
                        rule = new_rule;
                    }
                }
            }
        }

        if (!ok) {
            char *esc = g_markup_printf_escaped("<span foreground='#e5534b'>%s</span>", err[0] ? err : "Invalid rule.");
            gtk_label_set_markup(GTK_LABEL(err_label), esc);
            g_free(esc);
            continue;
        }

        // update local copy
        g_free(rule->process_name); rule->process_name = g_strdup(proc);
        g_free(rule->target_hosts); rule->target_hosts = g_strdup(hosts);
        g_free(rule->target_ports); rule->target_ports = g_strdup(ports);
        g_free(rule->proxy_name); rule->proxy_name = proxy_name ? g_strdup(proxy_name) : NULL;
        rule->protocol = proto;
        rule->action = action;
        save_config();
        refresh_rules_ui();
        break;
    }
    gtk_widget_destroy(dialog);
}

static void on_rule_edit(GtkWidget *widget, gpointer data) {
    open_rule_dialog((RuleData *)data);
}

static void on_rule_add_clicked(GtkWidget *widget, gpointer data) {
    open_rule_dialog(NULL);
}

static void on_rule_select_toggle(GtkToggleButton *btn, gpointer data) {
    RuleData *rule = (RuleData *)data;
    rule->selected = gtk_toggle_button_get_active(btn);
    if (btn_select_all_header) {
         bool all_selected = (g_rules_list != NULL);
         if (g_rules_list == NULL) all_selected = false;
         for (GList *l = g_rules_list; l != NULL; l = l->next) {
            RuleData *r = (RuleData *)l->data;
            if (!r->selected) {
                all_selected = false;
                break;
            }
        }
        gtk_button_set_label(GTK_BUTTON(btn_select_all_header), all_selected ? "Deselect All" : "Select All");
    }
}

static void on_rule_export_clicked(GtkWidget *widget, gpointer data) {
    if (!g_rules_list) return;
    bool any_selected = false;
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        if (((RuleData *)l->data)->selected) { any_selected = true; break; }
    }
    if (!any_selected) {
        show_message(GTK_WINDOW(rules_window ? rules_window : window), GTK_MESSAGE_WARNING, "Please select at least one rule to export.");
        return;
    }
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Export Rules", GTK_WINDOW(rules_window ? rules_window : window), GTK_FILE_CHOOSER_ACTION_SAVE, "_Cancel", GTK_RESPONSE_CANCEL, "_Save", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "proxy_rules.json");
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        FILE *f = filename ? fopen(filename, "w") : NULL;
        if (f) {
            // both our keys and the macOS ones (ruleProtocol/ruleAction), plus the proxy name
            fprintf(f, "[\n");
            bool first = true;
            for (GList *l = g_rules_list; l != NULL; l = l->next) {
                RuleData *r = (RuleData *)l->data;
                if (!r->selected) continue;
                if (!first) fprintf(f, ",\n");
                char *proc = escape_json_string(r->process_name);
                char *host = escape_json_string(r->target_hosts);
                char *port = escape_json_string(r->target_ports);
                char *pxy = escape_json_string(r->action == RULE_ACTION_PROXY ? r->proxy_name : NULL);
                const char *proto = (r->protocol == RULE_PROTOCOL_TCP) ? "TCP" : (r->protocol == RULE_PROTOCOL_UDP ? "UDP" : "BOTH");
                const char *act = (r->action == RULE_ACTION_PROXY) ? "PROXY" : (r->action == RULE_ACTION_DIRECT ? "DIRECT" : "BLOCK");
                fprintf(f, "  {\n    \"processNames\": \"%s\",\n    \"targetHosts\": \"%s\",\n    \"targetPorts\": \"%s\",\n    \"protocol\": \"%s\",\n    \"ruleProtocol\": \"%s\",\n    \"action\": \"%s\",\n    \"ruleAction\": \"%s\",\n    \"proxy\": \"%s\",\n    \"enabled\": %s\n  }", proc, host, port, proto, proto, act, act, pxy, r->enabled ? "true" : "false");
                g_free(proc); g_free(host); g_free(port); g_free(pxy);
                first = false;
            }
            fprintf(f, "\n]\n");
            if (fclose(f) == 0) show_message(GTK_WINDOW(rules_window ? rules_window : window), GTK_MESSAGE_INFO, "Rules exported successfully.");
            else show_message(GTK_WINDOW(rules_window ? rules_window : window), GTK_MESSAGE_ERROR, "Failed to write %s", filename);
        } else {
            show_message(GTK_WINDOW(rules_window ? rules_window : window), GTK_MESSAGE_ERROR, "Could not open %s for writing.", filename ? filename : "file");
        }
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

// first non-NULL of two (consumes both)
static char *pick_str(char *a, char *b) {
    if (a) { g_free(b); return a; }
    return b;
}

static void on_rule_import_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Import Rules", GTK_WINDOW(rules_window ? rules_window : window), GTK_FILE_CHOOSER_ACTION_OPEN, "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        char *content = NULL;
        gsize len;
        if (filename && g_file_get_contents(filename, &content, &len, NULL)) {
            char *curr = content;
            int imported = 0, failed = 0, index = 0;
            GString *fail_msg = g_string_new("");

            while ((curr = strchr(curr, '{')) != NULL) {
                char *end = strchr(curr, '}');
                if (!end) break;
                char saved = *end; *end = '\0';
                index++;

                // our keys first, macOS keys as fallback
                char *proc = extract_sub_json_str(curr, "processNames");
                char *host = extract_sub_json_str(curr, "targetHosts");
                char *port = extract_sub_json_str(curr, "targetPorts");
                char *proto_s = pick_str(extract_sub_json_str(curr, "protocol"), extract_sub_json_str(curr, "ruleProtocol"));
                char *act_s = pick_str(extract_sub_json_str(curr, "action"), extract_sub_json_str(curr, "ruleAction"));
                char *proxy_s = extract_sub_json_str(curr, "proxy");
                bool en = json_has_key(curr, "enabled") ? extract_sub_json_bool(curr, "enabled") : true;

                if (!proc) {
                    failed++;
                    if (fail_msg->len < 3000) g_string_append_printf(fail_msg, "Rule #%d: missing processNames\n", index);
                } else {
                    RuleProtocol p = RULE_PROTOCOL_BOTH;
                    if (proto_s && g_ascii_strcasecmp(proto_s, "TCP") == 0) p = RULE_PROTOCOL_TCP;
                    else if (proto_s && g_ascii_strcasecmp(proto_s, "UDP") == 0) p = RULE_PROTOCOL_UDP;
                    // anything that is not DIRECT/BLOCK is PROXY (macOS stores the proxy id there)
                    RuleAction a = RULE_ACTION_PROXY;
                    if (act_s && g_ascii_strcasecmp(act_s, "DIRECT") == 0) a = RULE_ACTION_DIRECT;
                    else if (act_s && g_ascii_strcasecmp(act_s, "BLOCK") == 0) a = RULE_ACTION_BLOCK;

                    const char *h = host ? host : "*";
                    const char *po = port ? port : "*";
                    // unknown proxy name -> default proxy
                    ProxyData *px = (a == RULE_ACTION_PROXY) ? find_proxy_by_name(proxy_s) : NULL;

                    char err[256] = "";
                    uint32_t nid = ProxyBridge_AddRule(proc, h, po, p, a, px ? px->id : 0, err, sizeof(err));
                    if (nid == 0) {
                        failed++;
                        if (fail_msg->len < 3000) g_string_append_printf(fail_msg, "Rule #%d (%s): %s\n", index, proc, err[0] ? err : "rejected");
                    } else {
                        if (!en) ProxyBridge_DisableRule(nid);
                        RuleData *nd = g_malloc0(sizeof(RuleData));
                        nd->id = nid; nd->process_name = g_strdup(proc); nd->target_hosts = g_strdup(h);
                        nd->target_ports = g_strdup(po); nd->protocol = p; nd->action = a; nd->enabled = en;
                        nd->proxy_name = px ? g_strdup(px->name) : NULL;
                        g_rules_list = g_list_append(g_rules_list, nd);
                        imported++;
                    }
                }
                g_free(proc); g_free(host); g_free(port); g_free(proto_s); g_free(act_s); g_free(proxy_s);
                *end = saved; curr = end + 1;
            }
            g_free(content);

            if (imported > 0) { save_config(); refresh_rules_ui(); }
            GtkWindow *parent = GTK_WINDOW(rules_window ? rules_window : window);
            if (failed > 0) {
                show_message(parent, GTK_MESSAGE_WARNING, "Imported %d rules, %d failed validation and were skipped:\n\n%s", imported, failed, fail_msg->str);
            } else if (imported > 0) {
                show_message(parent, GTK_MESSAGE_INFO, "Imported %d rules.", imported);
            } else {
                show_message(parent, GTK_MESSAGE_WARNING, "No rules found in the file.");
            }
            g_string_free(fail_msg, TRUE);
        } else {
            show_message(GTK_WINDOW(rules_window ? rules_window : window), GTK_MESSAGE_ERROR, "Could not read the selected file.");
        }
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void on_bulk_delete_clicked(GtkWidget *widget, gpointer data) {
    if (!g_rules_list) return;
    GList *iter = g_rules_list;
    GList *to_delete = NULL;
    while (iter != NULL) {
        RuleData *rule = (RuleData *)iter->data;
        if (rule->selected) to_delete = g_list_append(to_delete, rule);
        iter = iter->next;
    }
    if (!to_delete) return;
    for (GList *d = to_delete; d != NULL; d = d->next) {
        RuleData *rule = (RuleData *)d->data;
        if (rule->id != 0) ProxyBridge_DeleteRule(rule->id);
        g_rules_list = g_list_remove(g_rules_list, rule);
        free_rule_data(rule);
    }
    g_list_free(to_delete);
    save_config();
    refresh_rules_ui();
}

static void on_select_all_clicked(GtkWidget *widget, gpointer data) {
    if (!g_rules_list) return;
    bool all_selected = true;
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        if (!((RuleData *)l->data)->selected) { all_selected = false; break; }
    }
    bool new_state = !all_selected;
    for (GList *l = g_rules_list; l != NULL; l = l->next) ((RuleData *)l->data)->selected = new_state;
    refresh_rules_ui();
}

static void refresh_rules_ui() {
    if (!rules_list_box) return;
    GList *children = gtk_container_get_children(GTK_CONTAINER(rules_list_box));
    for(GList *iter = children; iter != NULL; iter = g_list_next(iter)) gtk_widget_destroy(GTK_WIDGET(iter->data));
    g_list_free(children);

    if (btn_select_all_header) {
        bool all_selected = (g_rules_list != NULL);
        if (g_rules_list == NULL) all_selected = false;
        for (GList *l = g_rules_list; l != NULL; l = l->next) {
            if (!((RuleData *)l->data)->selected) { all_selected = false; break; }
        }
        gtk_button_set_label(GTK_BUTTON(btn_select_all_header), all_selected ? "Deselect All" : "Select All");
    }

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 15);
    gtk_container_add(GTK_CONTAINER(rules_list_box), grid);

    int row = 0;
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("  "), 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Enable"), 1, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Actions"), 2, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("SR"), 3, row, 1, 1);
    GtkWidget *h_proc = gtk_label_new("Process"); gtk_widget_set_halign(h_proc, GTK_ALIGN_START);
    gtk_widget_set_hexpand(h_proc, TRUE); gtk_grid_attach(GTK_GRID(grid), h_proc, 4, row, 1, 1);
    GtkWidget *h_host = gtk_label_new("Target Hosts"); gtk_widget_set_halign(h_host, GTK_ALIGN_START);
    gtk_widget_set_hexpand(h_host, TRUE); gtk_grid_attach(GTK_GRID(grid), h_host, 5, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Protocol"), 6, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Action"), 7, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), gtk_label_new("Proxy"), 8, row, 1, 1);
    row++;
    gtk_grid_attach(GTK_GRID(grid), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), 0, row, 9, 1); row++;

    int sr_counter = 1;
    for (GList *l = g_rules_list; l != NULL; l = l->next) {
        RuleData *r = (RuleData *)l->data;
        GtkWidget *chk_sel = gtk_check_button_new();
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk_sel), r->selected);
        g_signal_connect(chk_sel, "toggled", G_CALLBACK(on_rule_select_toggle), r);
        gtk_grid_attach(GTK_GRID(grid), chk_sel, 0, row, 1, 1);

        GtkWidget *chk = gtk_check_button_new();
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chk), r->enabled);
        g_signal_connect(chk, "toggled", G_CALLBACK(on_rule_toggle), r);
        gtk_grid_attach(GTK_GRID(grid), chk, 1, row, 1, 1);

        GtkWidget *act_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
        GtkWidget *btn_edit = gtk_button_new_with_label("Edit");
        g_signal_connect(btn_edit, "clicked", G_CALLBACK(on_rule_edit), r);
        GtkWidget *btn_del = gtk_button_new_with_label("Delete");
        g_signal_connect(btn_del, "clicked", G_CALLBACK(on_rule_delete), r);
        // list position is the priority, first match wins
        GtkWidget *btn_up = gtk_button_new_with_label("\u25B2");
        gtk_widget_set_tooltip_text(btn_up, "Move up (higher priority)");
        gtk_widget_set_sensitive(btn_up, l->prev != NULL);
        g_signal_connect(btn_up, "clicked", G_CALLBACK(on_rule_move_up), r);
        GtkWidget *btn_down = gtk_button_new_with_label("\u25BC");
        gtk_widget_set_tooltip_text(btn_down, "Move down (lower priority)");
        gtk_widget_set_sensitive(btn_down, l->next != NULL);
        g_signal_connect(btn_down, "clicked", G_CALLBACK(on_rule_move_down), r);
        gtk_box_pack_start(GTK_BOX(act_box), btn_edit, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(act_box), btn_del, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(act_box), btn_up, FALSE, FALSE, 0);
        gtk_box_pack_start(GTK_BOX(act_box), btn_down, FALSE, FALSE, 0);
        gtk_grid_attach(GTK_GRID(grid), act_box, 2, row, 1, 1);

        char sr_str[16]; snprintf(sr_str, sizeof(sr_str), "%d", sr_counter++);
        gtk_grid_attach(GTK_GRID(grid), gtk_label_new(sr_str), 3, row, 1, 1);

        GtkWidget *l_proc = gtk_label_new(r->process_name); gtk_widget_set_halign(l_proc, GTK_ALIGN_START);
        gtk_label_set_ellipsize(GTK_LABEL(l_proc), PANGO_ELLIPSIZE_END);
        gtk_grid_attach(GTK_GRID(grid), l_proc, 4, row, 1, 1);

        GtkWidget *l_host = gtk_label_new(r->target_hosts); gtk_widget_set_halign(l_host, GTK_ALIGN_START);
        gtk_label_set_ellipsize(GTK_LABEL(l_host), PANGO_ELLIPSIZE_END);
        gtk_grid_attach(GTK_GRID(grid), l_host, 5, row, 1, 1);

        const char* proto_strs[] = {"TCP", "UDP", "BOTH"};
        gtk_grid_attach(GTK_GRID(grid), gtk_label_new(proto_strs[r->protocol <= RULE_PROTOCOL_BOTH ? r->protocol : RULE_PROTOCOL_BOTH]), 6, row, 1, 1);

        const char* action_strs[] = {"PROXY", "DIRECT", "BLOCK"};
        GtkWidget *l_act = gtk_label_new(action_strs[r->action <= RULE_ACTION_BLOCK ? r->action : RULE_ACTION_PROXY]);
        GtkStyleContext *context = gtk_widget_get_style_context(l_act);
        if (r->action == RULE_ACTION_PROXY) gtk_style_context_add_class(context, "success");
        else if (r->action == RULE_ACTION_DIRECT) gtk_style_context_add_class(context, "info");
        else gtk_style_context_add_class(context, "warning");
        gtk_grid_attach(GTK_GRID(grid), l_act, 7, row, 1, 1);

        // proxy only matters for PROXY rules
        const char *proxy_txt = "-";
        if (r->action == RULE_ACTION_PROXY)
            proxy_txt = (r->proxy_name && *r->proxy_name && find_proxy_by_name(r->proxy_name)) ? r->proxy_name : "default";
        GtkWidget *l_proxy = gtk_label_new(proxy_txt);
        gtk_label_set_ellipsize(GTK_LABEL(l_proxy), PANGO_ELLIPSIZE_END);
        gtk_grid_attach(GTK_GRID(grid), l_proxy, 8, row, 1, 1);

        row++;
        gtk_grid_attach(GTK_GRID(grid), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), 0, row, 9, 1); row++;
    }
    gtk_widget_show_all(rules_list_box);
}

void refresh_rules_window() {
    refresh_rules_ui();
}

// widgets are gone, refresh_rules_ui must not touch them any more
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
    GtkWidget *dialog = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    rules_window = dialog;
    g_signal_connect(dialog, "destroy", G_CALLBACK(on_rules_window_destroy), NULL);
    gtk_window_set_title(GTK_WINDOW(dialog), "Process Rules");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 1000, 500);
    gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(window));
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 20);
    gtk_container_add(GTK_CONTAINER(dialog), vbox);

    GtkWidget *header_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title), "<span size='x-large' weight='bold'>Process Rules</span>");
    GtkWidget *add_btn = gtk_button_new_with_label("+ Add Rule");
    g_signal_connect(add_btn, "clicked", G_CALLBACK(on_rule_add_clicked), NULL);
    btn_select_all_header = gtk_button_new_with_label("Select All");
    g_signal_connect(btn_select_all_header, "clicked", G_CALLBACK(on_select_all_clicked), NULL);
    GtkWidget *del_all_btn = gtk_button_new_with_label("Delete Selected");
    g_signal_connect(del_all_btn, "clicked", G_CALLBACK(on_bulk_delete_clicked), NULL);
    GtkWidget *import_btn = gtk_button_new_with_label("Import");
    g_signal_connect(import_btn, "clicked", G_CALLBACK(on_rule_import_clicked), NULL);
    GtkWidget *export_btn = gtk_button_new_with_label("Export");
    g_signal_connect(export_btn, "clicked", G_CALLBACK(on_rule_export_clicked), NULL);

    gtk_box_pack_start(GTK_BOX(header_box), title, FALSE, FALSE, 0);
    GtkWidget *spacer = gtk_label_new("");
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_pack_start(GTK_BOX(header_box), spacer, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(header_box), add_btn, FALSE, FALSE, 5);
    gtk_box_pack_end(GTK_BOX(header_box), btn_select_all_header, FALSE, FALSE, 5);
    gtk_box_pack_end(GTK_BOX(header_box), del_all_btn, FALSE, FALSE, 5);
    gtk_box_pack_end(GTK_BOX(header_box), export_btn, FALSE, FALSE, 5);
    gtk_box_pack_end(GTK_BOX(header_box), import_btn, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(vbox), header_box, FALSE, FALSE, 0);

    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_vexpand(scrolled, TRUE);
    rules_list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(scrolled), rules_list_box);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

    refresh_rules_ui();
    gtk_widget_show_all(dialog);
}
