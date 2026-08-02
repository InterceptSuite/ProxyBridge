#include "gui.h"

// widgets
GtkWidget *window;
GtkTextView *conn_view;
GtkTextBuffer *conn_buffer;
GtkTextView *log_view;
GtkTextBuffer *log_buffer;
GtkWidget *status_bar;
guint status_context_id;

// default config
char g_proxy_ip[256] = "";
uint16_t g_proxy_port = 0;
ProxyType g_proxy_type = PROXY_TYPE_SOCKS5;
char g_proxy_user[256] = "";
char g_proxy_pass[256] = "";

GList *g_rules_list = NULL;
bool g_chk_logging = true;
bool g_chk_dns = true;

static void on_log_traffic_toggled(GtkCheckMenuItem *item, gpointer data) {
    bool active = gtk_check_menu_item_get_active(item);
    ProxyBridge_SetTrafficLoggingEnabled(active);
    g_chk_logging = active;
    save_config();
}

static void on_dns_proxy_toggled(GtkCheckMenuItem *item, gpointer data) {
    bool active = gtk_check_menu_item_get_active(item);
    ProxyBridge_SetDnsViaProxy(active);
    g_chk_dns = active;
    save_config();
}

// same feed as windows/mac: https://download.interceptsuite.com/proxybridge.json
#define UPD_FEED_URL "https://download.interceptsuite.com/proxybridge.json"

static char *extract_platform_block(const char *json, const char *platform) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", platform);
    char *p = strstr(json, needle);
    if (!p) return NULL;
    char *brace = strchr(p, '{');
    if (!brace) return NULL;
    int depth = 0;
    for (char *q = brace; *q; q++) {
        if (*q == '{') depth++;
        else if (*q == '}') {
            depth--;
            if (depth == 0)
                return g_strndup(brace, (gsize)(q - brace + 1));
        }
    }
    return NULL;
}

static void parse_ver(const char *s, int out[3]) {
    out[0] = out[1] = out[2] = 0;
    if (!s) return;
    while (*s && (*s < '0' || *s > '9')) s++;
    int i = 0;
    while (*s && i < 3) {
        if (*s >= '0' && *s <= '9') {
            int n = 0;
            while (*s >= '0' && *s <= '9') {
                n = n * 10 + (*s - '0');
                s++;
            }
            out[i++] = n;
        } else if (*s == '.') {
            s++;
        } else {
            break;
        }
    }
}

static int ver_cmp(const int a[3], const int b[3]) {
    for (int i = 0; i < 3; i++) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

static int https_url_ok(const char *url) {
    if (!url || strncmp(url, "https://", 8) != 0) return 0;
    for (const char *p = url; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || c > 126) return 0;
        if (c == ' ' || c == '"' || c == '\'' || c == '`' || c == '\\') return 0;
    }
    return 1;
}

static void on_check_update(GtkWidget *widget, gpointer data) {
    char *argv[] = {
        (char *)"curl", (char *)"-sS",
        (char *)"-H", (char *)"User-Agent: ProxyBridge-UpdateChecker",
        (char *)UPD_FEED_URL,
        NULL
    };
    char *json = NULL;
    char *curl_err = NULL;
    GError *spawn_err = NULL;
    int exit_code = 0;

    // feed only, no deploy.sh. open the linux download/notes url in the browser
    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                      &json, &curl_err, &exit_code, &spawn_err)) {
        show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Update check failed: %s",
                     spawn_err ? spawn_err->message : "unknown");
        if (spawn_err) g_error_free(spawn_err);
        g_free(curl_err);
        return;
    }
    if (exit_code != 0 || !json || json[0] == '\0') {
        show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Update check failed (curl exit %d).", exit_code);
        g_free(json);
        g_free(curl_err);
        return;
    }

    char *linux_obj = extract_platform_block(json, "linux");
    g_free(json);
    g_free(curl_err);
    if (!linux_obj) {
        show_message(GTK_WINDOW(window), GTK_MESSAGE_WARNING, "Could not parse linux update info.");
        return;
    }

    char *version = extract_sub_json_str(linux_obj, "version");
    char *download = extract_sub_json_str(linux_obj, "download");
    char *notes = extract_sub_json_str(linux_obj, "release_notes");
    g_free(linux_obj);

    if (!version || !version[0]) {
        show_message(GTK_WINDOW(window), GTK_MESSAGE_WARNING, "Could not parse version info.");
        g_free(version);
        g_free(download);
        g_free(notes);
        return;
    }

    int cur[3], lat[3];
    parse_ver(PROXYBRIDGE_VERSION, cur);
    parse_ver(version, lat);
    if (ver_cmp(lat, cur) <= 0) {
        show_message(GTK_WINDOW(window), GTK_MESSAGE_INFO, "You are using the latest version (%s).", PROXYBRIDGE_VERSION);
        g_free(version);
        g_free(download);
        g_free(notes);
        return;
    }

    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_NONE,
        "Version %s is available (current %s).\nOpen the download page in your browser?",
        version, PROXYBRIDGE_VERSION);
    gtk_dialog_add_button(GTK_DIALOG(dialog), "Open in Browser", GTK_RESPONSE_ACCEPT);
    gtk_dialog_add_button(GTK_DIALOG(dialog), "Close", GTK_RESPONSE_CANCEL);
    int resp = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    if (resp == GTK_RESPONSE_ACCEPT) {
        const char *url = NULL;
        if (https_url_ok(notes)) url = notes;
        else if (https_url_ok(download)) url = download;
        if (!url) {
            show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "No safe https url in update feed.");
        } else {
            GError *uri_err = NULL;
            if (!gtk_show_uri_on_window(GTK_WINDOW(window), url, GDK_CURRENT_TIME, &uri_err)) {
                show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Could not open browser: %s",
                             uri_err ? uri_err->message : "unknown");
                if (uri_err) g_error_free(uri_err);
            }
        }
    }
    g_free(version);
    g_free(download);
    g_free(notes);
}

static void on_about(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("About ProxyBridge", GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_MODAL, "OK", GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 300);
    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content_area), 20);
    char *markup = g_strdup_printf(
        "<span size='xx-large' weight='bold'>ProxyBridge</span>\n"
        "<span color='gray'>Version %s</span>\n\n"
        "Universal proxy client for Linux applications\n\n"
        "Author: Sourav Kalal / InterceptSuite\n\n"
        "Website: <a href=\"https://interceptsuite.com\">interceptsuite.com</a>\n"
        "GitHub: <a href=\"https://github.com/InterceptSuite/ProxyBridge\">InterceptSuite/ProxyBridge</a>\n\n"
        "License: MIT", PROXYBRIDGE_VERSION);
    GtkWidget *label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), markup);
    gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_CENTER);
    g_free(markup);
    gtk_box_pack_start(GTK_BOX(content_area), label, TRUE, TRUE, 0);
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void signal_handler(int sig) {
    fprintf(stderr, "\nSignal %d received. Stopping ProxyBridge...\n", sig);
    ProxyBridge_Stop();
    exit(sig);
}

static void on_window_destroy(GtkWidget *widget, gpointer data) {
    ProxyBridge_Stop();
    gtk_main_quit();
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);

    if (getuid() != 0) { gtk_init(&argc, &argv); show_message(NULL, GTK_MESSAGE_ERROR, "ProxyBridge must be run as root (sudo)."); return 1; }
    setenv("GSETTINGS_BACKEND", "memory", 1);

    // load config from file
    load_config();

    gtk_init(&argc, &argv);

    GtkSettings *settings = gtk_settings_get_default();
    if (settings) g_object_set(settings, "gtk-application-prefer-dark-theme", TRUE, NULL);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "ProxyBridge");
    gtk_window_set_default_size(GTK_WINDOW(window), 900, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    // setup menu
    GtkWidget *menubar = gtk_menu_bar_new();
    GtkWidget *proxy_menu_item = gtk_menu_item_new_with_label("Proxy");
    GtkWidget *proxy_menu = gtk_menu_new();
    GtkWidget *config_item = gtk_menu_item_new_with_label("Proxy Settings");
    GtkWidget *rules_item = gtk_menu_item_new_with_label("Proxy Rules");

    GtkWidget *log_check_item = gtk_check_menu_item_new_with_label("Enable Traffic Logging");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(log_check_item), g_chk_logging);
    g_signal_connect(log_check_item, "toggled", G_CALLBACK(on_log_traffic_toggled), NULL);

    GtkWidget *dns_check_item = gtk_check_menu_item_new_with_label("DNS via Proxy");
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(dns_check_item), g_chk_dns);
    g_signal_connect(dns_check_item, "toggled", G_CALLBACK(on_dns_proxy_toggled), NULL);

    GtkWidget *exit_item = gtk_menu_item_new_with_label("Exit");

    g_signal_connect(config_item, "activate", G_CALLBACK(on_proxy_configure), NULL);
    g_signal_connect(rules_item, "activate", G_CALLBACK(on_proxy_rules_clicked), NULL);
    g_signal_connect(exit_item, "activate", G_CALLBACK(on_window_destroy), NULL);

    gtk_menu_shell_append(GTK_MENU_SHELL(proxy_menu), config_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(proxy_menu), rules_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(proxy_menu), gtk_separator_menu_item_new());
    gtk_menu_shell_append(GTK_MENU_SHELL(proxy_menu), log_check_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(proxy_menu), dns_check_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(proxy_menu), gtk_separator_menu_item_new());
    gtk_menu_shell_append(GTK_MENU_SHELL(proxy_menu), exit_item);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(proxy_menu_item), proxy_menu);

    GtkWidget *about_menu_item = gtk_menu_item_new_with_label("About");
    GtkWidget *about_menu = gtk_menu_new();
    GtkWidget *about_child_item = gtk_menu_item_new_with_label("About");
    g_signal_connect(about_child_item, "activate", G_CALLBACK(on_about), NULL);
    GtkWidget *update_item = gtk_menu_item_new_with_label("Check for Updates");
    g_signal_connect(update_item, "activate", G_CALLBACK(on_check_update), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(about_menu), about_child_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(about_menu), update_item);
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(about_menu_item), about_menu);

    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), proxy_menu_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), about_menu_item);
    gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);

    // tabs
    GtkWidget *notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 0);

    // connections tab
    GtkWidget *conn_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(conn_vbox), 5);
    GtkWidget *conn_toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *conn_search = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(conn_search), "Search connections...");
    g_signal_connect(conn_search, "search-changed", G_CALLBACK(on_search_conn_changed), NULL);
    GtkWidget *conn_clear_btn = gtk_button_new_with_label("Clear Logs");
    g_signal_connect(conn_clear_btn, "clicked", G_CALLBACK(on_clear_conn_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(conn_toolbar), conn_search, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(conn_toolbar), conn_clear_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(conn_vbox), conn_toolbar, FALSE, FALSE, 0);
    conn_view = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_editable(conn_view, FALSE);
    gtk_text_view_set_cursor_visible(conn_view, FALSE);
    conn_buffer = gtk_text_view_get_buffer(conn_view);
    gtk_text_buffer_create_tag(conn_buffer, "hidden", "invisible", TRUE, NULL);
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrolled_window), GTK_WIDGET(conn_view));
    gtk_box_pack_start(GTK_BOX(conn_vbox), scrolled_window, TRUE, TRUE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), conn_vbox, gtk_label_new("Connections"));

    // logs tab
    GtkWidget *log_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(log_vbox), 5);
    GtkWidget *log_toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *log_search = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(log_search), "Search logs...");
    g_signal_connect(log_search, "search-changed", G_CALLBACK(on_search_log_changed), NULL);
    GtkWidget *log_clear_btn = gtk_button_new_with_label("Clear Logs");
    g_signal_connect(log_clear_btn, "clicked", G_CALLBACK(on_clear_log_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(log_toolbar), log_search, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(log_toolbar), log_clear_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(log_vbox), log_toolbar, FALSE, FALSE, 0);
    log_view = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_editable(log_view, FALSE);
    gtk_text_view_set_cursor_visible(log_view, FALSE);
    log_buffer = gtk_text_view_get_buffer(log_view);
    gtk_text_buffer_create_tag(log_buffer, "hidden", "invisible", TRUE, NULL);
    GtkWidget *log_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(log_scroll), GTK_WIDGET(log_view));
    gtk_box_pack_start(GTK_BOX(log_vbox), log_scroll, TRUE, TRUE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), log_vbox, gtk_label_new("Activity Logs"));

    // status bar
    status_bar = gtk_statusbar_new();
    status_context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(status_bar), "Status");
    gtk_box_pack_start(GTK_BOX(vbox), status_bar, FALSE, FALSE, 0);

    // start
    ProxyBridge_SetLogCallback(lib_log_callback);
    ProxyBridge_SetConnectionCallback(lib_connection_callback);
    ProxyBridge_SetTrafficLoggingEnabled(g_chk_logging);
    ProxyBridge_SetDnsViaProxy(g_chk_dns);

    if (ProxyBridge_Start()) {
        // apply config
        ProxyBridge_SetProxyConfig(g_proxy_type, g_proxy_ip, g_proxy_port, g_proxy_user, g_proxy_pass);

        // restore rules
        for (GList *l = g_rules_list; l != NULL; l = l->next) {
            RuleData *r = (RuleData *)l->data;
            r->id = ProxyBridge_AddRule(r->process_name, r->target_hosts, r->target_ports, r->protocol, r->action);
            if (!r->enabled) ProxyBridge_DisableRule(r->id);
        }

        gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, "ProxyBridge Service Started.");
    } else {
        gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, "Failed to start ProxyBridge engine.");
    }

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
