#include "gui.h"
#include <glib-unix.h>
#include <signal.h>

GtkWidget *window;
GtkTextBuffer *conn_buffer;
GtkTextBuffer *log_buffer;
GtkWidget *status_bar;
guint status_context_id;

GList *g_rules_list = NULL;
bool g_chk_logging = true;
bool g_chk_dns = true;
static GtkWidget *log_item, *dns_item;

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

// the switches belong to the profile: after a profile change, show and apply the new profile's values
void gui_sync_switches() {
    ProxyBridge_SetTrafficLoggingEnabled(g_chk_logging);
    ProxyBridge_SetDnsViaProxy(g_chk_dns);
    if (log_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(log_item), g_chk_logging);
    if (dns_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(dns_item), g_chk_dns);
}

// same feed as windows/mac: https://download.interceptsuite.com/proxybridge.json
#define UPD_FEED_URL "https://download.interceptsuite.com/proxybridge.json"

// match "linux": { ... } as a key, not a random "linux" string value
static char *extract_platform_block(const char *json, const char *platform) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", platform);
    size_t nlen = strlen(needle);
    const char *p = json;
    const char *key = NULL;
    while ((p = strstr(p, needle)) != NULL) {
        const char *after = p + nlen;
        while (*after == ' ' || *after == '\t' || *after == '\n' || *after == '\r') after++;
        if (*after == ':') {
            key = p;
            break;
        }
        p += nlen;
    }
    if (!key) return NULL;
    const char *brace = strchr(key, '{');
    if (!brace) return NULL;
    int depth = 0;
    for (const char *q = brace; *q; q++) {
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
        "Universal proxy client for Linux applications\n"
        "eBPF backend (needs root, kernel 5.11+ with BTF and cgroup v2)\n\n"
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

typedef enum { ENGINE_STOPPED, ENGINE_STARTING, ENGINE_RUNNING, ENGINE_STOPPING } EngineState;

static EngineState engine_state = ENGINE_STOPPED;
static GThread *engine_thread = NULL;
static struct { bool start, ok; } engine_job;
static GtkWidget *status_info;
static GtkWidget *start_item, *stop_item;
static guint status_source = 0;
static uint64_t last_conn_count = 0;
static unsigned conn_rate = 0;

static void update_status_info() {
    static const char *names[] = {"Stopped", "Starting...", "Running", "Stopping..."};
    char *text = g_strdup_printf("Engine: %s  |  Profile: %s  |  Proxies: %u  |  Rules: %u  |  %u conn/s",
                                 names[engine_state], g_active_profile, g_list_length(g_proxies_list),
                                 g_list_length(g_rules_list), conn_rate);
    gtk_label_set_text(GTK_LABEL(status_info), text);
    g_free(text);
    gtk_widget_set_sensitive(start_item, engine_state == ENGINE_STOPPED);
    gtk_widget_set_sensitive(stop_item, engine_state == ENGINE_RUNNING);
}

static void set_engine_state(EngineState state) {
    engine_state = state;
    update_status_info();
}

static gboolean status_tick(gpointer data) {
    uint64_t now = gui_conn_event_count();
    conn_rate = (unsigned)(now - last_conn_count);
    last_conn_count = now;
    update_status_info();
    return G_SOURCE_CONTINUE;
}

// runs in the main loop (g_unix_signal_add), so no library calls from a real signal context
static gboolean on_unix_signal(gpointer data) {
    fprintf(stderr, "\nSignal received. Stopping ProxyBridge...\n");
    gtk_main_quit();
    return G_SOURCE_REMOVE;
}

static void on_window_destroy(GtkWidget *widget, gpointer data) {
    if (status_source) g_source_remove(status_source);
    status_source = 0;
    gui_logs_stop_timers();
    gtk_main_quit();
}

static gboolean engine_job_done(gpointer data) {
    g_thread_join(engine_thread);
    engine_thread = NULL;
    if (!engine_job.start) {
        set_engine_state(ENGINE_STOPPED);
        gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, "ProxyBridge Service Stopped.");
    } else if (engine_job.ok) {
        set_engine_state(ENGINE_RUNNING);
        gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, "ProxyBridge Service Started (eBPF).");
    } else {
        set_engine_state(ENGINE_STOPPED);
        gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, "Failed to start ProxyBridge engine. See the Activity Logs tab.");
        show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR,
            "Failed to start the ProxyBridge engine.\n\n"
            "Open the \"Activity Logs\" tab to see the reason.\n"
            "The eBPF backend needs root, a kernel >= 5.11 with BTF and cgroup v2.");
    }
    return G_SOURCE_REMOVE;
}

static gpointer engine_job_thread(gpointer data) {
    engine_job.ok = engine_job.start ? ProxyBridge_Start() : ProxyBridge_Stop();
    g_idle_add(engine_job_done, NULL);
    return NULL;
}

// Start/Stop can take a second (BPF load, /proc scan), keep them off the UI thread
static void engine_request(bool start) {
    if (engine_thread || engine_state != (start ? ENGINE_STOPPED : ENGINE_RUNNING)) return;
    engine_job.start = start;
    set_engine_state(start ? ENGINE_STARTING : ENGINE_STOPPING);
    engine_thread = g_thread_new("engine", engine_job_thread, NULL);
}

static void on_start_engine(GtkWidget *widget, gpointer data) {
    engine_request(true);
}

static void on_stop_engine(GtkWidget *widget, gpointer data) {
    engine_request(false);
}

// exit path: wait for a pending job, then stop synchronously
static void shutdown_engine() {
    if (engine_thread) {
        g_thread_join(engine_thread);
        engine_thread = NULL;
        engine_state = engine_job.start && engine_job.ok ? ENGINE_RUNNING : ENGINE_STOPPED;
    }
    if (engine_state == ENGINE_RUNNING) ProxyBridge_Stop();
    engine_state = ENGINE_STOPPED;
}

static GtkWidget *add_menu_item(GtkWidget *menu, const char *label, GCallback cb) {
    GtkWidget *item = gtk_menu_item_new_with_label(label);
    g_signal_connect(item, "activate", cb, NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    return item;
}

static GtkWidget *add_check_item(GtkWidget *menu, const char *label, bool active, GCallback cb) {
    GtkWidget *item = gtk_check_menu_item_new_with_label(label);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), active);
    g_signal_connect(item, "toggled", cb, NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
    return item;
}

static void add_separator(GtkWidget *menu) {
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
}

static GtkWidget *add_submenu(GtkWidget *menubar, const char *label) {
    GtkWidget *item = gtk_menu_item_new_with_label(label);
    GtkWidget *menu = gtk_menu_new();
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(item), menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar), item);
    return menu;
}

static GtkTextBuffer *add_text_tab(GtkWidget *notebook, const char *title, const char *placeholder, GCallback on_search, GCallback on_clear, GCallback on_pause) {
    GtkWidget *tab = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(tab), 5);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    GtkWidget *search = gtk_search_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(search), placeholder);
    g_signal_connect(search, "search-changed", on_search, NULL);
    GtkWidget *clear_btn = gtk_button_new_with_label("Clear Logs");
    g_signal_connect(clear_btn, "clicked", on_clear, NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), search, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(toolbar), clear_btn, FALSE, FALSE, 0);
    if (on_pause) {
        GtkWidget *pause_btn = gtk_toggle_button_new_with_label("Pause");
        g_signal_connect(pause_btn, "toggled", on_pause, NULL);
        gtk_box_pack_start(GTK_BOX(toolbar), pause_btn, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(tab), toolbar, FALSE, FALSE, 0);

    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_create_tag(buffer, "hidden", "invisible", TRUE, NULL);
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrolled), view);
    gtk_box_pack_start(GTK_BOX(tab), scrolled, TRUE, TRUE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), tab, gtk_label_new(title));
    return buffer;
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        gtk_init(&argc, &argv);
        show_message(NULL, GTK_MESSAGE_ERROR, "ProxyBridge must be run as root (sudo).");
        return 1;
    }
    setenv("GSETTINGS_BACKEND", "memory", 1);
    load_config();
    gtk_init(&argc, &argv);

    GtkSettings *settings = gtk_settings_get_default();
    if (settings) g_object_set(settings, "gtk-application-prefer-dark-theme", TRUE, NULL);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char *win_title = g_strdup_printf("ProxyBridge - %s", g_active_profile);
    gtk_window_set_title(GTK_WINDOW(window), win_title);
    g_free(win_title);
    gtk_window_set_default_size(GTK_WINDOW(window), 900, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    GtkWidget *menubar = gtk_menu_bar_new();
    GtkWidget *proxy_menu = add_submenu(menubar, "Proxy");
    add_menu_item(proxy_menu, "Proxy Settings...", G_CALLBACK(on_proxy_configure));
    add_menu_item(proxy_menu, "Proxy Rules...", G_CALLBACK(on_proxy_rules_clicked));
    add_menu_item(proxy_menu, "Profiles...", G_CALLBACK(on_profiles_clicked));
    add_separator(proxy_menu);
    log_item = add_check_item(proxy_menu, "Enable Traffic Logging", g_chk_logging, G_CALLBACK(on_log_traffic_toggled));
    dns_item = add_check_item(proxy_menu, "DNS via Proxy", g_chk_dns, G_CALLBACK(on_dns_proxy_toggled));
    add_separator(proxy_menu);
    start_item = add_menu_item(proxy_menu, "Start Engine", G_CALLBACK(on_start_engine));
    stop_item = add_menu_item(proxy_menu, "Stop Engine", G_CALLBACK(on_stop_engine));
    add_menu_item(proxy_menu, "Exit", G_CALLBACK(on_window_destroy));
    GtkWidget *about_menu = add_submenu(menubar, "About");
    add_menu_item(about_menu, "About", G_CALLBACK(on_about));
    add_menu_item(about_menu, "Check for Updates", G_CALLBACK(on_check_update));
    gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 0);
    conn_buffer = add_text_tab(notebook, "Connections", "Search connections...", G_CALLBACK(on_search_conn_changed), G_CALLBACK(on_clear_conn_clicked), G_CALLBACK(on_pause_conn_toggled));
    log_buffer = add_text_tab(notebook, "Activity Logs", "Search logs...", G_CALLBACK(on_search_log_changed), G_CALLBACK(on_clear_log_clicked), NULL);

    GtkWidget *status_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    status_bar = gtk_statusbar_new();
    status_context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(status_bar), "Status");
    status_info = gtk_label_new("");
    gtk_widget_set_margin_end(status_info, 10);
    gtk_box_pack_start(GTK_BOX(status_box), status_bar, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(status_box), status_info, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), status_box, FALSE, FALSE, 0);
    gui_logs_init();

    ProxyBridge_SetLogCallback(lib_log_callback);
    ProxyBridge_SetConnectionCallback(lib_connection_callback);
    ProxyBridge_SetTrafficLoggingEnabled(g_chk_logging);
    ProxyBridge_SetDnsViaProxy(g_chk_dns);
    apply_proxies_to_lib();
    apply_rules_to_lib();

    g_unix_signal_add(SIGINT, on_unix_signal, NULL);
    g_unix_signal_add(SIGTERM, on_unix_signal, NULL);

    gtk_widget_show_all(window);
    update_status_info();
    status_source = g_timeout_add_seconds(1, status_tick, NULL);
    engine_request(true);
    gtk_main();

    shutdown_engine();
    gui_logs_free();
    config_free_all();
    return 0;
}
