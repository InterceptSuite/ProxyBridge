#include "gui.h"
#include "gui_boot.h"
#include "gui_icon.h"
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
bool g_chk_log_every = false;
bool g_chk_auto_clear = true;
int g_zoom = 100;
bool g_chk_updates = true;
static GtkWidget *log_item, *every_item, *enable_item, *clear_item, *boot_item, *update_item;
static GtkCssProvider *zoom_provider;
static char zoom_css[96];

static void sync_update_item();

static void on_log_traffic_toggled(GtkCheckMenuItem *item, gpointer data) {
    bool active = gtk_check_menu_item_get_active(item);
    ProxyBridge_SetTrafficLoggingEnabled(active);
    g_chk_logging = active;
    save_config();
}

static void on_log_every_toggled(GtkCheckMenuItem *item, gpointer data) {
    bool active = gtk_check_menu_item_get_active(item);
    ProxyBridge_SetLogEveryConnection(active);
    g_chk_log_every = active;
    save_config();
}

// main switch: pauses the rules for new connections; it is not part of a profile
static void on_enable_toggled(GtkCheckMenuItem *item, gpointer data) {
    ProxyBridge_SetEnabled(gtk_check_menu_item_get_active(item));
    gui_log("ProxyBridge %s", gtk_check_menu_item_get_active(item) ? "enabled" : "paused: new connections are not redirected");
}

// the logo for the title bar, task switcher and dock
static void set_app_icon(void) {
    GList *icons = NULL;
    const struct { const unsigned char *data; size_t len; } src[] = { { gui_icon_128, sizeof gui_icon_128 }, { gui_icon_256, sizeof gui_icon_256 } };
    for (size_t i = 0; i < sizeof src / sizeof *src; i++) {
        GdkPixbufLoader *loader = gdk_pixbuf_loader_new_with_type("png", NULL);
        if (!loader) continue;
        if (gdk_pixbuf_loader_write(loader, src[i].data, src[i].len, NULL) && gdk_pixbuf_loader_close(loader, NULL)) {
            GdkPixbuf *pb = gdk_pixbuf_loader_get_pixbuf(loader);
            if (pb) icons = g_list_append(icons, g_object_ref(pb));
        } else {
            gdk_pixbuf_loader_close(loader, NULL);
        }
        g_object_unref(loader);
    }
    if (icons) {
        gtk_window_set_default_icon_list(icons);
        g_list_free_full(icons, g_object_unref);
    }
}

static void close_open_menus(GtkWidget *menubar) {
    if (menubar) gtk_menu_shell_cancel(GTK_MENU_SHELL(menubar));
}

static void on_active_changed(GObject *w, GParamSpec *pspec, gpointer menubar) {
    if (!gtk_window_is_active(GTK_WINDOW(w))) close_open_menus(menubar);
}

static gboolean on_focus_out(GtkWidget *w, GdkEvent *ev, gpointer menubar) {
    close_open_menus(menubar);
    return FALSE;
}

// ---- Profile > Switch Profile: one radio item per profile, the active one is checked ----
static GtkWidget *switch_menu;
static guint switch_rebuild_source;

static void free_closure_name(gpointer data, GClosure *closure) { g_free(data); }

static gboolean rebuild_switch_menu(gpointer unused) {
    switch_rebuild_source = 0;
    if (!switch_menu) return G_SOURCE_REMOVE;
    GList *kids = gtk_container_get_children(GTK_CONTAINER(switch_menu));
    for (GList *k = kids; k; k = k->next) gtk_widget_destroy(GTK_WIDGET(k->data));
    g_list_free(kids);
    GSList *group = NULL;
    for (GList *l = g_profiles; l; l = l->next) {
        Profile *p = l->data;
        GtkWidget *item = gtk_radio_menu_item_new_with_label(group, p->name);
        group = gtk_radio_menu_item_get_group(GTK_RADIO_MENU_ITEM(item));
        gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(item), strcmp(p->name, g_active_profile) == 0);   // before the handler exists
        g_signal_connect_data(item, "toggled", G_CALLBACK(on_profile_switch_item), g_strdup(p->name), free_closure_name, 0);
        gtk_menu_shell_append(GTK_MENU_SHELL(switch_menu), item);
    }
    gtk_widget_show_all(switch_menu);
    return G_SOURCE_REMOVE;
}

// called after any change of the profile list or of the active profile. Deferred: it is usually called from the handler of a
// menu item that the rebuild would destroy.
void gui_refresh_profile_menu(void) {
    if (!switch_rebuild_source) switch_rebuild_source = g_idle_add(rebuild_switch_menu, NULL);
}

static void on_auto_clear_toggled(GtkCheckMenuItem *item, gpointer data) {
    g_chk_auto_clear = gtk_check_menu_item_get_active(item);
    save_config();
}

static bool boot_syncing;

static void on_boot_toggled(GtkCheckMenuItem *item, gpointer data) {
    if (boot_syncing) return;
    bool want = gtk_check_menu_item_get_active(item);
    char *err = NULL;
    if (!pbc_boot_set(want, &err)) {
        show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Could not %s starting at boot: %s", want ? "enable" : "disable", err ? err : "unknown error");
        g_free(err);
        boot_syncing = true;
        gtk_check_menu_item_set_active(item, pbc_boot_is_enabled());
        boot_syncing = false;
        return;
    }
    g_chk_boot = want;
    save_config();
    if (pbc_is_service())
        gui_log(want ? "Start at Boot is on: the service applies profile '%s' when the machine starts and keeps routing after this window is closed" :
                       "Start at Boot is off: routing stops when this window is closed", g_active_profile);
    else
        gui_log("ProxyBridge %s at boot (service proxybridge.service, profile '%s')", want ? "will start" : "will no longer start", g_active_profile);
}

static void on_update_startup_toggled(GtkCheckMenuItem *item, gpointer data) {
    g_chk_updates = gtk_check_menu_item_get_active(item);
    save_config();
}

static void sync_update_item() {
    if (update_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(update_item), g_chk_updates);
}

// ---- font zoom ----
const char *gui_zoom_css() { return zoom_css; }

static void apply_zoom_css() {
    snprintf(zoom_css, sizeof zoom_css, "window, dialog, messagedialog { font-size: %d%%; }", g_zoom);
    if (!zoom_provider) {
        zoom_provider = gtk_css_provider_new();
        gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(zoom_provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
    }
    gtk_css_provider_load_from_data(zoom_provider, zoom_css, -1, NULL);
}

void gui_set_zoom(int percent) {
    g_zoom = percent < PBP_ZOOM_MIN ? PBP_ZOOM_MIN : percent > PBP_ZOOM_MAX ? PBP_ZOOM_MAX : percent;
    apply_zoom_css();
    save_config();
}

static void on_zoom_in(GtkWidget *w, gpointer d) { gui_set_zoom(g_zoom + 10); }
static void on_zoom_out(GtkWidget *w, gpointer d) { gui_set_zoom(g_zoom - 10); }
static void on_zoom_reset(GtkWidget *w, gpointer d) { gui_set_zoom(100); }

// the switches belong to the profile: after a profile change, show and apply the new profile's values
void gui_sync_switches() {
    ProxyBridge_SetTrafficLoggingEnabled(g_chk_logging);
    ProxyBridge_SetDnsViaProxy(g_chk_dns);
    ProxyBridge_SetLogEveryConnection(g_chk_log_every);
    apply_zoom_css();
    if (clear_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(clear_item), g_chk_auto_clear);
    if (every_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(every_item), g_chk_log_every);
    if (log_item) gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(log_item), g_chk_logging);
}

// same feed as windows/mac: https://download.interceptsuite.com/proxybridge.json
#define UPD_FEED_URL "https://download.interceptsuite.com/proxybridge.json"

static int https_url_ok(const char *url) {
    if (!url || strncmp(url, "https://", 8) != 0) return 0;
    for (const char *p = url; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || c > 126) return 0;
        if (c == ' ' || c == '"' || c == '\'' || c == '`' || c == '\\') return 0;
    }
    return 1;
}

// The browser is opened as root: only the project's own release pages are handed to it.
static int release_host_ok(const char *url) {
    static const char *const hosts[] = { "https://github.com/InterceptSuite/", "https://download.interceptsuite.com/", "https://interceptsuite.com/", "https://www.interceptsuite.com/" };
    for (size_t i = 0; i < sizeof hosts / sizeof *hosts; i++)
        if (g_str_has_prefix(url, hosts[i])) return 1;
    return 0;
}

static const char *update_feed_url() {
#ifdef PB_TEST_HOOKS
    const char *override = getenv("PB_UPDATE_FEED");      // only in the UI test build: the shipped program always uses the real feed
    if (override && *override) return override;
#endif
    return UPD_FEED_URL;
}

typedef struct {
    char *version, *download, *notes;
    char *problem;                 // why no answer could be had
    GtkMessageType problem_type;
    bool newer;
    bool startup;                  // started by the program, not by the user: stay quiet unless there is news
} UpdateInfo;

static void update_free(UpdateInfo *u) {
    g_free(u->version); g_free(u->download); g_free(u->notes); g_free(u->problem);
    g_free(u);
}

// Asks the feed (curl) and compares versions. Runs on any thread.
static UpdateInfo *update_lookup(void) {
    UpdateInfo *u = g_malloc0(sizeof *u);
    char *argv[] = {
        (char *)"curl", (char *)"-sS", (char *)"-m", (char *)"15", (char *)"--proto", (char *)"=https,file",
        (char *)"-H", (char *)"User-Agent: ProxyBridge-UpdateChecker", (char *)"--",
        (char *)update_feed_url(),
        NULL
    };
    char *json = NULL, *curl_err = NULL;
    GError *spawn_err = NULL;
    int exit_code = 0;
    if (!g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL, &json, &curl_err, &exit_code, &spawn_err)) {
        u->problem = g_strdup_printf("Update check failed: %s", spawn_err ? spawn_err->message : "unknown");
        u->problem_type = GTK_MESSAGE_ERROR;
        if (spawn_err) g_error_free(spawn_err);
        g_free(curl_err);
        return u;
    }
    if (!g_spawn_check_wait_status(exit_code, NULL) || !json || json[0] == '\0') {
        u->problem = g_strdup("Update check failed (could not fetch the update feed).");
        u->problem_type = GTK_MESSAGE_ERROR;
        g_free(json); g_free(curl_err);
        return u;
    }
    // the same strict parser and version check as the command line program (the feed is remote input)
    char *version = NULL, *download = NULL, *notes = NULL;
    int rc = pbp_update_parse(json, strlen(json), &version, &download, &notes);
    g_free(json);
    g_free(curl_err);
    if (rc != 0) {
        u->problem = g_strdup("Could not parse linux update info.");
        u->problem_type = GTK_MESSAGE_WARNING;
        return u;
    }
    u->version = g_strdup(version); u->download = g_strdup(download ? download : ""); u->notes = g_strdup(notes ? notes : "");
    free(version); free(download); free(notes);
    u->newer = pbp_version_newer(u->version, PROXYBRIDGE_VERSION);
    return u;
}

// Opens an address in the default browser. The tests build records the address in a file instead (no browser in a test display).
static void open_in_browser(const char *url) {
#ifdef PB_TEST_HOOKS
    const char *log = getenv("PB_OPEN_URL_LOG");
    if (log && *log) {
        FILE *f = fopen(log, "a");
        if (f) { fprintf(f, "%s\n", url); fclose(f); }
        return;
    }
#endif
    GError *uri_err = NULL;
    if (!gtk_show_uri_on_window(GTK_WINDOW(window), url, GDK_CURRENT_TIME, &uri_err)) {
        show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "Could not open browser: %s", uri_err ? uri_err->message : "unknown");
        if (uri_err) g_error_free(uri_err);
    }
}

// Main thread. A user-started check reports everything; a start-up check only speaks up when a newer version exists.
static void update_show(UpdateInfo *u) {
    if (u->problem) {
        if (!u->startup) show_message(GTK_WINDOW(window), u->problem_type, "%s", u->problem);
        return;
    }
    if (!u->newer) {
        if (!u->startup) show_message(GTK_WINDOW(window), GTK_MESSAGE_INFO, "You are using the latest version (%s).", PROXYBRIDGE_VERSION);
        return;
    }
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_NONE,
        "Version %s is available (current %s).\nOpen the download page in your browser?",
        u->version, PROXYBRIDGE_VERSION);
    gtk_dialog_add_button(GTK_DIALOG(dialog), "Open in Browser", GTK_RESPONSE_ACCEPT);
    gtk_dialog_add_button(GTK_DIALOG(dialog), "Close", GTK_RESPONSE_CANCEL);
    if (u->startup) gtk_dialog_add_button(GTK_DIALOG(dialog), "Don't Check at Startup", GTK_RESPONSE_REJECT);
    int resp = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    if (resp == GTK_RESPONSE_REJECT) {
        g_chk_updates = false;
        save_config();
        sync_update_item();
    } else if (resp == GTK_RESPONSE_ACCEPT) {
        const char *url = NULL;                   // only pages of the project itself are opened in a browser running as root
        if (https_url_ok(u->notes) && release_host_ok(u->notes)) url = u->notes;
        else if (https_url_ok(u->download) && release_host_ok(u->download)) url = u->download;
        if (!url) {
            show_message(GTK_WINDOW(window), GTK_MESSAGE_ERROR, "No safe https url in update feed.");
        } else {
            open_in_browser(url);
        }
    }
}

// same address as the Windows app's Help > Documentation
#define DOCS_URL "https://proxybridge.interceptsuite.com/docs/"

static void on_documentation(GtkWidget *widget, gpointer data) {
    open_in_browser(DOCS_URL);
}

static void on_check_update(GtkWidget *widget, gpointer data) {
    UpdateInfo *u = update_lookup();
    update_show(u);
    update_free(u);
}

static gboolean update_show_idle(gpointer data) {
    UpdateInfo *u = data;
    update_show(u);
    update_free(u);
    return G_SOURCE_REMOVE;
}

static gpointer update_startup_thread(gpointer data) {
    UpdateInfo *u = update_lookup();
    u->startup = true;
    g_idle_add(update_show_idle, u);
    return NULL;
}

// Looks for a new version without blocking the window (the answer arrives on the main loop).
void gui_check_updates_on_startup() {
    g_thread_unref(g_thread_new("update_check", update_startup_thread, NULL));
}

static void on_about(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("About ProxyBridge", GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_MODAL, "OK", GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 400, 300);
    gtk_widget_set_name(dialog, "dlg_about");
    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content_area), 20);
    char *markup = g_strdup_printf(
        "<span size='xx-large' weight='bold'>ProxyBridge</span>\n"
        "<span color='gray'>Version %s</span>\n\n"
        "Universal proxy client for Linux applications\n"
        "eBPF backend, run by the ProxyBridge service (root);\nkernel 5.11+ with BTF and cgroup v2\n\n"
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
    // With the service the engine belongs to the service: closing the window must not switch routing off
    // Start at Boot keeps the service routing after the window closes; without it routing ends with the window, as it always did
    if (engine_state == ENGINE_RUNNING && (!pbc_is_service() || !g_chk_boot)) ProxyBridge_Stop();
    engine_state = ENGINE_STOPPED;
    pbc_disconnect();
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
    const char *prefix = strcmp(title, "Connections") == 0 ? "conn" : "log";     // widget names for the UI test
    char wname[32];
    snprintf(wname, sizeof wname, "%s_search", prefix); gtk_widget_set_name(search, wname);
    gtk_entry_set_placeholder_text(GTK_ENTRY(search), placeholder);
    g_signal_connect(search, "search-changed", on_search, NULL);
    GtkWidget *clear_btn = gtk_button_new_with_label("Clear Logs");
    snprintf(wname, sizeof wname, "%s_clear", prefix); gtk_widget_set_name(clear_btn, wname);
    g_signal_connect(clear_btn, "clicked", on_clear, NULL);
    gtk_box_pack_start(GTK_BOX(toolbar), search, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(toolbar), clear_btn, FALSE, FALSE, 0);
    if (on_pause) {
        GtkWidget *pause_btn = gtk_toggle_button_new_with_label("Pause");
        snprintf(wname, sizeof wname, "%s_pause", prefix); gtk_widget_set_name(pause_btn, wname);
        g_signal_connect(pause_btn, "toggled", on_pause, NULL);
        gtk_box_pack_start(GTK_BOX(toolbar), pause_btn, FALSE, FALSE, 0);
    }
    gtk_box_pack_start(GTK_BOX(tab), toolbar, FALSE, FALSE, 0);

    GtkWidget *view = gtk_text_view_new();
    snprintf(wname, sizeof wname, "%s_view", prefix); gtk_widget_set_name(view, wname);
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

// set only by the UI test: it drives the finished window instead of the user and returns when it is done
void (*pb_gui_ready_hook)(void) = NULL;

// ---- Live Connections tab ----
static GtkListStore *flows_store;
static GtkWidget *flows_tree, *flows_page;

static char *human_bytes(uint64_t b) {
    if (b < 1024) return g_strdup_printf("%llu B", (unsigned long long)b);
    if (b < 1024 * 1024) return g_strdup_printf("%.1f KB", b / 1024.0);
    if (b < 1024ULL * 1024 * 1024) return g_strdup_printf("%.1f MB", b / (1024.0 * 1024));
    return g_strdup_printf("%.2f GB", b / (1024.0 * 1024 * 1024));
}

void gui_refresh_flows() {
    if (!flows_store) return;
    static ProxyBridgeFlow flows[PB_FLOWS_MAX];
    uint32_t n = ProxyBridge_GetFlows(flows, PB_FLOWS_MAX);
    gtk_list_store_clear(flows_store);
    for (uint32_t i = 0; i < n; i++) {
        const ProxyBridgeFlow *f = &flows[i];
        const char *proxy = "?";
        for (GList *l = g_proxies_list; l != NULL; l = l->next)
            if (((ProxyData *)l->data)->id == f->proxy_id) proxy = ((ProxyData *)l->data)->name;
        char *dest = f->is_ipv6 ? g_strdup_printf("[%s]:%u", f->host, f->port) : g_strdup_printf("%s:%u", f->host, f->port);
        char *age = g_strdup_printf("%u s", f->age_ms / 1000);
        char *sent = human_bytes(f->sent), *recv = human_bytes(f->received);
        GtkTreeIter it;
        gtk_list_store_append(flows_store, &it);
        gtk_list_store_set(flows_store, &it, 0, f->name, 1, (guint)f->pid, 2, dest, 3, f->is_udp ? "UDP" : "TCP", 4, proxy, 5, age, 6, sent, 7, recv, -1);
        g_free(dest); g_free(age); g_free(sent); g_free(recv);
    }
}

static gboolean flows_tick(gpointer data) {
    if (flows_page && gtk_widget_get_mapped(flows_page)) gui_refresh_flows();
    return G_SOURCE_CONTINUE;
}

static GtkWidget *add_flows_tab(GtkWidget *notebook) {
    flows_store = gtk_list_store_new(8, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    flows_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(flows_store));
    gtk_widget_set_name(flows_tree, "flows_tree");
    g_object_unref(flows_store);
    const char *titles[] = {"Process", "PID", "Destination", "Proto", "Proxy", "Age", "Sent", "Received"};
    for (int i = 0; i < 8; i++) {
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(titles[i], gtk_cell_renderer_text_new(), "text", i, NULL);
        gtk_tree_view_column_set_resizable(c, TRUE);
        gtk_tree_view_column_set_expand(c, i == 2);
        gtk_tree_view_append_column(GTK_TREE_VIEW(flows_tree), c);
    }
    flows_page = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(flows_page), flows_tree);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), flows_page, gtk_label_new("Live Connections"));
    return flows_page;
}

// The service went away (restarted, updated, stopped). Try again every two seconds and send the window's configuration once it is back.
static guint reconnect_source;
static bool resume_engine;                      // the engine was running when the connection broke: start it again afterwards

static gboolean reconnect_tick(gpointer data) {
    if (!pbc_reconnect()) return G_SOURCE_CONTINUE;
    reconnect_source = 0;
    pbc_BeginBatch();
    ProxyBridge_ClearRules();
    apply_proxies_to_lib();
    apply_rules_to_lib();
    pbc_EndBatch();
    gui_sync_switches();
    ProxyBridge_SetEnabled(gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(enable_item)));
    set_engine_state(pbc_service_engine_running() ? ENGINE_RUNNING : ENGINE_STOPPED);
    if (resume_engine) engine_request(true);          // a restarted service that is not set to start at boot waits for us
    resume_engine = false;
    gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, "Connected to the ProxyBridge service again.");
    gui_log("connected to the ProxyBridge service again");
    return G_SOURCE_REMOVE;
}

static gboolean service_lost_idle(gpointer data) {
    if (reconnect_source) return G_SOURCE_REMOVE;
    gtk_statusbar_push(GTK_STATUSBAR(status_bar), status_context_id, "Lost the connection to the ProxyBridge service. Trying to reconnect...");
    gui_log("lost the connection to the ProxyBridge service; trying to reconnect");
    resume_engine = engine_state == ENGINE_RUNNING;
    set_engine_state(ENGINE_STOPPED);
    reconnect_source = g_timeout_add_seconds(2, reconnect_tick, NULL);
    return G_SOURCE_REMOVE;
}

static void on_service_lost(void) {            // reader thread
    g_idle_add(service_lost_idle, NULL);
}

int main(int argc, char *argv[]) {
    setenv("GSETTINGS_BACKEND", "memory", 1);
    // Prefer the ProxyBridge service: the window then needs no root. Without a service, a window started as root runs the engine itself.
    char link_err[256] = "";
    int link = pbc_connect(NULL, link_err, sizeof link_err);
    if (link == PBC_CONNECTED) {
        gui_store_use(&pbc_store);
    } else if (link == PBC_REFUSED || getuid() != 0) {
        gtk_init(&argc, &argv);
        if (link == PBC_REFUSED)
            show_message(NULL, GTK_MESSAGE_ERROR, "%s\n\nIf this is a permissions problem, add your user to the group that may control ProxyBridge:\n    sudo usermod -aG proxybridge $USER", link_err);
        else
            show_message(NULL, GTK_MESSAGE_ERROR, "The ProxyBridge service is not running.\n\nStart it with:\n    sudo systemctl enable --now proxybridge\n\n(or run this window with sudo to use ProxyBridge without the service).");
        return 1;
    }
    load_config();
    gtk_init(&argc, &argv);

    GtkSettings *settings = gtk_settings_get_default();
    if (settings) g_object_set(settings, "gtk-application-prefer-dark-theme", TRUE, NULL);

    set_app_icon();
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char *win_title = g_strdup_printf("ProxyBridge - %s", g_active_profile);
    gtk_window_set_title(GTK_WINDOW(window), win_title);
    g_free(win_title);
    gtk_window_set_default_size(GTK_WINDOW(window), 900, 600);
    g_signal_connect(window, "destroy", G_CALLBACK(on_window_destroy), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    GtkWidget *menubar = gtk_menu_bar_new();
    // An open menu holds a grab. When the user moves to another program (often a native Wayland window this X11 client
    // never gets pointer events from) the menu would stay on top of it: close it as soon as this window loses focus.
    // Only on X11, where a menu holds a grab that can outlive a switch to another program. On Wayland (the window now runs as the user, so
    // it is a native Wayland window) opening a menu moves the keyboard focus to the menu's own popup: closing menus when the window
    // "loses focus" would close every menu the moment it opens, and the compositor already dismisses popups itself.
    GdkDisplay *gdisp = gdk_display_get_default();
    if (gdisp && strcmp(G_OBJECT_TYPE_NAME(gdisp), "GdkX11Display") == 0) {
        g_signal_connect(window, "notify::is-active", G_CALLBACK(on_active_changed), menubar);
        g_signal_connect(window, "focus-out-event", G_CALLBACK(on_focus_out), menubar);
    }
    // The same four menus as the Windows app: Proxy, Profile, Settings, Help
    GtkWidget *proxy_menu = add_submenu(menubar, "Proxy");
    enable_item = add_check_item(proxy_menu, "Enable ProxyBridge", true, G_CALLBACK(on_enable_toggled));      // the main on/off switch
    start_item = add_menu_item(proxy_menu, "Start Engine", G_CALLBACK(on_start_engine));
    stop_item = add_menu_item(proxy_menu, "Stop Engine", G_CALLBACK(on_stop_engine));
    add_separator(proxy_menu);
    add_menu_item(proxy_menu, "Proxy Settings...", G_CALLBACK(on_proxy_configure));
    add_menu_item(proxy_menu, "Proxy Rules...", G_CALLBACK(on_proxy_rules_clicked));
    add_menu_item(proxy_menu, "Log Filters...", G_CALLBACK(on_log_filters_clicked));
    add_separator(proxy_menu);
    add_menu_item(proxy_menu, "Exit", G_CALLBACK(on_window_destroy));
    // like the Windows app: Profile is a menu of its own and every item acts at once on the active profile
    GtkWidget *profile_menu = add_submenu(menubar, "Profile");
    add_menu_item(profile_menu, "New Profile...", G_CALLBACK(on_profile_new));
    add_menu_item(profile_menu, "Duplicate Profile...", G_CALLBACK(on_profile_duplicate));
    add_menu_item(profile_menu, "Rename Profile...", G_CALLBACK(on_profile_rename));
    add_menu_item(profile_menu, "Delete Profile...", G_CALLBACK(on_profile_delete));
    add_separator(profile_menu);
    add_menu_item(profile_menu, "Import Profile...", G_CALLBACK(on_profile_import));
    add_menu_item(profile_menu, "Export Profile...", G_CALLBACK(on_profile_export));
    add_separator(profile_menu);
    GtkWidget *switch_item = gtk_menu_item_new_with_label("Switch Profile");
    switch_menu = gtk_menu_new();
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(switch_item), switch_menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(profile_menu), switch_item);
    rebuild_switch_menu(NULL);
    GtkWidget *settings_menu = add_submenu(menubar, "Settings");
    log_item = add_check_item(settings_menu, "Enable Traffic Logging", g_chk_logging, G_CALLBACK(on_log_traffic_toggled));
    boot_item = add_check_item(settings_menu, "Start at Boot (systemd service)", pbc_boot_is_enabled(), G_CALLBACK(on_boot_toggled));
    clear_item = add_check_item(settings_menu, "Auto-clear Logs", g_chk_auto_clear, G_CALLBACK(on_auto_clear_toggled));
    every_item = add_check_item(settings_menu, "Log Every Connection", g_chk_log_every, G_CALLBACK(on_log_every_toggled));
    update_item = add_check_item(settings_menu, "Check for Updates on Startup", g_chk_updates, G_CALLBACK(on_update_startup_toggled));
    add_separator(settings_menu);
    GtkAccelGroup *accel = gtk_accel_group_new();
    gtk_window_add_accel_group(GTK_WINDOW(window), accel);
    GtkWidget *zin = add_menu_item(settings_menu, "Zoom In", G_CALLBACK(on_zoom_in));
    GtkWidget *zout = add_menu_item(settings_menu, "Zoom Out", G_CALLBACK(on_zoom_out));
    GtkWidget *zreset = add_menu_item(settings_menu, "Reset Zoom", G_CALLBACK(on_zoom_reset));
    gtk_widget_add_accelerator(zin, "activate", accel, GDK_KEY_plus, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(zin, "activate", accel, GDK_KEY_equal, GDK_CONTROL_MASK, GTK_ACCEL_MASK);
    gtk_widget_add_accelerator(zout, "activate", accel, GDK_KEY_minus, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    gtk_widget_add_accelerator(zreset, "activate", accel, GDK_KEY_0, GDK_CONTROL_MASK, GTK_ACCEL_VISIBLE);
    GtkWidget *help_menu = add_submenu(menubar, "Help");
    add_menu_item(help_menu, "Documentation", G_CALLBACK(on_documentation));
    add_menu_item(help_menu, "Check for Updates...", G_CALLBACK(on_check_update));
    add_separator(help_menu);
    add_menu_item(help_menu, "About", G_CALLBACK(on_about));
    gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);

    GtkWidget *notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 0);
    conn_buffer = add_text_tab(notebook, "Connections", "Search connections...", G_CALLBACK(on_search_conn_changed), G_CALLBACK(on_clear_conn_clicked), G_CALLBACK(on_pause_conn_toggled));
    log_buffer = add_text_tab(notebook, "Activity Logs", "Search logs...", G_CALLBACK(on_search_log_changed), G_CALLBACK(on_clear_log_clicked), NULL);
    add_flows_tab(notebook);
    g_timeout_add_seconds(1, flows_tick, NULL);

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
    ProxyBridge_SetConnectionCallbackEx(lib_connection_callback_ex);
    ProxyBridge_SetTrafficLoggingEnabled(g_chk_logging);
    ProxyBridge_SetDnsViaProxy(g_chk_dns);
    ProxyBridge_SetLogEveryConnection(g_chk_log_every);
    pbc_BeginBatch();                       // the service loads the whole configuration at once, never half of it
    apply_proxies_to_lib();
    apply_rules_to_lib();
    pbc_EndBatch();
    if (pbc_is_service()) {
        pbc_set_lost_callback(on_service_lost);
        pbc_replay_history(lib_log_callback);   // what the service did before this window opened
        ProxyBridge_SetEnabled(true);           // "Enable ProxyBridge" always starts on; the service may have been left paused by an earlier window
        gui_log("connected to the ProxyBridge service%s", g_chk_boot ? " (Start at Boot is on: it keeps routing when this window is closed)" : "");
    }

    g_unix_signal_add(SIGINT, on_unix_signal, NULL);
    g_unix_signal_add(SIGTERM, on_unix_signal, NULL);

    gtk_widget_show_all(window);
    update_status_info();
    status_source = g_timeout_add_seconds(1, status_tick, NULL);
    if (pbc_is_service()) set_engine_state(pbc_service_engine_running() ? ENGINE_RUNNING : ENGINE_STOPPED);   // it may already be routing (Start at Boot)
    engine_request(true);                                                                                       // does nothing when it is
    apply_zoom_css();
    if (g_chk_updates && !pb_gui_ready_hook) gui_check_updates_on_startup();
    if (pb_gui_ready_hook) pb_gui_ready_hook();
    else gtk_main();

    shutdown_engine();
    gui_logs_free();
    config_free_all();
    return 0;
}
