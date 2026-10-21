#ifndef PROXYBRIDGE_GUI_H
#define PROXYBRIDGE_GUI_H

#include <unistd.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ProxyBridge.h"
#include "pb_profile.h"

typedef struct {
    uint32_t id;            // library id, 0 = not registered
    char *name;             // unique key, rules and config refer to it
    ProxyType type;
    char *host;
    uint16_t port;
    char *username;
    char *password;
    bool send_domain;       // DNS via proxy: the proxy resolves host names (default on, like Windows and macOS)
} ProxyData;

typedef struct {
    uint32_t id;
    char *name;             // label, may be empty
    char *process_name;
    char *target_hosts;
    char *target_ports;
    RuleProtocol protocol;
    RuleAction action;
    char *proxy_name;       // NULL or "" = default proxy
    bool localhost;         // PROXY rule that also proxies loopback traffic
    bool enabled;
    bool selected;
} RuleData;

// lists are only current while the profile is inactive, see profile_sync_active
typedef struct {
    char *name;
    GList *proxies;
    char *default_proxy;
    GList *rules;
    bool logging, dns, log_every;   // traffic logging, DNS via proxy and "log every connection", stored in the profile like the Windows app does
    bool auto_clear;                // wipe a log once it passes 500 lines
    int zoom;                       // font zoom in percent, 60-300
    struct pbp_filter *filters;     // connection-log filters (malloc'd strings, freed with the profile)
    size_t nfilters;
    char *saved;            // what is on disk, to skip rewriting unchanged profiles
} Profile;

// Where profiles and settings.json are kept: files (a window with its own engine, running as root) or the ProxyBridge service.
struct gui_store {
    bool   (*list)(GPtrArray *names);                                   // appends g_strdup'd profile names
    char  *(*get)(const char *name);                                    // g_malloc'd file content, or NULL
    bool   (*put)(const char *name, const char *data, char *err, size_t errn);
    bool   (*del)(const char *name);
    bool   (*exists)(const char *name);
    bool   (*settings_get)(char **active, bool *check_updates, bool *start_at_boot);   // *active g_malloc'd or NULL
    bool   (*settings_set)(const char *active, bool check_updates, bool start_at_boot, char *err, size_t errn);
    char  *(*legacy_get)(void);                                          // text of a config.ini from an older version, g_malloc'd, or NULL
    void   (*legacy_done)(void);                                         // set that file aside (config.ini.bak) once it has been converted
};
extern const struct gui_store gui_store_files;
extern const struct gui_store pbc_store;          // pb_client.c
void gui_store_use(const struct gui_store *s);

typedef void (*RuleImportCb)(const RuleData *rule, int index, void *ud);

extern GtkWidget *window;
extern GtkTextBuffer *conn_buffer;
extern GtkTextBuffer *log_buffer;
extern GtkWidget *status_bar;
extern guint status_context_id;

// avoids libc strto*/atoi, glibc 2.38 redirects them to symbols old systems lack
static inline long parse_long(const char *s) {
    return s ? (long)g_ascii_strtoll(s, NULL, 10) : 0;
}

extern GList *g_profiles;
extern char *g_active_profile;
extern GList *g_proxies_list;   // working copy of the active profile
extern char *g_default_proxy;
extern GList *g_rules_list;
extern bool g_chk_logging;
extern bool g_chk_dns;
extern bool g_chk_log_every;
extern bool g_chk_auto_clear;
extern int g_zoom;
extern bool g_chk_boot;      // Start at Boot (settings.json): the service keeps routing after the window closes, and applies the profile at boot
extern bool g_chk_updates;   // check for a new version when the program starts (settings.json, not per profile)

void show_message(GtkWindow *parent, GtkMessageType type, const char *format, ...);
GtkWidget *combo_new(const char *first, ...) G_GNUC_NULL_TERMINATED;
GtkWidget *hint_label(const char *text);
void set_error_label(GtkWidget *label, const char *msg);
void grid_row(GtkWidget *grid, int row, const char *label, GtkWidget *widget);

// Target Host list helpers (gui_list.c): the editor shows one entry per line, the engine gets one clean ";" list.
char *list_normalize(const char *in);   // g_free() the result
char *list_format(const char *in);      // g_free() the result

char *extract_sub_json_str(const char *json, const char *key);
int rules_from_json(const char *json, RuleImportCb cb, void *ud);
char *rules_to_json(GList *rules, bool only_selected);

// Filters of the active profile. The edit functions take ownership of the array and refresh the log view.
struct pbp_filter *gui_filters(size_t *n);
void gui_filters_replace(struct pbp_filter *filters, size_t n);
struct pbp_filter pbp_filter_dup(const struct pbp_filter *f);
void pbp_filter_clear(struct pbp_filter *f);
void gui_logs_set_filters(const struct pbp_filter *f, size_t n);
void on_log_filters_clicked(GtkWidget *widget, gpointer data);
void gui_set_zoom(int percent);   // clamps to 60-300, applies and saves
const char *gui_zoom_css();
void gui_check_updates_on_startup();
void gui_sync_switches();
void gui_refresh_flows();   // refreshes the Live Connections tab from the engine   // pushes the active profile's logging/DNS switches to the engine and the menu
void save_config();
void load_config();
void config_free_all();
Profile *profile_find(const char *name);
Profile *profile_create(const char *name, bool copy_active);
bool profile_rename(Profile *p, const char *new_name);
bool profile_activate(const char *name);
bool profile_delete(Profile *p);
bool profile_export(const Profile *prof, const char *path, char *err, size_t errlen);
Profile *profile_import(const char *path, char *err, size_t errlen);   // not activated

void on_proxy_configure(GtkWidget *widget, gpointer data);
// Profile menu: every action works on the active profile
void on_profile_new(GtkWidget *widget, gpointer data);
void on_profile_duplicate(GtkWidget *widget, gpointer data);
void on_profile_rename(GtkWidget *widget, gpointer data);
void on_profile_delete(GtkWidget *widget, gpointer data);
void on_profile_import(GtkWidget *widget, gpointer data);
void on_profile_export(GtkWidget *widget, gpointer data);
void on_profile_switch_item(GtkWidget *item, gpointer data);       // data: the profile name
void gui_refresh_profile_menu(void);                               // rebuilds Profile > Switch (main.c)
ProxyData *find_proxy_by_name(const char *name);
uint32_t resolve_proxy_id(const char *name);
void free_proxy_data(ProxyData *p);
void apply_proxies_to_lib();

void on_proxy_rules_clicked(GtkWidget *widget, gpointer data);
void free_rule_data(RuleData *rule);
void apply_rules_to_lib();
void refresh_rules_window();

void gui_log(const char *format, ...);
void lib_log_callback(const char *message);
void lib_connection_callback_ex(const char *process_name, uint32_t pid, const char *dest_ip, uint16_t dest_port, const char *protocol, const char *proxy_info);
void gui_logs_init();
void gui_logs_stop_timers();
void gui_logs_free();
uint64_t gui_conn_event_count();
void on_pause_conn_toggled(GtkToggleButton *button, gpointer user_data);
void on_search_conn_changed(GtkSearchEntry *entry, gpointer user_data);
void on_search_log_changed(GtkSearchEntry *entry, gpointer user_data);
void on_clear_conn_clicked(GtkButton *button, gpointer user_data);
void on_clear_log_clicked(GtkButton *button, gpointer user_data);

// Path of the stored profile file for a profile name (g_malloc'd), or NULL for an unusable name.
char *profile_path(const char *name);

#include "pb_client.h"

#endif
