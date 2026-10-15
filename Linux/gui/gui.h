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

typedef struct {
    uint32_t id;            // library id, 0 = not registered
    char *name;             // unique key, rules and config refer to it
    ProxyType type;
    char *host;
    uint16_t port;
    char *username;
    char *password;
} ProxyData;

typedef struct {
    uint32_t id;
    char *process_name;
    char *target_hosts;
    char *target_ports;
    RuleProtocol protocol;
    RuleAction action;
    char *proxy_name;       // NULL or "" = default proxy
    bool enabled;
    bool selected;
} RuleData;

// lists are only current while the profile is inactive, see profile_sync_active
typedef struct {
    char *name;
    GList *proxies;
    char *default_proxy;
    GList *rules;
    bool logging, dns;      // traffic logging and DNS via proxy, stored in the profile like the Windows app does
    char *saved;            // what is on disk, to skip rewriting unchanged profiles
} Profile;

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

void show_message(GtkWindow *parent, GtkMessageType type, const char *format, ...);
GtkWidget *combo_new(const char *first, ...) G_GNUC_NULL_TERMINATED;
GtkWidget *hint_label(const char *text);
void set_error_label(GtkWidget *label, const char *msg);
void grid_row(GtkWidget *grid, int row, const char *label, GtkWidget *widget);

char *extract_sub_json_str(const char *json, const char *key);
int rules_from_json(const char *json, RuleImportCb cb, void *ud);
char *rules_to_json(GList *rules, bool only_selected);

void gui_sync_switches();   // pushes the active profile's logging/DNS switches to the engine and the menu
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
void on_profiles_clicked(GtkWidget *widget, gpointer data);
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
void lib_connection_callback(const char *process_name, uint32_t pid, const char *dest_ip, uint16_t dest_port, const char *proxy_info);
void gui_logs_init();
void gui_logs_stop_timers();
void gui_logs_free();
uint64_t gui_conn_event_count();
void on_pause_conn_toggled(GtkToggleButton *button, gpointer user_data);
void on_search_conn_changed(GtkSearchEntry *entry, gpointer user_data);
void on_search_log_changed(GtkSearchEntry *entry, gpointer user_data);
void on_clear_conn_clicked(GtkButton *button, gpointer user_data);
void on_clear_log_clicked(GtkButton *button, gpointer user_data);

#endif
