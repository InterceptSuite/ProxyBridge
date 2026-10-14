#ifndef PROXYBRIDGE_GUI_H
#define PROXYBRIDGE_GUI_H

#include <unistd.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdarg.h>
#include "ProxyBridge.h"
typedef struct {
    char *process_name;
    uint32_t pid;
    char *dest_ip;
    uint16_t dest_port;
    char *proxy_info;
    char *timestamp;
} ConnectionData;

typedef struct {
    char *message;
} LogData;

typedef struct {
    uint32_t id;            // library proxy id, 0 = not registered with the library
    char *name;             // unique key, also what rules and the config refer to
    ProxyType type;
    char *host;
    uint16_t port;
    char *username;
    char *password;
} ProxyData;

// proxy manager dialog widgets
typedef struct {
    GtkWidget *dialog;
    GtkWidget *tree;
    GtkListStore *store;
    GtkWidget *test_host;
    GtkWidget *test_port;
    GtkTextBuffer *output_buffer;
    GtkWidget *test_btn;
} ConfigInfo;

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

struct TestRunnerData {
    uint32_t proxy_id;
    char *host;
    uint16_t port;
    GtkTextBuffer *buffer;  // referenced, released in the idle callback
    GtkWidget *btn;         // referenced, released in the idle callback
};

typedef struct {
    char *result_text;
    GtkTextBuffer *buffer;
    GtkWidget *btn;
} TestResultData;

extern GtkWidget *window;
extern GtkTextBuffer *conn_buffer;
extern GtkTextBuffer *log_buffer;
extern GtkWidget *status_bar;
extern guint status_context_id;

typedef struct {
    char *name;
    GList *proxies;         // ProxyData, only current while the profile is not active (see profile_sync_active)
    char *default_proxy;
    GList *rules;           // RuleData
} Profile;

extern GList *g_profiles;       // list of Profile
extern char *g_active_profile;  // name of the active profile
extern GList *g_proxies_list;   // list of ProxyData
extern char *g_default_proxy;   // name of the default proxy, NULL if none

extern GList *g_rules_list;
extern bool g_chk_logging;
extern bool g_chk_dns;

long safe_strtol(const char *nptr);
void show_message(GtkWindow *parent, GtkMessageType type, const char *format, ...);
void trim_buffer_lines(GtkTextBuffer *buffer, int max_lines);
char* get_current_time_str();
char *escape_json_string(const char *src);
char *extract_sub_json_str(const char *json, const char *key);
bool extract_sub_json_bool(const char *json, const char *key);
bool json_has_key(const char *json, const char *key);

// config storage
void save_config();
void load_config();
void profile_sync_active();
Profile *profile_find(const char *name);
Profile *profile_create(const char *name, bool copy_active);
bool profile_rename(Profile *p, const char *new_name);
bool profile_activate(const char *name);
bool profile_delete(Profile *p);

// settings / proxies
void on_proxy_configure(GtkWidget *widget, gpointer data);
void on_profiles_clicked(GtkWidget *widget, gpointer data);
ProxyData *find_proxy_by_name(const char *name);
uint32_t resolve_proxy_id(const char *name);
void free_proxy_data(ProxyData *p);
void apply_proxies_to_lib();

// rules section
void on_proxy_rules_clicked(GtkWidget *widget, gpointer data);
void free_rule_data(RuleData *rule);
void apply_rules_to_lib();
void refresh_rules_window();

// Logs
void gui_log(const char *format, ...);
void lib_log_callback(const char *message);
void lib_connection_callback(const char *process_name, uint32_t pid, const char *dest_ip, uint16_t dest_port, const char *proxy_info);
void on_search_conn_changed(GtkSearchEntry *entry, gpointer user_data);
void on_search_log_changed(GtkSearchEntry *entry, gpointer user_data);
void on_clear_conn_clicked(GtkButton *button, gpointer user_data);
void on_clear_log_clicked(GtkButton *button, gpointer user_data);

#endif
