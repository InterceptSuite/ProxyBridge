#include "gui.h"
#include "gui_events.h"
#include <time.h>
#include <pthread.h>

#define RING_CAPACITY 4096
#define SLOT_SIZE 512
#define DRAIN_MAX 2000
#define DRAIN_BUF_SIZE (256 * 1024)
#define DRAIN_INTERVAL_MS 100
#define CONN_HISTORY 2000
#define LOG_HISTORY 1000
#define AUTO_CLEAR_LINES 500      // a log is wiped once it grows past this, when auto-clear is on

typedef struct {
    GtkTextBuffer **buffer;
    EventRing *ring;
    int max_lines;
    char *filter;       // lowercase, NULL = show all
    bool paused;
} View;

static View conn_view = {&conn_buffer, NULL, CONN_HISTORY, NULL, false};
static View log_view = {&log_buffer, NULL, LOG_HISTORY, NULL, false};
static char *drain_buf = NULL;

// Connection-log filters. The library calls the connection callback from its own threads, so the copy has its own lock.
static pthread_mutex_t filter_mu = PTHREAD_MUTEX_INITIALIZER;
static struct pbp_filter *filters;
static size_t nfilters;

void gui_logs_set_filters(const struct pbp_filter *f, size_t n) {
    struct pbp_filter *copy = calloc(n ? n : 1, sizeof *copy);
    for (size_t i = 0; copy && i < n; i++) copy[i] = pbp_filter_dup(&f[i]);
    pthread_mutex_lock(&filter_mu);
    struct pbp_filter *old = filters;
    size_t nold = nfilters;
    filters = copy;
    nfilters = copy ? n : 0;
    pthread_mutex_unlock(&filter_mu);
    for (size_t i = 0; i < nold; i++) pbp_filter_clear(&old[i]);
    free(old);
}
static guint drain_source = 0;

static void filter_from_line(GtkTextBuffer *buffer, int first_line, const char *lower_search) {
    GtkTextIter line_start, buf_end;
    gtk_text_buffer_get_iter_at_line(buffer, &line_start, first_line);
    gtk_text_buffer_get_end_iter(buffer, &buf_end);
    gtk_text_buffer_remove_tag_by_name(buffer, "hidden", &line_start, &buf_end);
    if (!lower_search) return;

    while (!gtk_text_iter_is_end(&line_start)) {
        GtkTextIter line_end = line_start;
        if (!gtk_text_iter_ends_line(&line_end))
            gtk_text_iter_forward_to_line_end(&line_end);

        char *line_text = gtk_text_buffer_get_text(buffer, &line_start, &line_end, FALSE);
        char *lower_line = g_utf8_strdown(line_text, -1);
        if (!strstr(lower_line, lower_search)) {
            GtkTextIter next_line = line_end;
            gtk_text_iter_forward_char(&next_line);
            gtk_text_buffer_apply_tag_by_name(buffer, "hidden", &line_start, &next_line);
        }
        g_free(lower_line);
        g_free(line_text);
        gtk_text_iter_forward_line(&line_start);
    }
}

static void set_filter(View *v, const char *text) {
    g_free(v->filter);
    v->filter = (text && *text) ? g_utf8_strdown(text, -1) : NULL;
    if (*v->buffer) filter_from_line(*v->buffer, 0, v->filter);
}

void on_search_conn_changed(GtkSearchEntry *entry, gpointer user_data) {
    set_filter(&conn_view, gtk_entry_get_text(GTK_ENTRY(entry)));
}

void on_search_log_changed(GtkSearchEntry *entry, gpointer user_data) {
    set_filter(&log_view, gtk_entry_get_text(GTK_ENTRY(entry)));
}

void on_clear_conn_clicked(GtkButton *button, gpointer user_data) {
    if (conn_buffer) gtk_text_buffer_set_text(conn_buffer, "", 0);
}

void on_clear_log_clicked(GtkButton *button, gpointer user_data) {
    if (log_buffer) gtk_text_buffer_set_text(log_buffer, "", 0);
}

void on_pause_conn_toggled(GtkToggleButton *button, gpointer user_data) {
    conn_view.paused = gtk_toggle_button_get_active(button);
}

// one insert, one filter pass over the new lines and one trim per batch
static void append_batch(View *v, const char *text, uint64_t dropped) {
    GtkTextBuffer *buffer = *v->buffer;
    if (!buffer) return;

    GString *batch = g_string_new(text);
    if (dropped) g_string_append_printf(batch, "[%" G_GUINT64_FORMAT " events skipped]\n", dropped);
    if (!g_utf8_validate(batch->str, -1, NULL)) {
        char *fixed = g_utf8_make_valid(batch->str, -1);
        g_string_assign(batch, fixed);
        g_free(fixed);
    }

    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buffer, &end);
    int first_line = gtk_text_iter_get_line(&end);
    gtk_text_buffer_insert(buffer, &end, batch->str, (gint)batch->len);
    g_string_free(batch, TRUE);

    if (v->filter) filter_from_line(buffer, first_line, v->filter);

    int lines = gtk_text_buffer_get_line_count(buffer) - 1;
    if (g_chk_auto_clear && lines > AUTO_CLEAR_LINES) {
        gtk_text_buffer_set_text(buffer, "", 0);
        return;
    }
    int excess = lines - v->max_lines;
    if (excess > 0) {
        GtkTextIter start, cut;
        gtk_text_buffer_get_start_iter(buffer, &start);
        gtk_text_buffer_get_iter_at_line(buffer, &cut, excess);
        gtk_text_buffer_delete(buffer, &start, &cut);
    }
}

static void drain_view(View *v) {
    if (v->paused || !v->ring) return;
    uint64_t dropped = 0;
    size_t n = event_ring_drain(v->ring, drain_buf, DRAIN_BUF_SIZE, DRAIN_MAX, &dropped);
    if (n || dropped) append_batch(v, drain_buf, dropped);
}

static gboolean drain_tick(gpointer user_data) {
    drain_view(&conn_view);
    drain_view(&log_view);
    return G_SOURCE_CONTINUE;
}

void gui_logs_init() {
    drain_buf = g_malloc(DRAIN_BUF_SIZE);
    conn_view.ring = event_ring_new(RING_CAPACITY, SLOT_SIZE);
    log_view.ring = event_ring_new(RING_CAPACITY, SLOT_SIZE);
    drain_source = g_timeout_add(DRAIN_INTERVAL_MS, drain_tick, NULL);
}

void gui_logs_stop_timers() {
    if (drain_source) g_source_remove(drain_source);
    drain_source = 0;
}

// call after the engine stopped, library threads push into the rings until then
void gui_logs_free() {
    gui_logs_stop_timers();
    event_ring_free(conn_view.ring);
    event_ring_free(log_view.ring);
    conn_view.ring = log_view.ring = NULL;
    g_free(conn_view.filter);
    g_free(log_view.filter);
    conn_view.filter = log_view.filter = NULL;
    g_free(drain_buf);
    drain_buf = NULL;
    gui_logs_set_filters(NULL, 0);
}

uint64_t gui_conn_event_count() {
    uint64_t pushed = 0;
    if (conn_view.ring) event_ring_stats(conn_view.ring, &pushed, NULL, NULL);
    return pushed;
}

static void push_line(View *v, const char *fmt, ...) G_GNUC_PRINTF(2, 3);

static void push_line(View *v, const char *fmt, ...) {
    if (!v->ring) return;
    char line[SLOT_SIZE];
    time_t now = time(NULL);
    struct tm tm_now;
    size_t off = 0;
    if (localtime_r(&now, &tm_now)) off = strftime(line, sizeof(line), "[%H:%M:%S] ", &tm_now);
    va_list args;
    va_start(args, fmt);
    g_vsnprintf(line + off, sizeof(line) - off, fmt, args);
    va_end(args);
    event_ring_push(v->ring, line);
}

void lib_log_callback(const char *message) {
    push_line(&log_view, "%s", message ? message : "");
}

void gui_log(const char *format, ...) {
    char msg[SLOT_SIZE];
    va_list args;
    va_start(args, format);
    g_vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);
    lib_log_callback(msg);
}

void lib_connection_callback_ex(const char *process_name, uint32_t pid, const char *dest_ip, uint16_t dest_port, const char *protocol,
                                const char *proxy_info) {
    const char *info = proxy_info ? proxy_info : "";
    const char *action = strcmp(info, "DIRECT") == 0 ? "Direct" : strcmp(info, "BLOCK") == 0 ? "Blocked" : "Proxy";
    char port[8];
    snprintf(port, sizeof port, "%u", dest_port);
    pthread_mutex_lock(&filter_mu);
    bool show = pbp_filters_pass(filters, nfilters, process_name ? process_name : "", dest_ip ? dest_ip : "", port, protocol ? protocol : "", action);
    pthread_mutex_unlock(&filter_mu);
    if (!show) return;
    // like the Windows app: a UDP flow is marked, a TCP connection is not
    push_line(&conn_view, "%s (PID:%u) -> %s:%u via %s%s", process_name ? process_name : "", pid, dest_ip ? dest_ip : "", dest_port, info,
              protocol && !strcmp(protocol, "UDP") ? " (UDP)" : "");
}
