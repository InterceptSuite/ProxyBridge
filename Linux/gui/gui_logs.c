#include "gui.h"

#define MAX_LINES 100

static void filter_text_view(GtkTextBuffer *buffer, const char *text) {
    if (!buffer) return;

    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    gtk_text_buffer_remove_tag_by_name(buffer, "hidden", &start, &end);
    if (!text || !*text) return;

    char *lower_search = g_utf8_strdown(text, -1);
    GtkTextIter line_start = start;
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
    g_free(lower_search);
}

void on_search_conn_changed(GtkSearchEntry *entry, gpointer user_data) {
    filter_text_view(conn_buffer, gtk_entry_get_text(GTK_ENTRY(entry)));
}

void on_search_log_changed(GtkSearchEntry *entry, gpointer user_data) {
    filter_text_view(log_buffer, gtk_entry_get_text(GTK_ENTRY(entry)));
}

void on_clear_conn_clicked(GtkButton *button, gpointer user_data) {
    if (conn_buffer) gtk_text_buffer_set_text(conn_buffer, "", 0);
}

void on_clear_log_clicked(GtkButton *button, gpointer user_data) {
    if (log_buffer) gtk_text_buffer_set_text(log_buffer, "", 0);
}

// library strings are not guaranteed utf8
static void append_line(GtkTextBuffer *buffer, char *line) {
    if (buffer) {
        if (!g_utf8_validate(line, -1, NULL)) {
            char *fixed = g_utf8_make_valid(line, -1);
            g_free(line);
            line = fixed;
        }
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(buffer, &end);
        gtk_text_buffer_insert(buffer, &end, line, -1);
        trim_buffer_lines(buffer, MAX_LINES);
    }
    g_free(line);
}

static gboolean update_log_gui(gpointer user_data) {
    char *time_str = get_current_time_str();
    append_line(log_buffer, g_strdup_printf("%s %s\n", time_str, (char *)user_data));
    g_free(time_str);
    g_free(user_data);
    return FALSE;
}

static gboolean update_connection_gui_append(gpointer user_data) {
    ConnectionData *d = (ConnectionData *)user_data;
    append_line(conn_buffer, g_strdup_printf("%s %s (PID:%u) -> %s:%u via %s\n",
                d->timestamp, d->process_name, d->pid, d->dest_ip, d->dest_port, d->proxy_info));
    g_free(d->process_name);
    g_free(d->dest_ip);
    g_free(d->proxy_info);
    g_free(d->timestamp);
    g_free(d);
    return FALSE;
}

void lib_log_callback(const char *message) {
    g_idle_add(update_log_gui, g_strdup(message ? message : ""));
}

void gui_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *msg = g_strdup_vprintf(format, args);
    va_end(args);
    g_idle_add(update_log_gui, msg);
}

void lib_connection_callback(const char *process_name, uint32_t pid, const char *dest_ip, uint16_t dest_port, const char *proxy_info) {
    ConnectionData *data = g_malloc0(sizeof(ConnectionData));
    data->process_name = g_strdup(process_name ? process_name : "");
    data->pid = pid;
    data->dest_ip = g_strdup(dest_ip ? dest_ip : "");
    data->dest_port = dest_port;
    data->proxy_info = g_strdup(proxy_info ? proxy_info : "");
    data->timestamp = get_current_time_str();
    g_idle_add(update_connection_gui_append, data);
}
