#include "gui.h"

// filter logs based on search
static void filter_text_view(GtkTextBuffer *buffer, const char *text) {
    if (!buffer) return;

    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    gtk_text_buffer_remove_tag_by_name(buffer, "hidden", &start, &end);

    if (!text || strlen(text) == 0) return;

    GtkTextIter line_start = start;
    while (!gtk_text_iter_is_end(&line_start)) {
        GtkTextIter line_end = line_start;
        if (!gtk_text_iter_ends_line(&line_end))
            gtk_text_iter_forward_to_line_end(&line_end);

        char *line_text = gtk_text_buffer_get_text(buffer, &line_start, &line_end, FALSE);

        // search case insensitive
        char *lower_line = g_utf8_strdown(line_text, -1);
        char *lower_search = g_utf8_strdown(text, -1);

        if (!strstr(lower_line, lower_search)) {
             GtkTextIter next_line = line_end;
             gtk_text_iter_forward_char(&next_line); // include newline
             gtk_text_buffer_apply_tag_by_name(buffer, "hidden", &line_start, &next_line);
        }

        g_free(lower_line);
        g_free(lower_search);
        g_free(line_text);

        gtk_text_iter_forward_line(&line_start);
    }
}

void on_search_conn_changed(GtkSearchEntry *entry, gpointer user_data) {
    const char *text = gtk_entry_get_text(GTK_ENTRY(entry));
    filter_text_view(conn_buffer, text);
}

void on_search_log_changed(GtkSearchEntry *entry, gpointer user_data) {
    const char *text = gtk_entry_get_text(GTK_ENTRY(entry));
    filter_text_view(log_buffer, text);
}

void on_clear_conn_clicked(GtkButton *button, gpointer user_data) {
    if (conn_buffer) gtk_text_buffer_set_text(conn_buffer, "", 0);
}

void on_clear_log_clicked(GtkButton *button, gpointer user_data) {
    if (log_buffer) gtk_text_buffer_set_text(log_buffer, "", 0);
}

static void free_connection_data(ConnectionData *data) {
    if (data) {
        g_free(data->process_name);
        g_free(data->dest_ip);
        g_free(data->proxy_info);
        g_free(data->timestamp);
        g_free(data);
    }
}

// update logs from main thread
static gboolean update_log_gui(gpointer user_data) {
    LogData *data = (LogData *)user_data;
    if (!data) return FALSE;

    if (log_buffer) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(log_buffer, &end);

        char *time_str = get_current_time_str();
        char *full_msg = g_strdup_printf("%s %s\n", time_str, data->message);
        g_free(time_str);

        // library strings are not guaranteed utf8
        if (!g_utf8_validate(full_msg, -1, NULL)) {
            char *fixed = g_utf8_make_valid(full_msg, -1);
            g_free(full_msg);
            full_msg = fixed;
        }
        gtk_text_buffer_insert(log_buffer, &end, full_msg, -1);
        g_free(full_msg);

        trim_buffer_lines(log_buffer, 100);
    }

    g_free(data->message);
    g_free(data);
    return FALSE; // done
}

// update conn info
static gboolean update_connection_gui_append(gpointer user_data) {
    ConnectionData *data = (ConnectionData *)user_data;
    if (!data) return FALSE;

    if (conn_buffer) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(conn_buffer, &end);

        char *line_buffer = g_strdup_printf("%s %s (PID:%u) -> %s:%u via %s\n",
                 data->timestamp, data->process_name, data->pid, data->dest_ip, data->dest_port, data->proxy_info);
        if (!g_utf8_validate(line_buffer, -1, NULL)) {
            char *fixed = g_utf8_make_valid(line_buffer, -1);
            g_free(line_buffer);
            line_buffer = fixed;
        }

        gtk_text_buffer_insert(conn_buffer, &end, line_buffer, -1);
        g_free(line_buffer);

        trim_buffer_lines(conn_buffer, 100);
    }

    free_connection_data(data);
    return FALSE;
}

void lib_log_callback(const char *message) {
    LogData *data = g_malloc0(sizeof(LogData));
    data->message = g_strdup(message ? message : "");
    g_idle_add(update_log_gui, data);
}

// log a message from the gui itself, same path as library logs
void gui_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *msg = g_strdup_vprintf(format, args);
    va_end(args);
    lib_log_callback(msg);
    g_free(msg);
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
