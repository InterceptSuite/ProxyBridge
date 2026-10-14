#include "gui.h"

// safer way to turn string to int
long safe_strtol(const char *nptr) {
    if (!nptr) return 0; // null check
    char *endptr;
    long val = strtol(nptr, &endptr, 10);
    if (endptr == nptr) return 0; // bad input
    return val;
}

// show popup msg
void show_message(GtkWindow *parent, GtkMessageType type, const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *msg = g_strdup_vprintf(format, args);
    va_end(args);

    GtkWidget *dialog = gtk_message_dialog_new(parent,
                                            GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_MODAL,
                                            type,
                                            GTK_BUTTONS_OK,
                                            "%s", msg);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    g_free(msg);
}

// keep log size under control so we dont use too much ram
void trim_buffer_lines(GtkTextBuffer *buffer, int max_lines) {
    if (gtk_text_buffer_get_line_count(buffer) > max_lines) {
        GtkTextIter start, next;
        gtk_text_buffer_get_start_iter(buffer, &start);
        next = start;
        gtk_text_iter_forward_line(&next);
        gtk_text_buffer_delete(buffer, &start, &next);
    }
}

char* get_current_time_str() {
    time_t rawtime;
    struct tm *timeinfo;
    char *buffer = g_malloc0(32);
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    if (!timeinfo || strftime(buffer, 32, "[%H:%M:%S]", timeinfo) == 0) buffer[0] = '\0';
    return buffer; // free with g_free
}

// json stuff
char *escape_json_string(const char *src) {
    if (!src) return g_strdup("");
    GString *str = g_string_new("");
    for (const char *p = src; *p; p++) {
        if (*p == '\\') g_string_append(str, "\\\\");
        else if (*p == '"') g_string_append(str, "\\\"");
        else if (*p == '\n') g_string_append(str, "\\n");
        else if (*p == '\r') g_string_append(str, "\\r");
        else if (*p == '\t') g_string_append(str, "\\t");
        else if ((unsigned char)*p < 0x20) g_string_append_printf(str, "\\u%04x", (unsigned char)*p);
        else g_string_append_c(str, *p);
    }
    return g_string_free(str, FALSE);
}

// basic parser, good enough for valid inputs. returns NULL if the key is missing or its value is not a string
char *extract_sub_json_str(const char *json, const char *key) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);
    const char *k = strstr(json, search_key);
    if (!k) return NULL;
    const char *colon = strchr(k + strlen(search_key), ':');
    if (!colon) return NULL;
    const char *v = colon + 1;
    while (*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
    if (*v != '"') return NULL;
    v++;

    // copy up to the closing quote, handling escapes
    GString *out = g_string_new("");
    while (*v && *v != '"') {
        if (*v == '\\' && v[1]) {
            v++;
            switch (*v) {
                case 'n': g_string_append_c(out, '\n'); break;
                case 'r': g_string_append_c(out, '\r'); break;
                case 't': g_string_append_c(out, '\t'); break;
                default: g_string_append_c(out, *v); break; // \\ \" \/
            }
        } else {
            g_string_append_c(out, *v);
        }
        v++;
    }
    if (*v != '"') { g_string_free(out, TRUE); return NULL; }
    return g_string_free(out, FALSE);
}

// true if the key is present at all (extract_sub_json_bool cant tell false from missing)
bool json_has_key(const char *json, const char *key) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);
    return strstr(json, search_key) != NULL;
}

bool extract_sub_json_bool(const char *json, const char *key) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);
    char *k = strstr(json, search_key);
    if (!k) return false;
    char *colon = strchr(k, ':');
    if (!colon) return false;
    // skip whitespace
    char *v = colon + 1;
    while(*v == ' ' || *v == '\t' || *v == '\n' || *v == '\r') v++;
    if (strncmp(v, "true", 4) == 0) return true;
    return false;
}
