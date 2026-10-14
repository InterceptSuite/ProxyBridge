#include "gui.h"

void show_message(GtkWindow *parent, GtkMessageType type, const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *msg = g_strdup_vprintf(format, args);
    va_end(args);

    GtkWidget *dialog = gtk_message_dialog_new(parent, GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_MODAL,
                                               type, GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    g_free(msg);
}

GtkWidget *combo_new(const char *first, ...) {
    GtkWidget *combo = gtk_combo_box_text_new();
    va_list args;
    va_start(args, first);
    for (const char *s = first; s; s = va_arg(args, const char *))
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), s);
    va_end(args);
    return combo;
}

GtkWidget *hint_label(const char *text) {
    GtkWidget *l = gtk_label_new(text);
    gtk_style_context_add_class(gtk_widget_get_style_context(l), "dim-label");
    gtk_widget_set_halign(l, GTK_ALIGN_START);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_label_set_line_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_max_width_chars(GTK_LABEL(l), 60);
    return l;
}

void set_error_label(GtkWidget *label, const char *msg) {
    char *m = g_markup_printf_escaped("<span foreground='#e5534b'>%s</span>", msg);
    gtk_label_set_markup(GTK_LABEL(label), m);
    g_free(m);
}

void grid_row(GtkWidget *grid, int row, const char *label, GtkWidget *widget) {
    GtkWidget *l = gtk_label_new(label);
    gtk_widget_set_halign(l, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), l, 0, row, 1, 1);
    gtk_widget_set_hexpand(widget, TRUE);
    gtk_grid_attach(GTK_GRID(grid), widget, 1, row, 1, 1);
}
