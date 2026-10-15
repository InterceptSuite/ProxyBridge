#include "gui.h"

// Target Host list helpers. Line breaks exist only in the editor, for readability; the engine and the
// saved profile never see them.

// Returns a newly allocated copy without line breaks/control characters, without blanks around the
// separators (';' or ','), without empty entries, joined with ';'. Never longer than the input.
char *list_normalize(const char *in) {
    if (!in) in = "";
    char *out = g_malloc(strlen(in) + 1);
    char *w = out;
    const char *r = in;
    gboolean any = FALSE;
    while (*r) {
        while (*r && (*r == ';' || *r == ',' || (unsigned char)*r <= ' ')) r++;   // separators, blanks, line breaks
        if (!*r) break;
        if (any) *w++ = ';';
        char *last = w;                                                           // end of the entry without trailing blanks
        while (*r && *r != ';' && *r != ',') {
            char c = *r++;
            if ((unsigned char)c < ' ') continue;                                 // a line break inside an entry is ignored
            *w++ = c;
            if (c != ' ') last = w;
        }
        w = last;
        any = TRUE;
    }
    *w = 0;
    return out;
}

// Returns a newly allocated copy with a line break after every ';' (one entry per line).
char *list_format(const char *in) {
    if (!in) in = "";
    size_t n = strlen(in);
    char *out = g_malloc(n * 2 + 1);                       // every ';' grows by one byte
    char *w = out;
    for (const char *p = in; *p; p++) {
        *w++ = *p;
        if (*p == ';') *w++ = '\n';
    }
    *w = 0;
    return out;
}
