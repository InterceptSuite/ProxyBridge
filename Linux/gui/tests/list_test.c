#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "../gui.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void norm(const char *in, const char *want) {
    char *g = list_normalize(in);
    if (strcmp(g, want)) { printf("FAIL [%s] -> [%s] want [%s]\n", in, g, want); fails++; }
    g_free(g);
}

int main(void) {
    norm("google.com;\n*.google.com;\n*.gstatic.com;\ngithub.com;\n*.github.com;\n", "google.com;*.google.com;*.gstatic.com;github.com;*.github.com");
    norm("  a ; b ,c  ", "a;b;c");
    norm("a\r\nb", "ab");                  // a line break alone is not a separator
    norm(";;;", ""); norm("", ""); norm("  \r\n\t ", "");
    norm("a;;b;;;c;", "a;b;c");
    norm("*", "*");
    norm("a b ; c", "a b;c");
    norm("\x01x\x02;y", "x;y");
    norm("\xc3\xa9xample.com;\n b.org", "\xc3\xa9xample.com;b.org");   // UTF-8 passes through
    { char *nn = list_normalize(NULL); CHECK(nn != NULL); g_free(nn); }

    char *f = list_format("a;b;c"); CHECK(!strcmp(f, "a;\nb;\nc")); g_free(f);
    f = list_format(""); CHECK(!strcmp(f, "")); g_free(f);
    f = list_format("a;"); CHECK(!strcmp(f, "a;\n")); g_free(f);
    {   // normalise(format(x)) == x for a clean list
        char *x = list_normalize("a.com; b.com ;c.com"); char *y = list_format(x); char *z = list_normalize(y);
        CHECK(!strcmp(x, z)); g_free(x); g_free(y); g_free(z);
    }
    srand(1);                              // random input: result never longer, never contains control chars or ',', no edge ';'
    const char alpha[] = "ab;, \r\n\t.*\x01Z";
    for (int it = 0; it < 100000; it++) {
        int n = rand() % 80; char *in = g_malloc(n + 1);
        for (int i = 0; i < n; i++) in[i] = alpha[rand() % (int)(sizeof alpha - 1)];
        in[n] = 0;
        char *o = list_normalize(in); size_t m = strlen(o);
        CHECK(m <= (size_t)n);
        for (size_t i = 0; i < m; i++) CHECK((unsigned char)o[i] >= ' ' && o[i] != ',');
        if (m) CHECK(o[0] != ';' && o[m - 1] != ';' && o[0] != ' ' && o[m - 1] != ' ');
        g_free(o); g_free(in);
    }
    printf(fails ? "FAILED %d\n" : "list_test OK\n", fails);
    return fails ? 1 : 0;
}
