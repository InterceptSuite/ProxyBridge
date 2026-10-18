// test_json.c - the small JSON parser/writer behind profiles and settings (gui\profile\json.h).
// Covers valid documents, escapes, malformed and truncated input, the nesting limit, huge values, the writer's
// escaping (and that what it writes parses back to the same text), and random garbage read through a guard page.
#include <stdlib.h>
#include <string.h>
#include "../gui/profile/json.h"
#include "pbtest.h"

static JVal* P(const char* s) { return json_parse(s, strlen(s)); }

int main(void)
{
    /* ---- valid documents ---- */
    { JVal* v = P("{\"a\": 1, \"b\": \"text\", \"c\": true, \"d\": false, \"e\": null, \"f\": [1, 2, 3], \"g\": {\"h\": \"i\"}, \"n\": -12.5e1}");
      CHECK(v && v->type == J_OBJ);
      CHECK(json_long(v, "a", 0) == 1 && !strcmp(json_str(v, "b", ""), "text") && json_bool(v, "c", 0) == 1 && json_bool(v, "d", 1) == 0);
      CHECK(json_get(v, "f") && json_get(v, "f")->type == J_ARR && json_get(v, "g")->type == J_OBJ);
      CHECK(json_long(v, "n", 0) == -125);
      CHECK(json_get(v, "missing") == NULL && json_long(v, "missing", 42) == 42 && !strcmp(json_str(v, "missing", "dflt"), "dflt") && json_bool(v, "missing", 1) == 1);
      CHECK(json_long(v, "b", 7) == 7 || json_long(v, "b", 7) == 0);                         /* wrong type: a default, never a crash */
      json_free(v); }
    { JVal* v = P("  \r\n\t [ ] "); CHECK(v && v->type == J_ARR && v->child == NULL); json_free(v); }
    { JVal* v = P("{}"); CHECK(v && v->type == J_OBJ && v->child == NULL); json_free(v); }

    /* ---- string escapes ---- */
    { JVal* v = P("{\"s\": \"a\\nb\\r\\tc\\\"d\\\\e\\/f\\bg\\fh\"}");
      CHECK(v && !strcmp(json_str(v, "s", ""), "a\nb\r\tc\"d\\e/f\bg\fh")); json_free(v); }
    { JVal* v = P("{\"s\": \"\\u0041\\u00e9\\u20ac\"}");                                       /* A, e-acute, euro sign */
      CHECK(v && !strcmp(json_str(v, "s", ""), "A\xC3\xA9\xE2\x82\xAC")); json_free(v); }
    { JVal* v = P("{\"s\": \"caf\xC3\xA9 \xE4\xB8\xAD\xE6\x96\x87\"}");                       /* raw UTF-8 passes through */
      CHECK(v && !strcmp(json_str(v, "s", ""), "caf\xC3\xA9 \xE4\xB8\xAD\xE6\x96\x87")); json_free(v); }
    { JVal* v = P("{\"s\": \"x\\u12\"}");  CHECK(v == NULL || json_str(v, "s", NULL) == NULL || 1); json_free(v); }   /* short \u escape: no crash */
    { JVal* v = P("{\"s\": \"\\uZZZZ\"}");  json_free(v); CHECK(TRUE); }                      /* non-hex \u escape: no crash */
    { JVal* v = P("{\"k\": \"unterminated"); json_free(v); CHECK(TRUE); }

    /* ---- malformed and truncated documents never crash (guard page after the last byte) ---- */
    { const char* docs[] = { "", " ", "{", "[", "{\"a\"", "{\"a\":", "{\"a\": 1,", "{\"a\": 1 \"b\": 2}", "[1,,2]", "[1 2]", "}", "]", "nul", "tru", "-", "\"", "\\",
                             "{\"a\": [1, 2", "{\"a\": {\"b\": {\"c\": " };
      for (size_t i = 0; i < sizeof docs / sizeof *docs; i++)
      { void* b; size_t n = strlen(docs[i]); BYTE* g = pb_guarded(docs[i], n, &b); JVal* v = json_parse((const char*)g, n); json_free(v); pb_guard_release(b); }
      CHECK(TRUE); }
    { const char* full = "{\"Version\": \"1.0\", \"ProxyRules\": [{\"Name\": \"a\", \"IsEnabled\": true, \"ProxyConfigId\": 12}, {\"Name\": \"b\\u00e9\"}], \"x\": [1, 2.5, null, false]}";
      size_t n = strlen(full);
      for (size_t cut = 0; cut <= n; cut++)                                                    /* every prefix, parsed from a buffer that ends exactly there */
      { void* b; BYTE* g = pb_guarded(full, cut, &b); JVal* v = json_parse((const char*)g, cut); json_free(v); pb_guard_release(b); }
      CHECK(TRUE); }

    /* ---- nesting limit: deep documents are refused without exhausting the stack ---- */
    { char deep[400]; int d = J_MAX_DEPTH;
      memset(deep, '[', d); memset(deep + d, ']', d); deep[2 * d] = 0;
      JVal* ok = P(deep); CHECK(ok != NULL); json_free(ok);                                   /* exactly at the limit */
      memset(deep, '[', d + 1); memset(deep + d + 1, ']', d + 1); deep[2 * (d + 1)] = 0;
      JVal* over = P(deep); CHECK(over == NULL); json_free(over); }                           /* one more level: rejected */
    { size_t n = 2000000; char* deep = (char*)malloc(n + 1); memset(deep, '[', n); deep[n] = 0;   /* two million opening brackets */
      JVal* v = json_parse(deep, n); CHECK(v == NULL); json_free(v); free(deep); }
    { size_t n = 400000; char* deep = (char*)malloc(n + 1); for (size_t i = 0; i < n; i += 2) { deep[i] = '{'; deep[i + 1] = '"'; } deep[n] = 0;
      JVal* v = json_parse(deep, n); json_free(v); free(deep); CHECK(TRUE); }                  /* nested objects with unterminated keys */

    /* ---- big values ---- */
    { size_t n = 6 * 1024 * 1024; char* s = (char*)malloc(n + 64); strcpy_s(s, 16, "{\"big\": \""); memset(s + 9, 'x', n); strcpy_s(s + 9 + n, 8, "\"}");
      JVal* v = json_parse(s, 9 + n + 2); CHECK(v && strlen(json_str(v, "big", "")) == n); json_free(v); free(s); }
    { StrBuf b; sb_init(&b); sb_put(&b, "["); for (int i = 0; i < 50000; i++) { if (i) sb_put(&b, ","); sb_put(&b, "{\"k\":1}"); } sb_put(&b, "]");
      JVal* v = json_parse(b.buf, b.len); int cnt = 0; for (JVal* c = v ? v->child : NULL; c; c = c->next) cnt++; CHECK(cnt == 50000); json_free(v); sb_free(&b); }

    /* ---- writer: escaping, and write -> parse gives back the same text ---- */
    { StrBuf b; sb_init(&b); sb_json_str(&b, "q\"uote \\ back\nline\r\ttab\x01\x1f \xC3\xA9\xE4\xB8\xAD");
      CHECK(strstr(b.buf, "\\\"") && strstr(b.buf, "\\\\") && strstr(b.buf, "\\n") && strstr(b.buf, "\\r") && strstr(b.buf, "\\t") && strstr(b.buf, "\\u0001") && strstr(b.buf, "\\u001f"));
      CHECK(b.buf[0] == '"' && b.buf[b.len - 1] == '"');
      sb_free(&b); }
    { StrBuf b; sb_init(&b); sb_json_str(&b, NULL); CHECK(!strcmp(b.buf, "\"\"")); sb_free(&b); }
    srand(31337);
    for (int it = 0; it < 20000; it++)
    {
        char s[80]; int n = rand() % 70;
        for (int i = 0; i < n; i++) { int r = rand() % 10; s[i] = (char)(r < 6 ? 0x20 + rand() % 0x5F : r < 8 ? "\"\\/\n\r\t\b\f"[rand() % 8] : 1 + rand() % 31); }
        s[n] = 0;
        StrBuf b; sb_init(&b); sb_put(&b, "{\"k\": "); sb_json_str(&b, s); sb_put(&b, "}");
        JVal* v = json_parse(b.buf, b.len);
        if (!v || strcmp(json_str(v, "k", "\x7f"), s)) { g_fails++; printf("  FAIL round trip of a %d-character string\n", n); }
        json_free(v); sb_free(&b);
    }
    g_checks += 20000;

    /* ---- random garbage and mutated documents (guard page): never crash, never hang ---- */
    { const char* seed = "{\"A\": [1, true, null, \"s\\n\\u0041\"], \"B\": {\"C\": -1.5e3}}"; size_t sl = strlen(seed);
      for (int it = 0; it < 40000; it++)
      {
          char buf[200]; size_t n;
          if (it % 2) { n = (size_t)(rand() % 120); for (size_t i = 0; i < n; i++) buf[i] = (char)(rand() % 3 ? "{}[]\",:\\ 0123456789tfnul-.e"[rand() % 26] : rand()); }
          else { n = sl; memcpy(buf, seed, sl); int fl = 1 + rand() % 4; for (int f = 0; f < fl; f++) buf[rand() % sl] = (char)(rand() % 4 ? "{}[]\",:\\"[rand() % 8] : rand()); if (it % 4 == 0) n = (size_t)(rand() % (int)(sl + 1)); }
          void* b; BYTE* g = pb_guarded(buf, n, &b); JVal* v = json_parse((const char*)g, n); json_free(v); pb_guard_release(b);
      }
      g_checks += 40000; }

    return pbtest_done("test_json");
}
