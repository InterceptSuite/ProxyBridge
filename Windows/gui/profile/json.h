// json.h - a compact, dependency-free JSON parser + writer for the GUI.
//
// Just enough to round-trip ProxyBridge's settings.json and *.pbprofile files
// (PascalCase keys). Parser builds a small DOM; writer is a growable UTF-8 string
// buffer with correct escaping. Whitespace/formatting is insignificant, so we emit
// compact-ish indented JSON.
#ifndef PB_JSON_H
#define PB_JSON_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// DOM
typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;

typedef struct JVal {
    JType         type;
    char*         key;    // member key (owned) - set only for object members
    int           bval;   // J_BOOL
    double        nval;   // J_NUM
    char*         sval;   // J_STR (owned, decoded UTF-8)
    struct JVal*  child;  // first child (J_ARR / J_OBJ)
    struct JVal*  next;   // next sibling
} JVal;

// parser
// depth guards against stack overflow from deeply nested (or hostile) input:
// json_parse recurses once per nesting level, so an unbounded document would
// exhaust the stack. 64 levels is far more than any real profile needs.
#define J_MAX_DEPTH 64
typedef struct { const char* p; const char* end; int depth; } JParser;

static JVal* j_new(JType t)
{
    JVal* v = (JVal*)calloc(1, sizeof(JVal));
    if (v) v->type = t;
    return v;
}

static void json_free(JVal* v)
{
    while (v)
    {
        JVal* nx = v->next;
        if (v->child) json_free(v->child);
        free(v->key);
        free(v->sval);
        free(v);
        v = nx;
    }
}

static void j_skip_ws(JParser* s)
{
    while (s->p < s->end)
    {
        char c = *s->p;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') s->p++;
        else break;
    }
}

// Decode a JSON string (assumes *s->p == '"'). Returns malloc'd UTF-8, advances past it.
static char* j_parse_string(JParser* s)
{
    if (s->p >= s->end || *s->p != '"') return NULL;
    s->p++;
    size_t cap = 16, len = 0;
    char* out = (char*)malloc(cap);
    if (!out) return NULL;
    while (s->p < s->end && *s->p != '"')
    {
        char c = *s->p++;
        if (c == '\\' && s->p < s->end)
        {
            char e = *s->p++;
            switch (e)
            {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            case 'u':
            {
                if (s->end - s->p < 4) { free(out); return NULL; }
                unsigned cp = 0;
                for (int i = 0; i < 4; i++)
                {
                    char h = *s->p++;
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                    else { free(out); return NULL; }
                }
                // Encode code point as UTF-8 (BMP only; surrogate pairs are rare in our files).
                char buf[4]; int n = 0;
                if (cp < 0x80) buf[n++] = (char)cp;
                else if (cp < 0x800) { buf[n++] = (char)(0xC0 | (cp >> 6)); buf[n++] = (char)(0x80 | (cp & 0x3F)); }
                else { buf[n++] = (char)(0xE0 | (cp >> 12)); buf[n++] = (char)(0x80 | ((cp >> 6) & 0x3F)); buf[n++] = (char)(0x80 | (cp & 0x3F)); }
                for (int i = 0; i < n; i++)
                {
                    if (len + 1 >= cap) { cap *= 2; char* t = (char*)realloc(out, cap); if (!t) { free(out); return NULL; } out = t; }
                    out[len++] = buf[i];
                }
                continue;
            }
            default: c = e; break;
            }
        }
        if (len + 1 >= cap) { cap *= 2; char* t = (char*)realloc(out, cap); if (!t) { free(out); return NULL; } out = t; }
        out[len++] = c;
    }
    if (s->p < s->end && *s->p == '"') s->p++;
    out[len] = 0;
    return out;
}

static JVal* j_parse_value(JParser* s);

static JVal* j_parse_container(JParser* s, char open, char close, JType type)
{
    if (++s->depth > J_MAX_DEPTH) { s->depth--; return NULL; }   // too deeply nested - reject
    s->p++; // consume open
    JVal* node = j_new(type);
    if (!node) { s->depth--; return NULL; }
    JVal* tail = NULL;
    j_skip_ws(s);
    if (s->p < s->end && *s->p == close) { s->p++; s->depth--; return node; }
    while (s->p < s->end)
    {
        j_skip_ws(s);
        char* key = NULL;
        if (type == J_OBJ)
        {
            key = j_parse_string(s);
            j_skip_ws(s);
            if (s->p < s->end && *s->p == ':') s->p++;
        }
        JVal* val = j_parse_value(s);
        if (!val) { free(key); json_free(node); s->depth--; return NULL; }
        val->key = key;
        if (tail) tail->next = val; else node->child = val;
        tail = val;
        j_skip_ws(s);
        if (s->p < s->end && *s->p == ',') { s->p++; continue; }
        if (s->p < s->end && *s->p == close) { s->p++; break; }
        break;
    }
    (void)open;
    s->depth--;
    return node;
}

static JVal* j_parse_value(JParser* s)
{
    j_skip_ws(s);
    if (s->p >= s->end) return NULL;
    char c = *s->p;
    if (c == '{') return j_parse_container(s, '{', '}', J_OBJ);
    if (c == '[') return j_parse_container(s, '[', ']', J_ARR);
    if (c == '"') { char* str = j_parse_string(s); JVal* v = j_new(J_STR); if (v) v->sval = str; else free(str); return v; }
    if (c == 't') { if (s->end - s->p >= 4 && strncmp(s->p, "true", 4) == 0) { s->p += 4; JVal* v = j_new(J_BOOL); if (v) v->bval = 1; return v; } return NULL; }
    if (c == 'f') { if (s->end - s->p >= 5 && strncmp(s->p, "false", 5) == 0) { s->p += 5; JVal* v = j_new(J_BOOL); if (v) v->bval = 0; return v; } return NULL; }
    if (c == 'n') { if (s->end - s->p >= 4 && strncmp(s->p, "null", 4) == 0) { s->p += 4; return j_new(J_NULL); } return NULL; }
    // number
    {
        char numbuf[64]; int n = 0;
        while (s->p < s->end && n < 63)
        {
            char d = *s->p;
            if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' || d == 'e' || d == 'E') { numbuf[n++] = d; s->p++; }
            else break;
        }
        numbuf[n] = 0;
        if (n == 0) return NULL;
        JVal* v = j_new(J_NUM);
        if (v) v->nval = atof(numbuf);
        return v;
    }
}

// Parse a whole document. Returns root (owned) or NULL.
static JVal* json_parse(const char* text, size_t length)
{
    JParser s; s.p = text; s.end = text + length; s.depth = 0;
    return j_parse_value(&s);
}

// DOM accessors
static JVal* json_get(const JVal* obj, const char* key)
{
    if (!obj || obj->type != J_OBJ) return NULL;
    for (JVal* c = obj->child; c; c = c->next)
        if (c->key && strcmp(c->key, key) == 0) return c;
    return NULL;
}

static const char* json_str(const JVal* obj, const char* key, const char* def)
{
    JVal* v = json_get(obj, key);
    return (v && v->type == J_STR && v->sval) ? v->sval : def;
}

static int json_bool(const JVal* obj, const char* key, int def)
{
    JVal* v = json_get(obj, key);
    return (v && v->type == J_BOOL) ? v->bval : def;
}

static long json_long(const JVal* obj, const char* key, long def)
{
    JVal* v = json_get(obj, key);
    return (v && v->type == J_NUM) ? (long)v->nval : def;
}

// writer (growable UTF-8 buffer)
typedef struct { char* buf; size_t len, cap; } StrBuf;

static void sb_init(StrBuf* b) { b->cap = 256; b->len = 0; b->buf = (char*)malloc(b->cap); if (b->buf) b->buf[0] = 0; }
static void sb_free(StrBuf* b) { free(b->buf); b->buf = NULL; }
static void sb_putn(StrBuf* b, const char* s, size_t n)
{
    if (!b->buf) return;
    if (b->len + n + 1 > b->cap) { while (b->len + n + 1 > b->cap) b->cap *= 2; char* t = (char*)realloc(b->buf, b->cap); if (!t) return; b->buf = t; }
    memcpy(b->buf + b->len, s, n); b->len += n; b->buf[b->len] = 0;
}
static void sb_put(StrBuf* b, const char* s) { sb_putn(b, s, strlen(s)); }

// Append a JSON-escaped string literal (with surrounding quotes).
static void sb_json_str(StrBuf* b, const char* s)
{
    sb_put(b, "\"");
    if (s)
    {
        for (const unsigned char* p = (const unsigned char*)s; *p; p++)
        {
            unsigned char c = *p;
            switch (c)
            {
            case '"':  sb_put(b, "\\\""); break;
            case '\\': sb_put(b, "\\\\"); break;
            case '\b': sb_put(b, "\\b");  break;
            case '\f': sb_put(b, "\\f");  break;
            case '\n': sb_put(b, "\\n");  break;
            case '\r': sb_put(b, "\\r");  break;
            case '\t': sb_put(b, "\\t");  break;
            default:
                if (c < 0x20) { char u[8]; snprintf(u, sizeof(u), "\\u%04x", c); sb_put(b, u); }
                else { char ch = (char)c; sb_putn(b, &ch, 1); }  // pass UTF-8 bytes through
            }
        }
    }
    sb_put(b, "\"");
}

#endif // PB_JSON_H
