// test_proto.c - the wire protocol between the app and the engine service (src\service\pb_proto.h).
// The reader/writer must reject malformed or hostile messages without overrunning anything.
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "../src/service/pb_proto.h"
#include "pbtest.h"

int main(void)
{
    /* ---- writer ---- */
    { BYTE buf[64]; PbW w; PbW_Init(&w, buf, sizeof buf);
      PbW_U32(&w, 7); PbW_Str(&w, "abc"); PbW_Str(&w, NULL); PbW_Str(&w, "");
      CHECK(w.ok && w.len == 4 + (4 + 3) + 4 + 4);
      PbR r; PbR_Init(&r, buf, w.len); char s[16]; BOOL isNull;
      CHECK(PbR_U32(&r) == 7);
      PbR_Str(&r, s, sizeof s, &isNull); CHECK(r.ok && !isNull && strcmp(s, "abc") == 0);
      PbR_Str(&r, s, sizeof s, &isNull); CHECK(r.ok && isNull && s[0] == 0);          /* NULL string survives the trip */
      PbR_Str(&r, s, sizeof s, &isNull); CHECK(r.ok && !isNull && s[0] == 0);         /* empty string is not NULL */
      CHECK(r.pos == r.len); }
    { BYTE buf[8]; PbW w; PbW_Init(&w, buf, sizeof buf);                              /* writer overflow flips ok, never writes past */
      PbW_U32(&w, 1); PbW_U32(&w, 2); CHECK(w.ok); PbW_U32(&w, 3); CHECK(!w.ok && w.len == 8); }
    { BYTE buf[16]; PbW w; PbW_Init(&w, buf, sizeof buf); PbW_Str(&w, "0123456789abcdefXYZ"); CHECK(!w.ok); }
    { static char big[PB_STR_MAX + 8]; memset(big, 'a', sizeof big - 1); big[sizeof big - 1] = 0;
      static BYTE buf[PB_MSG_MAX]; PbW w; PbW_Init(&w, buf, sizeof buf); PbW_Str(&w, big); CHECK(!w.ok); }   /* longer than PB_STR_MAX */

    /* ---- reader: malformed input ---- */
    { BYTE b[3] = {1, 2, 3}; PbR r; PbR_Init(&r, b, 3); PbR_U32(&r); CHECK(!r.ok); }  /* too short for a u32 */
    { BYTE b[8] = {0xFF, 0xFF, 0xFF, 0x7F, 'a', 'b', 'c', 'd'}; PbR r; PbR_Init(&r, b, 8); char s[8];
      PbR_Str(&r, s, sizeof s, NULL); CHECK(!r.ok && s[0] == 0); }                    /* declared length far beyond the message */
    { BYTE b[8] = {10, 0, 0, 0, 'a', 'b', 'c', 'd'}; PbR r; PbR_Init(&r, b, 8); char s[8];
      PbR_Str(&r, s, sizeof s, NULL); CHECK(!r.ok); }                                 /* length 10, only 4 bytes present */
    { BYTE b[4 + PB_STR_MAX + 16]; UINT32 n = PB_STR_MAX + 1; memcpy(b, &n, 4); memset(b + 4, 'a', PB_STR_MAX + 1);
      PbR r; PbR_Init(&r, b, sizeof b); char s[16]; PbR_Str(&r, s, sizeof s, NULL); CHECK(!r.ok); }   /* above PB_STR_MAX */
    { BYTE b[4 + 20]; UINT32 n = 20; memcpy(b, &n, 4); memset(b + 4, 'x', 20);        /* reply bigger than the caller's buffer: truncated + terminated */
      PbR r; PbR_Init(&r, b, sizeof b); char s[8]; memset(s, 0x55, sizeof s); PbR_Str(&r, s, sizeof s, NULL);
      CHECK(r.ok && strlen(s) == 7 && s[7] == 0); }
    { BYTE b[4]; PbR r; PbR_Init(&r, b, 0); CHECK(PbR_U32(&r) == 0 && !r.ok); char s[4]; PbR_Str(&r, s, sizeof s, NULL); CHECK(!r.ok); }   /* empty message; stays failed */

    /* ---- random messages: parsing never reads or writes outside its buffers ---- */
    srand(4242);
    for (int it = 0; it < 50000; it++)
    {
        int n = rand() % 48; BYTE* m = (BYTE*)malloc((size_t)n + 16);
        for (int i = 0; i < n; i++) m[i] = (BYTE)(rand() % 3 ? rand() % 12 : rand());   /* small lengths are common, big ones rare */
        PbR r; PbR_Init(&r, m, (DWORD)n);
        for (int f = 0; f < 6; f++)
        {
            char s[12]; memset(s, 0x55, sizeof s);
            if (f % 2) { PbR_U32(&r); }
            else { PbR_Str(&r, s, sizeof s, NULL); size_t l = strnlen(s, sizeof s); if (l >= sizeof s) { g_fails++; puts("  FAIL unterminated string from reader"); } }
            if (r.pos > r.len) { g_fails++; puts("  FAIL reader moved past the end"); break; }
        }
        free(m);
    }
    g_checks += 50000;

    return pbtest_done("test_proto");
}
