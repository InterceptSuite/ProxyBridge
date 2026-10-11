// pb_proto.h - wire protocol between ProxyBridge.exe (unprivileged GUI) and
// ProxyBridgeSvc.exe (LocalSystem service that owns ProxyBridgeCore.dll / WinDivert).
//
// Two message-mode named pipes, one client at a time:
//   PB_PIPE_CTL  request/response. Client writes one request message, reads one response.
//   PB_PIPE_EVT  service -> client only: log lines, connection events, proxy-test output.
//
// Every message is a flat byte buffer built with PbW (writer) and parsed with PbR (reader).
//   request  : u32 op, args...
//   response : u32 ret, extra...
//   event    : u32 type, fields...
// Integers are little-endian u32. A string is u32 length + bytes (no NUL);
// length 0xFFFFFFFF means NULL.
#ifndef PB_PROTO_H
#define PB_PROTO_H

#include <windows.h>

#define PB_SERVICE_NAME  L"ProxyBridgeSvc"
#define PB_PIPE_CTL      L"\\\\.\\pipe\\ProxyBridgeCtl"
#define PB_PIPE_EVT      L"\\\\.\\pipe\\ProxyBridgeEvt"
#define PB_PROTO_VERSION 1
#define PB_MSG_MAX       (64u * 1024u)
#define PB_STR_MAX       (32u * 1024u)
#define PB_NULL_STR      0xFFFFFFFFu

enum {
    PBOP_HELLO = 1,           // () -> PB_PROTO_VERSION
    PBOP_ADD_PROXY,           // type, ip, port, user, pass, sendDomain -> id
    PBOP_EDIT_PROXY,          // id, type, ip, port, user, pass, sendDomain -> bool
    PBOP_DELETE_PROXY,        // id -> bool
    PBOP_TEST_PROXY_START,    // id, host, port -> bool (result arrives as PBEVT_TEST_DONE)
    PBOP_ADD_RULE,            // proc, hosts, ports, domains, proto, action, cfgId -> id
    PBOP_ENABLE_RULE,         // id -> bool
    PBOP_DISABLE_RULE,        // id -> bool
    PBOP_DELETE_RULE,         // id -> bool
    PBOP_EDIT_RULE,           // id, proc, hosts, ports, domains, proto, action, cfgId -> bool
    PBOP_MOVE_RULE,           // id, pos -> bool
    PBOP_GET_RULE_POS,        // id -> pos
    PBOP_SET_LOCALHOST,       // bool -> 0
    PBOP_SET_TRAFFIC_LOG,     // bool -> 0
    PBOP_CLEAR_CONN_LOGS,     // () -> 0
    PBOP_START,               // () -> bool
    PBOP_STOP                 // () -> bool
};

enum {
    PBEVT_LOG = 1,            // str message
    PBEVT_CONN,               // str process, u32 pid, str ip, u32 port, str info
    PBEVT_TEST_LINE,          // str line
    PBEVT_TEST_DONE           // u32 result (int)
};

// writer
typedef struct { BYTE *buf; DWORD len; DWORD cap; BOOL ok; } PbW;

static void PbW_Init(PbW *w, BYTE *buf, DWORD cap) { w->buf = buf; w->len = 0; w->cap = cap; w->ok = TRUE; }
static void PbW_U32(PbW *w, UINT32 v)
{
    if (!w->ok || w->len + 4 > w->cap) { w->ok = FALSE; return; }
    memcpy(w->buf + w->len, &v, 4); w->len += 4;
}
static void PbW_Str(PbW *w, const char *s)
{
    if (s == NULL) { PbW_U32(w, PB_NULL_STR); return; }
    size_t n = strlen(s);
    if (n > PB_STR_MAX) { w->ok = FALSE; return; }
    PbW_U32(w, (UINT32)n);
    if (!w->ok || w->len + n > w->cap) { w->ok = FALSE; return; }
    memcpy(w->buf + w->len, s, n); w->len += (DWORD)n;
}

// reader (bounds-checked: any malformed message just flips ok to FALSE)
typedef struct { const BYTE *buf; DWORD len; DWORD pos; BOOL ok; } PbR;

static void PbR_Init(PbR *r, const BYTE *buf, DWORD len) { r->buf = buf; r->len = len; r->pos = 0; r->ok = TRUE; }
static UINT32 PbR_U32(PbR *r)
{
    UINT32 v = 0;
    if (!r->ok || r->pos + 4 > r->len) { r->ok = FALSE; return 0; }
    memcpy(&v, r->buf + r->pos, 4); r->pos += 4;
    return v;
}
// Copies into out (always NUL-terminated, truncated to outCap-1). Returns FALSE if the string
// was NULL (out[0] = 0) or the message is malformed. *isNull is set for the NULL case.
static void PbR_Str(PbR *r, char *out, size_t outCap, BOOL *isNull)
{
    out[0] = 0;
    if (isNull) *isNull = FALSE;
    UINT32 n = PbR_U32(r);
    if (!r->ok) return;
    if (n == PB_NULL_STR) { if (isNull) *isNull = TRUE; return; }
    if (n > PB_STR_MAX || r->pos + n > r->len) { r->ok = FALSE; return; }
    size_t c = n < outCap - 1 ? n : outCap - 1;
    memcpy(out, r->buf + r->pos, c); out[c] = 0;
    r->pos += n;
}

#endif // PB_PROTO_H
