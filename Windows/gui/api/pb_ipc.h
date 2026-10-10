// pb_ipc.h - PBApi backed by ProxyBridgeSvc.exe over named pipes (see src/service/pb_proto.h).
//
// This is how the unprivileged GUI drives the engine: the service (LocalSystem, installed
// once by the installer) owns ProxyBridgeCore.dll and WinDivert; the GUI only needs to open
// the pipes. The function table is identical to the one PB_LoadDirect() fills in, so the
// rest of the GUI does not know which path is in use.
//
// Callbacks (log / connection / proxy-test lines) are delivered on a reader thread, the same
// "native thread - never touch UI directly" contract as the in-process engine.
#ifndef PB_IPC_H
#define PB_IPC_H

#include "pb_api.h"
#include "../../src/service/pb_proto.h"

enum { PB_IPC_OK = 0, PB_IPC_NO_SERVICE, PB_IPC_BUSY, PB_IPC_BAD_VERSION };

static HANDLE           g_ipcCtl = INVALID_HANDLE_VALUE;
static HANDLE           g_ipcEvt = INVALID_HANDLE_VALUE;
static HANDLE           g_ipcReader = NULL;
static CRITICAL_SECTION g_ipcLock;          // one request/response at a time
static CRITICAL_SECTION g_ipcTestLock;      // one proxy test at a time
static BOOL             g_ipcInit = FALSE;
static HANDLE           g_ipcTestDone = NULL;
static volatile LONG    g_ipcTestResult = -1;
static PBLogCallback        g_ipcLogCb = NULL;
static PBConnectionCallback g_ipcConnCb = NULL;
static PBTestLogCallback    g_ipcTestCb = NULL;
static void*                g_ipcTestUser = NULL;

// events
static DWORD WINAPI PbIpcReader(LPVOID arg)
{
    (void)arg;
    BYTE buf[PB_MSG_MAX];
    for (;;)
    {
        DWORD n = 0;
        if (!ReadFile(g_ipcEvt, buf, sizeof(buf), &n, NULL)) break;
        PbR r; PbR_Init(&r, buf, n);
        UINT32 type = PbR_U32(&r);
        char a[8192], b[8192], c[8192];
        if (type == PBEVT_LOG)
        {
            PbR_Str(&r, a, sizeof(a), NULL);
            if (r.ok && g_ipcLogCb) g_ipcLogCb(a);
        }
        else if (type == PBEVT_CONN)
        {
            PbR_Str(&r, a, sizeof(a), NULL); UINT32 pid = PbR_U32(&r);
            PbR_Str(&r, b, sizeof(b), NULL); UINT32 port = PbR_U32(&r);
            PbR_Str(&r, c, sizeof(c), NULL);
            if (r.ok && g_ipcConnCb) g_ipcConnCb(a, pid, b, (unsigned short)port, c);
        }
        else if (type == PBEVT_TEST_LINE)
        {
            PbR_Str(&r, a, sizeof(a), NULL);
            if (r.ok && g_ipcTestCb) g_ipcTestCb(a, g_ipcTestUser);
        }
        else if (type == PBEVT_TEST_DONE)
        {
            UINT32 rc = PbR_U32(&r);
            if (r.ok) { InterlockedExchange(&g_ipcTestResult, (LONG)rc); SetEvent(g_ipcTestDone); }
        }
    }
    SetEvent(g_ipcTestDone);   // service went away: release a pending proxy test
    return 0;
}

// Sends one request, returns the response's leading u32 (0 on any failure).
static UINT32 PbIpcCall(const BYTE *req, DWORD len)
{
    UINT32 ret = 0;
    BYTE rsp[64];
    EnterCriticalSection(&g_ipcLock);
    if (g_ipcCtl != INVALID_HANDLE_VALUE)
    {
        DWORD n = 0;
        if (WriteFile(g_ipcCtl, req, len, &n, NULL) && ReadFile(g_ipcCtl, rsp, sizeof(rsp), &n, NULL) && n >= 4)
            memcpy(&ret, rsp, 4);
        else { CloseHandle(g_ipcCtl); g_ipcCtl = INVALID_HANDLE_VALUE; }   // service gone
    }
    LeaveCriticalSection(&g_ipcLock);
    return ret;
}

#define PBIPC_BEGIN(opcode)  BYTE _b[PB_MSG_MAX]; PbW _w; PbW_Init(&_w, _b, sizeof(_b)); PbW_U32(&_w, (opcode))
#define PBIPC_END()          return _w.ok ? PbIpcCall(_b, _w.len) : 0

static UINT32 IpcAddProxyConfig(PBProxyType t, const char* ip, unsigned short port, const char* u, const char* p, BOOL sd)
{ PBIPC_BEGIN(PBOP_ADD_PROXY); PbW_U32(&_w, t); PbW_Str(&_w, ip); PbW_U32(&_w, port); PbW_Str(&_w, u); PbW_Str(&_w, p); PbW_U32(&_w, sd != 0); PBIPC_END(); }
static BOOL IpcEditProxyConfig(UINT32 id, PBProxyType t, const char* ip, unsigned short port, const char* u, const char* p, BOOL sd)
{ PBIPC_BEGIN(PBOP_EDIT_PROXY); PbW_U32(&_w, id); PbW_U32(&_w, t); PbW_Str(&_w, ip); PbW_U32(&_w, port); PbW_Str(&_w, u); PbW_Str(&_w, p); PbW_U32(&_w, sd != 0); PBIPC_END(); }
static BOOL IpcDeleteProxyConfig(UINT32 id)
{ PBIPC_BEGIN(PBOP_DELETE_PROXY); PbW_U32(&_w, id); PBIPC_END(); }

static int IpcTestProxyConfig(UINT32 id, const char* host, unsigned short port, char* out, size_t cap)
{ (void)id; (void)host; (void)port; if (out && cap) out[0] = 0; return -1; }   // unused by the GUI (see TestProxyConfigEx)

static int IpcTestProxyConfigEx(UINT32 id, const char* host, unsigned short port, PBTestLogCallback cb, void* user)
{
    int rc = -1;
    EnterCriticalSection(&g_ipcTestLock);
    g_ipcTestCb = cb; g_ipcTestUser = user;
    ResetEvent(g_ipcTestDone);
    InterlockedExchange(&g_ipcTestResult, -1);
    {
        PBIPC_BEGIN(PBOP_TEST_PROXY_START); PbW_U32(&_w, id); PbW_Str(&_w, host); PbW_U32(&_w, port);
        if (_w.ok && PbIpcCall(_b, _w.len))
        {
            WaitForSingleObject(g_ipcTestDone, 120000);
            rc = (int)g_ipcTestResult;
        }
    }
    g_ipcTestCb = NULL;
    LeaveCriticalSection(&g_ipcTestLock);
    return rc;
}

static UINT32 IpcAddRule(const char* proc, const char* hosts, const char* ports, const char* domains, PBRuleProtocol pr, PBRuleAction ac, UINT32 cfg)
{ PBIPC_BEGIN(PBOP_ADD_RULE); PbW_Str(&_w, proc); PbW_Str(&_w, hosts); PbW_Str(&_w, ports); PbW_Str(&_w, domains); PbW_U32(&_w, pr); PbW_U32(&_w, ac); PbW_U32(&_w, cfg); PBIPC_END(); }
static BOOL IpcEditRule(UINT32 id, const char* proc, const char* hosts, const char* ports, const char* domains, PBRuleProtocol pr, PBRuleAction ac, UINT32 cfg)
{ PBIPC_BEGIN(PBOP_EDIT_RULE); PbW_U32(&_w, id); PbW_Str(&_w, proc); PbW_Str(&_w, hosts); PbW_Str(&_w, ports); PbW_Str(&_w, domains); PbW_U32(&_w, pr); PbW_U32(&_w, ac); PbW_U32(&_w, cfg); PBIPC_END(); }
static BOOL IpcEnableRule(UINT32 id)  { PBIPC_BEGIN(PBOP_ENABLE_RULE);  PbW_U32(&_w, id); PBIPC_END(); }
static BOOL IpcDisableRule(UINT32 id) { PBIPC_BEGIN(PBOP_DISABLE_RULE); PbW_U32(&_w, id); PBIPC_END(); }
static BOOL IpcDeleteRule(UINT32 id)  { PBIPC_BEGIN(PBOP_DELETE_RULE);  PbW_U32(&_w, id); PBIPC_END(); }
static BOOL IpcMoveRule(UINT32 id, UINT32 pos) { PBIPC_BEGIN(PBOP_MOVE_RULE); PbW_U32(&_w, id); PbW_U32(&_w, pos); PBIPC_END(); }
static UINT32 IpcGetRulePos(UINT32 id) { PBIPC_BEGIN(PBOP_GET_RULE_POS); PbW_U32(&_w, id); PBIPC_END(); }
static void IpcSetLocalhost(BOOL v)   { PBIPC_BEGIN(PBOP_SET_LOCALHOST);   PbW_U32(&_w, v != 0); PbIpcCall(_b, _w.len); }
static void IpcSetTrafficLog(BOOL v)  { PBIPC_BEGIN(PBOP_SET_TRAFFIC_LOG); PbW_U32(&_w, v != 0); PbIpcCall(_b, _w.len); }
static void IpcClearConnLogs(void)    { PBIPC_BEGIN(PBOP_CLEAR_CONN_LOGS); PbIpcCall(_b, _w.len); }
static void IpcSetLogCallback(PBLogCallback cb)               { g_ipcLogCb = cb; }
static void IpcSetConnectionCallback(PBConnectionCallback cb) { g_ipcConnCb = cb; }
static BOOL IpcStart(void) { PBIPC_BEGIN(PBOP_START); PBIPC_END(); }
static BOOL IpcStop(void)  { PBIPC_BEGIN(PBOP_STOP);  PBIPC_END(); }

// Asks the SCM to start the service (the installer grants interactive users this right).
static void PbIpcTryStartService(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, PB_SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (svc)
    {
        StartServiceW(svc, 0, NULL);
        SERVICE_STATUS st;
        for (int i = 0; i < 50; i++)    // up to ~5 s for START_PENDING -> RUNNING
        {
            if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_RUNNING) break;
            Sleep(100);
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static HANDLE PbIpcOpen(const wchar_t* name, DWORD access, DWORD* err)
{
    for (int tries = 0; tries < 20; tries++)
    {
        HANDLE h = CreateFileW(name, access, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            DWORD mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(h, &mode, NULL, NULL);
            return h;
        }
        *err = GetLastError();
        if (*err != ERROR_PIPE_BUSY) break;
        Sleep(100);
    }
    return INVALID_HANDLE_VALUE;
}

// Connects to the service and fills `api` with pipe-backed functions.
// Returns PB_IPC_OK, or why not (PB_IPC_NO_SERVICE = not installed / not running).
static int PB_LoadService(PBApi* api)
{
    if (!g_ipcInit)
    {
        InitializeCriticalSection(&g_ipcLock);
        InitializeCriticalSection(&g_ipcTestLock);
        g_ipcTestDone = CreateEventW(NULL, TRUE, FALSE, NULL);
        g_ipcInit = TRUE;
    }

    DWORD err = 0;
    HANDLE ctl = PbIpcOpen(PB_PIPE_CTL, GENERIC_READ | GENERIC_WRITE, &err);
    if (ctl == INVALID_HANDLE_VALUE && err == ERROR_FILE_NOT_FOUND)
    {
        PbIpcTryStartService();
        ctl = PbIpcOpen(PB_PIPE_CTL, GENERIC_READ | GENERIC_WRITE, &err);
    }
    if (ctl == INVALID_HANDLE_VALUE)
        return (err == ERROR_PIPE_BUSY) ? PB_IPC_BUSY : PB_IPC_NO_SERVICE;

    HANDLE evt = PbIpcOpen(PB_PIPE_EVT, GENERIC_READ, &err);
    if (evt == INVALID_HANDLE_VALUE) { CloseHandle(ctl); return (err == ERROR_PIPE_BUSY) ? PB_IPC_BUSY : PB_IPC_NO_SERVICE; }

    g_ipcCtl = ctl; g_ipcEvt = evt;
    {
        PBIPC_BEGIN(PBOP_HELLO);
        if (PbIpcCall(_b, _w.len) != PB_PROTO_VERSION)
        {
            CloseHandle(g_ipcCtl); g_ipcCtl = INVALID_HANDLE_VALUE;
            CloseHandle(g_ipcEvt); g_ipcEvt = INVALID_HANDLE_VALUE;
            return PB_IPC_BAD_VERSION;
        }
    }
    g_ipcReader = CreateThread(NULL, 0, PbIpcReader, NULL, 0, NULL);

    ZeroMemory(api, sizeof(*api));
    api->AddProxyConfig = IpcAddProxyConfig;       api->EditProxyConfig = IpcEditProxyConfig;
    api->DeleteProxyConfig = IpcDeleteProxyConfig; api->TestProxyConfig = IpcTestProxyConfig;
    api->TestProxyConfigEx = IpcTestProxyConfigEx; api->AddRule = IpcAddRule;
    api->EnableRule = IpcEnableRule;               api->DisableRule = IpcDisableRule;
    api->DeleteRule = IpcDeleteRule;               api->EditRule = IpcEditRule;
    api->MoveRuleToPosition = IpcMoveRule;         api->GetRulePosition = IpcGetRulePos;
    api->SetLocalhostViaProxy = IpcSetLocalhost;   api->SetLogCallback = IpcSetLogCallback;
    api->SetConnectionCallback = IpcSetConnectionCallback;
    api->SetTrafficLoggingEnabled = IpcSetTrafficLog;
    api->ClearConnectionLogs = IpcClearConnLogs;   api->Start = IpcStart; api->Stop = IpcStop;
    return PB_IPC_OK;
}

#endif // PB_IPC_H
