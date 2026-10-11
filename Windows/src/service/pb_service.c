// pb_service.c - ProxyBridgeSvc.exe
//
// LocalSystem Windows service that owns ProxyBridgeCore.dll (and so the WinDivert driver).
// The installer registers it once (admin); after that the GUI runs as a normal user and
// drives the engine over two named pipes (see pb_proto.h). This is why ProxyBridge.exe no
// longer needs "Run as administrator".
//
// One client at a time. When the client goes away (exit or crash) the engine is stopped and
// the core DLL is unloaded, so the next client starts from a clean state.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pb_proto.h"
#define PB_NO_SEARCH_FALLBACK   // SYSTEM service: load the engine only from our own directory
#include "../../gui/api/pb_api.h"

// pipe access: SYSTEM + Administrators full, interactive (logged-on, local) users read/write.
// Network logons are not in this list, and PIPE_REJECT_REMOTE_CLIENTS blocks remote access too.
#define PB_PIPE_SDDL L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

static SERVICE_STATUS_HANDLE g_ssh = NULL;
static SERVICE_STATUS        g_status;
static volatile LONG         g_stop = 0;
static HANDLE                g_worker = NULL;     // thread running the accept/serve loop

static HANDLE   g_ctl = INVALID_HANDLE_VALUE;
static HANDLE   g_evt = INVALID_HANDLE_VALUE;
static PBApi    g_api;
static CRITICAL_SECTION g_evt_lock;               // serialises event writes from engine threads
static volatile LONG g_evt_live = 0;              // 1 while an event pipe client is attached

static void SetState(DWORD state, DWORD exitCode)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwWaitHint = (state == SERVICE_STOP_PENDING || state == SERVICE_START_PENDING) ? 10000 : 0;
    if (g_ssh) SetServiceStatus(g_ssh, &g_status);
}

// events (called from engine threads)
static void SendEvent(const BYTE *buf, DWORD len)
{
    if (!g_evt_live) return;
    EnterCriticalSection(&g_evt_lock);
    if (g_evt_live && g_evt != INVALID_HANDLE_VALUE)
    {
        DWORD wr = 0;
        if (!WriteFile(g_evt, buf, len, &wr, NULL)) InterlockedExchange(&g_evt_live, 0);
    }
    LeaveCriticalSection(&g_evt_lock);
}

static void OnLog(const char *msg)
{
    BYTE b[8192]; PbW w; PbW_Init(&w, b, sizeof(b));
    PbW_U32(&w, PBEVT_LOG); PbW_Str(&w, msg);
    if (w.ok) SendEvent(b, w.len);
}

static void OnConn(const char *proc, DWORD pid, const char *ip, unsigned short port, const char *info)
{
    BYTE b[8192]; PbW w; PbW_Init(&w, b, sizeof(b));
    PbW_U32(&w, PBEVT_CONN); PbW_Str(&w, proc); PbW_U32(&w, pid);
    PbW_Str(&w, ip); PbW_U32(&w, port); PbW_Str(&w, info);
    if (w.ok) SendEvent(b, w.len);
}

// proxy test runs on its own thread so the request that started it returns immediately
static volatile LONG g_test_busy = 0;
typedef struct { UINT32 id; char host[512]; unsigned short port; } TestJob;

static void TestLineCb(const char *line, void *user)
{
    (void)user;
    BYTE b[8192]; PbW w; PbW_Init(&w, b, sizeof(b));
    PbW_U32(&w, PBEVT_TEST_LINE); PbW_Str(&w, line);
    if (w.ok) SendEvent(b, w.len);
}

static DWORD WINAPI TestThread(LPVOID arg)
{
    TestJob *j = (TestJob *)arg;
    int rc = g_api.TestProxyConfigEx ? g_api.TestProxyConfigEx(j->id, j->host, j->port, TestLineCb, NULL) : -1;
    BYTE b[16]; PbW w; PbW_Init(&w, b, sizeof(b));
    PbW_U32(&w, PBEVT_TEST_DONE); PbW_U32(&w, (UINT32)rc);
    SendEvent(b, w.len);
    free(j);
    InterlockedExchange(&g_test_busy, 0);
    return 0;
}

// request dispatch. Returns FALSE if the request was malformed.
static BOOL Dispatch(const BYTE *req, DWORD reqLen, PbW *resp)
{
    PbR r; PbR_Init(&r, req, reqLen);
    UINT32 op = PbR_U32(&r);
    UINT32 ret = 0;

    // scratch for string args
    static char proc[PB_STR_MAX + 1], hosts[PB_STR_MAX + 1], ports[4096], domains[PB_STR_MAX + 1];
    static char ip[512], user[512], pass[512], host[512];
    BOOL nUser = FALSE, nPass = FALSE, nHosts = FALSE, nPorts = FALSE, nDomains = FALSE, nProc = FALSE;

    switch (op)
    {
    case PBOP_HELLO: ret = PB_PROTO_VERSION; break;

    case PBOP_ADD_PROXY: {
        UINT32 type = PbR_U32(&r); PbR_Str(&r, ip, sizeof(ip), NULL); UINT32 port = PbR_U32(&r);
        PbR_Str(&r, user, sizeof(user), &nUser); PbR_Str(&r, pass, sizeof(pass), &nPass);
        UINT32 sd = PbR_U32(&r);
        if (!r.ok || type > 1 || port > 65535) return FALSE;
        ret = g_api.AddProxyConfig((PBProxyType)type, ip, (unsigned short)port, nUser ? NULL : user, nPass ? NULL : pass, sd != 0);
        break; }
    case PBOP_EDIT_PROXY: {
        UINT32 id = PbR_U32(&r), type = PbR_U32(&r); PbR_Str(&r, ip, sizeof(ip), NULL); UINT32 port = PbR_U32(&r);
        PbR_Str(&r, user, sizeof(user), &nUser); PbR_Str(&r, pass, sizeof(pass), &nPass);
        UINT32 sd = PbR_U32(&r);
        if (!r.ok || type > 1 || port > 65535) return FALSE;
        ret = g_api.EditProxyConfig(id, (PBProxyType)type, ip, (unsigned short)port, nUser ? NULL : user, nPass ? NULL : pass, sd != 0);
        break; }
    case PBOP_DELETE_PROXY: { UINT32 id = PbR_U32(&r); if (!r.ok) return FALSE; ret = g_api.DeleteProxyConfig(id); break; }

    case PBOP_TEST_PROXY_START: {
        UINT32 id = PbR_U32(&r); PbR_Str(&r, host, sizeof(host), NULL); UINT32 port = PbR_U32(&r);
        if (!r.ok || port > 65535) return FALSE;
        if (InterlockedCompareExchange(&g_test_busy, 1, 0) != 0) { ret = 0; break; }
        TestJob *j = (TestJob *)calloc(1, sizeof(*j));
        if (!j) { InterlockedExchange(&g_test_busy, 0); ret = 0; break; }
        j->id = id; j->port = (unsigned short)port; strncpy_s(j->host, sizeof(j->host), host, _TRUNCATE);
        HANDLE t = CreateThread(NULL, 0, TestThread, j, 0, NULL);
        if (!t) { free(j); InterlockedExchange(&g_test_busy, 0); ret = 0; break; }
        CloseHandle(t); ret = 1;
        break; }

    case PBOP_ADD_RULE: case PBOP_EDIT_RULE: {
        UINT32 id = (op == PBOP_EDIT_RULE) ? PbR_U32(&r) : 0;
        PbR_Str(&r, proc, sizeof(proc), &nProc); PbR_Str(&r, hosts, sizeof(hosts), &nHosts);
        PbR_Str(&r, ports, sizeof(ports), &nPorts); PbR_Str(&r, domains, sizeof(domains), &nDomains);
        UINT32 proto = PbR_U32(&r), action = PbR_U32(&r), cfg = PbR_U32(&r);
        if (!r.ok || proto > 2 || action > 2) return FALSE;
        if (op == PBOP_ADD_RULE)
            ret = g_api.AddRule(nProc ? NULL : proc, nHosts ? NULL : hosts, nPorts ? NULL : ports, nDomains ? NULL : domains,
                                (PBRuleProtocol)proto, (PBRuleAction)action, cfg);
        else
            ret = g_api.EditRule(id, nProc ? NULL : proc, nHosts ? NULL : hosts, nPorts ? NULL : ports, nDomains ? NULL : domains,
                                 (PBRuleProtocol)proto, (PBRuleAction)action, cfg);
        break; }
    case PBOP_ENABLE_RULE:  { UINT32 id = PbR_U32(&r); if (!r.ok) return FALSE; ret = g_api.EnableRule(id);  break; }
    case PBOP_DISABLE_RULE: { UINT32 id = PbR_U32(&r); if (!r.ok) return FALSE; ret = g_api.DisableRule(id); break; }
    case PBOP_DELETE_RULE:  { UINT32 id = PbR_U32(&r); if (!r.ok) return FALSE; ret = g_api.DeleteRule(id);  break; }
    case PBOP_MOVE_RULE:    { UINT32 id = PbR_U32(&r), pos = PbR_U32(&r); if (!r.ok) return FALSE; ret = g_api.MoveRuleToPosition(id, pos); break; }
    case PBOP_GET_RULE_POS: { UINT32 id = PbR_U32(&r); if (!r.ok) return FALSE; ret = g_api.GetRulePosition(id); break; }

    case PBOP_SET_LOCALHOST:    { UINT32 v = PbR_U32(&r); if (!r.ok) return FALSE; g_api.SetLocalhostViaProxy(v != 0); break; }
    case PBOP_SET_TRAFFIC_LOG:  { UINT32 v = PbR_U32(&r); if (!r.ok) return FALSE; g_api.SetTrafficLoggingEnabled(v != 0); break; }
    case PBOP_CLEAR_CONN_LOGS:  g_api.ClearConnectionLogs(); break;
    case PBOP_START: ret = g_api.Start(); break;
    case PBOP_STOP:  ret = g_api.Stop();  break;
    default: return FALSE;
    }
    PbW_U32(resp, ret);
    return TRUE;
}

static void ClosePipes(void)
{
    InterlockedExchange(&g_evt_live, 0);
    EnterCriticalSection(&g_evt_lock);
    if (g_evt != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(g_evt); CloseHandle(g_evt); g_evt = INVALID_HANDLE_VALUE; }
    LeaveCriticalSection(&g_evt_lock);
    if (g_ctl != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(g_ctl); CloseHandle(g_ctl); g_ctl = INVALID_HANDLE_VALUE; }
}

static HANDLE MakePipe(const wchar_t *name, BOOL first, DWORD openMode)
{
    SECURITY_ATTRIBUTES sa; ZeroMemory(&sa, sizeof(sa)); sa.nLength = sizeof(sa);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PB_PIPE_SDDL, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
        return INVALID_HANDLE_VALUE;
    HANDLE h = CreateNamedPipeW(name,
        openMode | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,                       // single instance: one client at a time
        PB_MSG_MAX, PB_MSG_MAX, 0, &sa);
    LocalFree(sa.lpSecurityDescriptor);
    return h;
}

// ConnectNamedPipe on a helper thread so a client that opens the control pipe but never
// opens the event pipe cannot wedge the service.
typedef struct { HANDLE pipe; BOOL ok; } ConnJob;
static DWORD WINAPI ConnThread(LPVOID a)
{
    ConnJob *c = (ConnJob *)a;
    c->ok = ConnectNamedPipe(c->pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED;
    return 0;
}

static void ServeClient(void)
{
    BYTE req[PB_MSG_MAX], rsp[PB_MSG_MAX];

    // fresh engine for every client
    if (!PB_LoadDirect(&g_api)) return;
    g_api.SetLogCallback(OnLog);
    g_api.SetConnectionCallback(OnConn);
    InterlockedExchange(&g_evt_live, 1);

    for (;;)
    {
        DWORD n = 0;
        if (!ReadFile(g_ctl, req, sizeof(req), &n, NULL) || g_stop) break;
        PbW w; PbW_Init(&w, rsp, sizeof(rsp));
        if (!Dispatch(req, n, &w) || !w.ok) break;       // malformed -> drop the client
        DWORD wr = 0;
        if (!WriteFile(g_ctl, rsp, w.len, &wr, NULL)) break;
    }

    // client gone: stop capture and unload the engine (DllMain detach frees rules/configs)
    InterlockedExchange(&g_evt_live, 0);
    if (g_api.Stop) g_api.Stop();
    if (g_api.SetLogCallback) g_api.SetLogCallback(NULL);
    if (g_api.SetConnectionCallback) g_api.SetConnectionCallback(NULL);
    PB_UnloadDirect(&g_api);
}

static DWORD WINAPI WorkerMain(LPVOID arg)
{
    (void)arg;
    BOOL first = TRUE;
    while (!g_stop)
    {
        g_ctl = MakePipe(PB_PIPE_CTL, first, PIPE_ACCESS_DUPLEX);
        g_evt = MakePipe(PB_PIPE_EVT, first, PIPE_ACCESS_OUTBOUND);
        if (g_ctl == INVALID_HANDLE_VALUE || g_evt == INVALID_HANDLE_VALUE) { ClosePipes(); Sleep(1000); continue; }
        first = FALSE;

        if (!ConnectNamedPipe(g_ctl, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { ClosePipes(); continue; }
        if (g_stop) { ClosePipes(); break; }

        ConnJob cj = { g_evt, FALSE };
        HANDLE ct = CreateThread(NULL, 0, ConnThread, &cj, 0, NULL);
        if (ct)
        {
            if (WaitForSingleObject(ct, 5000) == WAIT_TIMEOUT)
            {
                CancelSynchronousIo(ct);
                WaitForSingleObject(ct, INFINITE);
            }
            CloseHandle(ct);
        }
        if (cj.ok && !g_stop) ServeClient();
        ClosePipes();
    }
    return 0;
}

static void WINAPI SvcCtrl(DWORD code)
{
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN)
    {
        SetState(SERVICE_STOP_PENDING, 0);
        InterlockedExchange(&g_stop, 1);
        if (g_worker) CancelSynchronousIo(g_worker);          // unblock ReadFile / ConnectNamedPipe
        // wake a ConnectNamedPipe that has not started yet
        HANDLE h = CreateFileW(PB_PIPE_CTL, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
}

static void WINAPI SvcMain(DWORD argc, LPWSTR *argv)
{
    (void)argc; (void)argv;
    g_ssh = RegisterServiceCtrlHandlerW(PB_SERVICE_NAME, SvcCtrl);
    if (!g_ssh) return;
    InitializeCriticalSection(&g_evt_lock);
    SetState(SERVICE_START_PENDING, 0);

    g_worker = CreateThread(NULL, 0, WorkerMain, NULL, 0, NULL);
    if (!g_worker) { SetState(SERVICE_STOPPED, GetLastError()); return; }
    SetState(SERVICE_RUNNING, 0);

    WaitForSingleObject(g_worker, INFINITE);
    CloseHandle(g_worker); g_worker = NULL;
    DeleteCriticalSection(&g_evt_lock);
    SetState(SERVICE_STOPPED, 0);
}

int wmain(void)
{
    // The engine DLL is loaded from our own directory by absolute path (PB_LoadDirect), and the
    // service must never search the CWD / PATH for it.
    SetDllDirectoryW(L"");
    SERVICE_TABLE_ENTRYW table[] = { { (LPWSTR)PB_SERVICE_NAME, SvcMain }, { NULL, NULL } };
    if (!StartServiceCtrlDispatcherW(table))
    {
        fwprintf(stderr, L"ProxyBridgeSvc is a Windows service; it is started by the Service Control Manager.\n");
        return 1;
    }
    return 0;
}
