#include "pb_internal.h"

// Owner-PID by local port from WinDivert's SOCKET layer.
//
// Finding the process behind a new outbound TCP connection used to mean fetching the whole
// system TCP table (GetExtendedTcpTable) for every SYN, on the single packet-capture thread.
// The table includes every TIME_WAIT socket, so on a machine that has been busy for hours it
// has tens of thousands of rows and one fetch costs several milliseconds - a few hundred new
// connections per second saturate the thread and everything captured slows down (measured:
// ~3.6 ms per fetch at ~9.6k rows, ~20 ms of capture-thread time per proxied connection).
//
// The socket layer reports every connect() together with its process ID *before* the SYN is
// sent, so a small port-indexed table filled from those events answers the lookup in O(1).
// Anything it cannot answer (event not seen yet, entry too old, socket-layer open failed)
// falls back to the table scan, so behaviour is never worse than before.

#define SOCKMAP_FRESH_MS 8000   // a SYN is evaluated within ~2 s even when the capture queue is backed up

typedef struct { volatile LONG pid; volatile LONG tick; } SOCKMAP_ENTRY;
static SOCKMAP_ENTRY g_sockmap[65536];
static HANDLE g_sock_handle = INVALID_HANDLE_VALUE;
static HANDLE g_sock_thread = NULL;
static volatile LONG g_sock_events = 0, g_sock_hits = 0, g_sock_scans = 0;

static DWORD WINAPI sockmap_thread(LPVOID arg)
{
    (void)arg;
    WINDIVERT_ADDRESS addr;
    while (1)
    {
        if (!WinDivertRecv(g_sock_handle, NULL, 0, NULL, &addr))
        {
            DWORD err = GetLastError();
            if (!running || err == ERROR_INVALID_HANDLE || err == ERROR_NO_DATA || err == ERROR_OPERATION_ABORTED)
                break;
            Sleep(5);
            continue;
        }
        if (addr.Event == WINDIVERT_EVENT_SOCKET_CONNECT && addr.Socket.Protocol == IPPROTO_TCP &&
            addr.Socket.LocalPort != 0 && addr.Socket.ProcessId != 0)
        {
            SOCKMAP_ENTRY *e = &g_sockmap[addr.Socket.LocalPort];
            InterlockedExchange(&e->tick, 0);                       // invalidate while updating
            InterlockedExchange(&e->pid, (LONG)addr.Socket.ProcessId);
            LONG t = (LONG)GetTickCount(); if (t == 0) t = 1;
            InterlockedExchange(&e->tick, t);
            if (InterlockedIncrement(&g_sock_events) == 1)
                log_message("Process lookup: socket events active (first: PID %lu, local port %u)",
                            (unsigned long)addr.Socket.ProcessId, (unsigned)addr.Socket.LocalPort);
        }
    }
    return 0;
}

BOOL sockmap_start(void)
{
    ZeroMemory(g_sockmap, sizeof(g_sockmap));
    g_sock_events = g_sock_hits = g_sock_scans = 0;
    g_sock_handle = WinDivertOpen("event == CONNECT", WINDIVERT_LAYER_SOCKET, 0,
                                  WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (g_sock_handle == INVALID_HANDLE_VALUE)
    {
        log_message("Process lookup: socket layer unavailable (%lu), using the TCP table scan", GetLastError());
        return FALSE;
    }
    WinDivertSetParam(g_sock_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    g_sock_thread = CreateThread(NULL, 0, sockmap_thread, NULL, 0, NULL);
    if (g_sock_thread == NULL)
    {
        WinDivertClose(g_sock_handle);
        g_sock_handle = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    return TRUE;
}

void sockmap_stop(void)
{
    if (g_sock_handle != INVALID_HANDLE_VALUE)
    {
        WinDivertShutdown(g_sock_handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(g_sock_handle);
        g_sock_handle = INVALID_HANDLE_VALUE;
    }
    if (g_sock_thread != NULL)
    {
        WaitForSingleObject(g_sock_thread, 2000);
        CloseHandle(g_sock_thread);
        g_sock_thread = NULL;
        log_message("Process lookup: %ld connections resolved via socket events, %ld via table scan",
                    g_sock_hits, g_sock_scans);
    }
}

// PID that connect()ed from this local port in the last SOCKMAP_FRESH_MS, or 0 (use the table).
DWORD sockmap_lookup_tcp(UINT16 port)
{
    if (g_sock_thread == NULL || port == 0)
        return 0;
    SOCKMAP_ENTRY *e = &g_sockmap[port];
    LONG t1 = e->tick;
    LONG pid = e->pid;
    LONG t2 = e->tick;
    if (t1 == 0 || t1 != t2 || pid == 0)
        return 0;
    if ((LONG)((LONG)GetTickCount() - t1) > SOCKMAP_FRESH_MS)
        return 0;
    InterlockedIncrement(&g_sock_hits);
    return (DWORD)pid;
}

void sockmap_note_scan(void)
{
    InterlockedIncrement(&g_sock_scans);
}
