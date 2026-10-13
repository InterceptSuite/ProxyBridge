// etw_probe.c - one-shot ground-truth probe for the DNS-Client ETW provider.
//
// Purpose: the hostname-recovery implementation parses event 3008 (query complete)
// using field names and a QueryResults layout that were never confirmed against a
// live system. This tool starts the same kind of real-time session the engine uses,
// triggers its own resolutions, and dumps every property of every DNS-Client event
// so the real names, types and string formats can be read off directly.
//
// Build:  cl.exe /nologo /O2 /D_UNICODE /DUNICODE etw_probe.c /link tdh.lib ws2_32.lib
// Run:    etw_probe.exe [seconds]      (default 12)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ws2_32.lib")

static const GUID DNS_CLIENT_PROVIDER =
    { 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };

static LARGE_INTEGER g_freq;
static volatile LONG g_stop;
static TRACEHANDLE   g_consumer;

static DWORD WINAPI consumer_thread(LPVOID unused)
{
    (void)unused;
    TRACEHANDLE h = g_consumer;
    ULONG r = ProcessTrace(&h, 1, NULL, NULL);
    return r;
}

static double qpc_ms(ULONGLONG ticks)
{
    return (double)ticks * 1000.0 / (double)g_freq.QuadPart;
}

// Dump one property value in a readable form, whatever its TDH type.
static void dump_property(EVENT_RECORD *rec, PTRACE_EVENT_INFO info, ULONG index)
{
    const EVENT_PROPERTY_INFO *p = &info->EventPropertyInfoArray[index];
    const WCHAR *name = (const WCHAR *)((const BYTE *)info + p->NameOffset);
    PROPERTY_DATA_DESCRIPTOR desc;
    desc.PropertyName = (ULONGLONG)(ULONG_PTR)name;
    desc.ArrayIndex = ULONG_MAX;
    desc.Reserved = 0;

    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS || size == 0 || size > 65536)
    {
        wprintf(L"      %-22s <unreadable>\n", name);
        return;
    }
    BYTE *buf = (BYTE *)calloc(1, size + 16);
    if (!buf) return;
    if (TdhGetProperty(rec, 0, NULL, 1, &desc, size, buf) != ERROR_SUCCESS)
    {
        wprintf(L"      %-22s <TdhGetProperty failed>\n", name);
        free(buf);
        return;
    }

    USHORT inType = (p->Flags & PropertyParamLength) ? TDH_INTYPE_UNICODESTRING
                                                     : p->nonStructType.InType;
    switch (inType)
    {
    case TDH_INTYPE_UNICODESTRING:
    {
        buf[size] = 0; buf[size + 1] = 0;
        wprintf(L"      %-22s (wstr) \"%ls\"\n", name, (const WCHAR *)buf);
        // Always show the exact bytes too: the QueryResults separator/prefix
        // convention is the whole point of this probe.
        wprintf(L"      %-22s bytes:", name);
        ULONG n = size / 2 > 64 ? 64 : size / 2;
        for (ULONG i = 0; i < n; i++) wprintf(L" %04X", ((const WORD *)buf)[i]);
        wprintf(L"\n");
        break;
    }
    case TDH_INTYPE_ANSISTRING:
        buf[size] = 0;
        wprintf(L"      %-22s (astr) \"%hs\"\n", name, (const char *)buf);
        break;
    case TDH_INTYPE_UINT32:
        wprintf(L"      %-22s (u32)  %lu\n", name, *(ULONG *)buf);
        break;
    case TDH_INTYPE_UINT64:
        wprintf(L"      %-22s (u64)  %llu\n", name, *(ULONGLONG *)buf);
        break;
    case TDH_INTYPE_UINT16:
        wprintf(L"      %-22s (u16)  %u\n", name, *(WORD *)buf);
        break;
    case TDH_INTYPE_UINT8:
        wprintf(L"      %-22s (u8)   %u\n", name, *buf);
        break;
    default:
        wprintf(L"      %-22s (intype=%u) sz=%lu:", name, inType, size);
        ULONG m = size > 32 ? 32 : size;
        for (ULONG i = 0; i < m; i++) wprintf(L" %02X", buf[i]);
        wprintf(L"\n");
        break;
    }
    free(buf);
}

static void WINAPI on_event(EVENT_RECORD *rec)
{
    if (!IsEqualGUID(&rec->EventHeader.ProviderId, &DNS_CLIENT_PROVIDER))
        return;
    // 3006 = query start, 3008 = query complete, 1018/1019 = cache, 8043/8044 = DoH/DoT.
    // Print everything so we can see which IDs actually fire on this machine.
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    ULONGLONG ts = (ULONGLONG)rec->EventHeader.TimeStamp.QuadPart;
    double lag = now.QuadPart > (LONGLONG)ts ? qpc_ms(now.QuadPart - (LONGLONG)ts) : -1.0;

    printf("EVENT id=%u pid=%lu tid=%lu ts=%llu lag=%.3f ms\n",
           rec->EventHeader.EventDescriptor.Id,
           (ULONG)rec->EventHeader.ProcessId, (ULONG)rec->EventHeader.ThreadId,
           ts, lag);

    ULONG info_size = 0;
    if (TdhGetEventInformation(rec, 0, NULL, NULL, &info_size) != ERROR_INSUFFICIENT_BUFFER && !info_size)
    {
        printf("      <no manifest metadata for this event>\n");
        return;
    }
    TRACE_EVENT_INFO *info = (TRACE_EVENT_INFO *)malloc(info_size);
    if (!info) return;
    if (TdhGetEventInformation(rec, 0, NULL, info, &info_size) != ERROR_SUCCESS)
    {
        printf("      <TdhGetEventInformation failed>\n");
        free(info);
        return;
    }
    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++)
        dump_property(rec, info, i);
    free(info);
    fflush(stdout);
}

static DWORD WINAPI resolver_thread(LPVOID unused)
{
    (void)unused;
    const char *names[] = { "www.google.com", "api.openai.com", "www.github.com",
                            "1.1.1.1", "example.com" };
    // Deliberate: resolve, then immediately open a TCP connection, which is exactly
    // the "resolve then connect" pattern whose ordering the engine has to guess at.
    for (int round = 0; round < 3 && !g_stop; round++)
    {
        for (int i = 0; i < 5 && !g_stop; i++)
        {
            struct addrinfo *res = NULL;
            LARGE_INTEGER t0, t1;
            QueryPerformanceCounter(&t0);
            if (getaddrinfo(names[i], "443", NULL, &res) == 0)
            {
                QueryPerformanceCounter(&t1);
                printf("RESOLVE %-18s resolve->return = %.3f ms\n",
                       names[i], qpc_ms(t1.QuadPart - t0.QuadPart));
                if (res)
                {
                    SOCKET s = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
                    if (s != INVALID_SOCKET)
                    {
                        QueryPerformanceCounter(&t1);
                        printf("RESOLVE %-18s resolve->connect-call = %.3f ms\n",
                               names[i], qpc_ms(t1.QuadPart - t0.QuadPart));
                        closesocket(s);
                    }
                    freeaddrinfo(res);
                }
            }
            else
                printf("RESOLVE %-18s FAILED\n", names[i]);
            fflush(stdout);
            Sleep(400);
        }
        Sleep(1000);
    }
    return 0;
}

int wmain(int argc, WCHAR **argv)
{
    int seconds = (argc > 1) ? _wtoi(argv[1]) : 12;
    QueryPerformanceFrequency(&g_freq);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    printf("QPC frequency: %lld Hz (1 tick = %.3f us)\n",
           g_freq.QuadPart, 1e6 / (double)g_freq.QuadPart);
    printf("My PID: %lu\n", GetCurrentProcessId());
    printf("Collecting DNS-Client events for %d seconds...\n\n", seconds);

    WCHAR name[64];
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"PB-ETW-Probe-%lu", GetCurrentProcessId());
    size_t props_size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(name);
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)calloc(1, props_size);
    props->Wnode.BufferSize = (ULONG)props_size;
    props->Wnode.Guid.Data1 = 0x2f0a7c19;
    props->Wnode.Guid.Data2 = 0x4b31;
    props->Wnode.Guid.Data3 = 0x40a2;
    DWORD pid = GetCurrentProcessId(), tick = GetTickCount();
    memcpy(&props->Wnode.Guid.Data4[0], &pid, 4);
    memcpy(&props->Wnode.Guid.Data4[4], &tick, 4);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;               // QPC, same domain as WinDivert timestamps
    props->BufferSize = 64;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer = 1;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    memcpy((BYTE *)props + props->LoggerNameOffset, name, sizeof(name));

    TRACEHANDLE session = 0;
    ULONG st = StartTraceW(&session, name, props);
    if (st != ERROR_SUCCESS)
    {
        printf("StartTrace failed: %lu", st);
        if (st == ERROR_ACCESS_DENIED)
            printf(" (ERROR_ACCESS_DENIED - real-time ETW sessions need admin "
                   "or Performance Log Users membership)");
        printf("\n");
        return 2;
    }
    printf("Session started (ClientContext=1 QPC).\n\n");

    st = EnableTraceEx2(session, &DNS_CLIENT_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (st != ERROR_SUCCESS)
    {
        printf("EnableTraceEx2 failed: %lu\n", st);
        ControlTraceW(session, name, props, EVENT_TRACE_CONTROL_STOP);
        return 3;
    }

    EVENT_TRACE_LOGFILEW logfile;
    ZeroMemory(&logfile, sizeof(logfile));
    logfile.LoggerName = name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD |
                               PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.EventRecordCallback = on_event;
    TRACEHANDLE consumer = OpenTraceW(&logfile);
    if (consumer == INVALID_PROCESSTRACE_HANDLE)
    {
        printf("OpenTrace failed: %lu\n", GetLastError());
        ControlTraceW(session, name, props, EVENT_TRACE_CONTROL_STOP);
        return 4;
    }

    // ProcessTrace blocks until the trace is closed, so run it on its own thread.
    g_consumer = consumer;
    HANDLE thread = CreateThread(NULL, 0, consumer_thread, NULL, 0, NULL);

    HANDLE resolver = CreateThread(NULL, 0, resolver_thread, NULL, 0, NULL);
    WaitForSingleObject(resolver, INFINITE);
    Sleep(1200);
    InterlockedExchange(&g_stop, 1);

    printf("\nStopping...\n");
    ULONG status = ControlTraceW(session, name, props, EVENT_TRACE_CONTROL_QUERY);
    if (status == ERROR_SUCCESS)
        printf("EventsLost=%lu RealTimeBuffersLost=%lu BuffersWritten=%lu\n",
               props->EventsLost, props->RealTimeBuffersLost, props->BuffersWritten);
    CloseTrace(consumer);
    ControlTraceW(session, name, props, EVENT_TRACE_CONTROL_STOP);
    printf("Done.\n");
    return 0;
}
