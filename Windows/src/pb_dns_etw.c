#include "pb_internal.h"
#include <evntrace.h>
#include <tdh.h>
#include <limits.h>

#pragma comment(lib, "tdh.lib")

#define DNS_ETW_DECISION_WAIT_MS 5
#define DNS_ETW_PENDING_MAX 256
#define DNS_ETW_PENDING_TTL_MS 5000
#define DNS_ETW_PENDING_FLUSH_INTERVAL_MS 20
#define DNS_ETW_FALLBACK_FLUSH_INTERVAL_MS 100

static const GUID g_dns_client_provider =
    { 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };

typedef struct DNS_ETW_STATE {
    TRACEHANDLE session;
    TRACEHANDLE consumer;
    HANDLE thread;
    HANDLE flush_thread;
    HANDLE selftest_thread;
    DWORD selftest_pid;
    HANDLE event_ready;
    HANDLE flush_request;
    HANDLE flush_done;
    EVENT_TRACE_PROPERTIES *properties;
    WCHAR name[96];
    volatile LONG stopping;
    volatile LONG64 starts;
    volatile LONG64 starts_pid4;
    volatile LONG64 starts_pid0;
    volatile LONG64 events;
    volatile LONG64 mapped;
    volatile LONG64 pid4;
    volatile LONG64 pid0;
    volatile LONG64 doh;
    volatile LONG64 dot;
    volatile LONG64 doh_pid4;
    volatile LONG64 dot_pid4;
    volatile LONG64 flush_requests;
    volatile LONG64 flush_successes;
    volatile LONG64 flush_failures;
    volatile LONG64 lookup_waits;
    volatile LONG64 lookup_hits;
    volatile LONG64 lookup_timeouts;
    volatile LONG64 last_flush_request_ms;
    volatile LONG64 no_results_field;
    volatile LONG64 unparsed_results;
    volatile LONG sample_logged;
    volatile LONG dumps_logged;
    volatile LONG first_dumps_logged;
    volatile LONG mapped_dumped;
    volatile LONG selftest_dumped;
    volatile LONG empty_lines_logged;
    volatile LONG mapped_lines_logged;
    volatile LONG64 status_ok;
    volatile LONG64 status_failed;
    volatile LONG64 last_failed_status;
    volatile LONG64 latency[8];
    volatile LONG64 flush_latency[8];
    volatile LONG64 wait_latency[8];
    volatile LONG flush_status;
    LARGE_INTEGER qpc_frequency;
} DNS_ETW_STATE;

static DNS_ETW_STATE g_dns_etw;

typedef struct DNS_ETW_PENDING_QUERY {
    BOOL used;
    DWORD pid;
    FILETIME process_created;
    ULONGLONG event_qpc;
    ULONGLONG token;
} DNS_ETW_PENDING_QUERY;

static SRWLOCK g_dns_etw_pending_lock = SRWLOCK_INIT;
static DNS_ETW_PENDING_QUERY g_dns_etw_pending[DNS_ETW_PENDING_MAX];
static volatile LONG64 g_dns_etw_pending_token;

static BOOL dns_etw_pending_expired(ULONGLONG event_qpc, ULONGLONG now_qpc)
{
    if (!event_qpc || now_qpc < event_qpc || g_dns_etw.qpc_frequency.QuadPart <= 0)
        return FALSE;
    ULONGLONG ttl = (ULONGLONG)g_dns_etw.qpc_frequency.QuadPart * DNS_ETW_PENDING_TTL_MS / 1000;
    return now_qpc - event_qpc > ttl;
}

static ULONGLONG dns_etw_pending_prune_locked(ULONGLONG now_qpc)
{
    ULONGLONG expired = 0;
    for (size_t i = 0; i < _countof(g_dns_etw_pending); i++)
    {
        DNS_ETW_PENDING_QUERY *entry = &g_dns_etw_pending[i];
        if (entry->used && dns_etw_pending_expired(entry->event_qpc, now_qpc))
        {
            entry->used = FALSE;
            expired++;
        }
    }
    return expired;
}

static void dns_etw_pending_start(DWORD pid, ULONGLONG event_qpc)
{
    FILETIME created;
    HANDLE process = NULL;
    if (!get_process_identity(pid, &created, &process))
    {
        dns_process_cache_note_gap(1);
        return;
    }
    CloseHandle(process);

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    DNS_ETW_PENDING_QUERY *slot = NULL;
    DNS_ETW_PENDING_QUERY *oldest = NULL;
    AcquireSRWLockExclusive(&g_dns_etw_pending_lock);
    ULONGLONG expired = dns_etw_pending_prune_locked((ULONGLONG)now.QuadPart);
    for (size_t i = 0; i < _countof(g_dns_etw_pending); i++)
    {
        DNS_ETW_PENDING_QUERY *entry = &g_dns_etw_pending[i];
        if (!entry->used) { slot = entry; break; }
        if (!oldest || entry->event_qpc < oldest->event_qpc) oldest = entry;
    }
    BOOL evicted = slot == NULL;
    if (!slot) slot = oldest;
    if (slot)
    {
        slot->used = TRUE;
        slot->pid = pid;
        slot->process_created = created;
        slot->event_qpc = event_qpc;
        slot->token = (ULONGLONG)InterlockedIncrement64(&g_dns_etw_pending_token);
    }
    ReleaseSRWLockExclusive(&g_dns_etw_pending_lock);
    if (expired) dns_process_cache_note_gap(expired);
    if (evicted) dns_process_cache_note_gap(1);
}

static BOOL dns_etw_pending_for_pid(DWORD pid, ULONGLONG before_qpc)
{
    BOOL found = FALSE;
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    AcquireSRWLockExclusive(&g_dns_etw_pending_lock);
    ULONGLONG expired = dns_etw_pending_prune_locked((ULONGLONG)now.QuadPart);
    for (size_t i = 0; i < _countof(g_dns_etw_pending); i++)
    {
        if (g_dns_etw_pending[i].used && g_dns_etw_pending[i].pid == pid &&
            (!before_qpc || g_dns_etw_pending[i].event_qpc <= before_qpc))
        {
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_dns_etw_pending_lock);
    if (expired) dns_process_cache_note_gap(expired);
    return found;
}

static BOOL dns_etw_pending_match(DWORD pid, ULONGLONG event_qpc,
                                 FILETIME *process_created, ULONGLONG *token)
{
    DNS_ETW_PENDING_QUERY *match = NULL;
    AcquireSRWLockShared(&g_dns_etw_pending_lock);
    for (size_t i = 0; i < _countof(g_dns_etw_pending); i++)
    {
        DNS_ETW_PENDING_QUERY *entry = &g_dns_etw_pending[i];
        if (entry->used && entry->pid == pid && entry->event_qpc <= event_qpc &&
            !dns_etw_pending_expired(entry->event_qpc, event_qpc) &&
            (!match || entry->event_qpc > match->event_qpc))
            match = entry;
    }
    if (match)
    {
        *process_created = match->process_created;
        *token = match->token;
    }
    ReleaseSRWLockShared(&g_dns_etw_pending_lock);
    return match != NULL;
}

static void dns_etw_pending_complete(ULONGLONG token)
{
    AcquireSRWLockExclusive(&g_dns_etw_pending_lock);
    for (size_t i = 0; i < _countof(g_dns_etw_pending); i++)
    {
        DNS_ETW_PENDING_QUERY *entry = &g_dns_etw_pending[i];
        if (entry->used && entry->token == token)
        {
            entry->used = FALSE;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_dns_etw_pending_lock);
}

static void dns_etw_record_latency(volatile LONG64 buckets[8], LONGLONG ticks)
{
    if (ticks < 0) ticks = 0;
    if (g_dns_etw.qpc_frequency.QuadPart <= 0) return;
    ULONGLONG us = (ULONGLONG)ticks * 1000000 /
                   (ULONGLONG)g_dns_etw.qpc_frequency.QuadPart;
    static const ULONGLONG upper_us[] = { 100, 500, 1000, 5000, 10000, 50000, 100000 };
    LONG bucket = 7;
    for (LONG i = 0; i < 7; i++) if (us <= upper_us[i]) { bucket = i; break; }
    InterlockedIncrement64(&buckets[bucket]);
}

static DWORD dns_etw_elapsed_ms(LARGE_INTEGER start)
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (now.QuadPart <= start.QuadPart || g_dns_etw.qpc_frequency.QuadPart <= 0)
        return 0;
    ULONGLONG ticks = (ULONGLONG)(now.QuadPart - start.QuadPart);
    return (DWORD)((ticks * 1000 + (ULONGLONG)g_dns_etw.qpc_frequency.QuadPart - 1) /
                   (ULONGLONG)g_dns_etw.qpc_frequency.QuadPart);
}

static BOOL dns_etw_schedule_flush(BOOL has_pending_query)
{
    ULONGLONG now = GetTickCount64();
    ULONGLONG interval = has_pending_query
        ? DNS_ETW_PENDING_FLUSH_INTERVAL_MS : DNS_ETW_FALLBACK_FLUSH_INTERVAL_MS;

    // A single packet thread calls lookups. Reuse an in-flight flush, but do not make
    // another connection wait for it; fallback flushes are only for future lookups.
    if (WaitForSingleObject(g_dns_etw.flush_done, 0) != WAIT_OBJECT_0)
        return FALSE;

    LONG64 previous = InterlockedCompareExchange64(&g_dns_etw.last_flush_request_ms, 0, 0);
    if (previous != 0 && now - (ULONGLONG)previous < interval)
        return FALSE;
    if (InterlockedCompareExchange64(&g_dns_etw.last_flush_request_ms,
                                     (LONG64)now, previous) != previous)
        return FALSE;

    ResetEvent(g_dns_etw.flush_done);
    if (!SetEvent(g_dns_etw.flush_request))
    {
        InterlockedExchange(&g_dns_etw.flush_status, (LONG)ERROR_INVALID_HANDLE);
        SetEvent(g_dns_etw.flush_done);
        return FALSE;
    }
    InterlockedIncrement64(&g_dns_etw.flush_requests);
    return TRUE;
}

static void dns_etw_close_events(void)
{
    if (g_dns_etw.event_ready) CloseHandle(g_dns_etw.event_ready);
    if (g_dns_etw.flush_request) CloseHandle(g_dns_etw.flush_request);
    if (g_dns_etw.flush_done) CloseHandle(g_dns_etw.flush_done);
    g_dns_etw.event_ready = NULL;
    g_dns_etw.flush_request = NULL;
    g_dns_etw.flush_done = NULL;
}

static WCHAR *etw_read_string(EVENT_RECORD *record, const WCHAR *name)
{
    PROPERTY_DATA_DESCRIPTOR desc;
    ULONG size = 0;
    desc.PropertyName = (ULONGLONG)(ULONG_PTR)name;
    desc.ArrayIndex = ULONG_MAX;
    desc.Reserved = 0;
    if (TdhGetPropertySize(record, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS ||
        size > 1024 * 1024)
        return NULL;

    // A zero-length value is a real answer ("the query produced nothing"), not a missing
    // field: return an empty string so callers can tell the two apart.
    WCHAR *value = (WCHAR *)calloc(1, size + sizeof(WCHAR));
    if (!value) return NULL;
    if (size && TdhGetProperty(record, 0, NULL, 1, &desc, size, (PBYTE)value) != ERROR_SUCCESS)
    {
        free(value);
        return NULL;
    }
    value[size / sizeof(WCHAR)] = L'\0';
    return value;
}

static BOOL etw_read_u32(EVENT_RECORD *record, const WCHAR *name, DWORD *value)
{
    PROPERTY_DATA_DESCRIPTOR desc;
    ULONG size = 0;
    desc.PropertyName = (ULONGLONG)(ULONG_PTR)name;
    desc.ArrayIndex = ULONG_MAX;
    desc.Reserved = 0;
    if (TdhGetPropertySize(record, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS || size != sizeof(*value))
        return FALSE;
    return TdhGetProperty(record, 0, NULL, 1, &desc, size, (PBYTE)value) == ERROR_SUCCESS;
}

static BOOL etw_hostname_utf8(const WCHAR *wide, char out[256])
{
    if (!wide || !wide[0]) return FALSE;
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, out, 256, NULL, NULL);
    if (count <= 1 || count > 256) return FALSE;
    size_t len = (size_t)count - 1;
    if (len && out[len - 1] == '.') out[--len] = '\0';
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)out[i];
        if (c <= 0x20 || c == 0x7f || c == ';' || c == '\\') return FALSE;
        if (c >= 'A' && c <= 'Z') out[i] = (char)(c + ('a' - 'A'));
    }
    return len > 0;
}

static BOOL etw_ip_token(const WCHAR *start, size_t length, char token[64])
{
    while (length && (*start == L' ' || *start == L'\t')) { start++; length--; }
    while (length && (start[length - 1] == L' ' || start[length - 1] == L'\t')) length--;
    // QueryResults entries may carry a record-type prefix ("A 1.2.3.4") or be a bare
    // address ("1.2.3.4"). Addresses never contain spaces, so keep only the tail
    // after the last space; InetPtonA then accepts either form.
    for (size_t i = length; i > 0; i--)
    {
        WCHAR c = start[i - 1];
        if (c == L' ' || c == L'\t')
        {
            start += i;
            length -= i;
            break;
        }
    }
    if (!length || length >= 64) return FALSE;
    for (size_t i = 0; i < length; i++)
    {
        if (start[i] > 0x7f) return FALSE;
        token[i] = (char)start[i];
    }
    token[length] = '\0';
    return TRUE;
}

// An IPv6 answer may be an IPv4-mapped/compatible address ("::ffff:1.2.3.4").
// The connection that follows is almost always IPv4, so record the v4 form too.
static BOOL etw_ipv6_to_ipv4(const UINT8 ip6[16], UINT32 *ip4)
{
    static const UINT8 zeros[10] = { 0 };
    if (memcmp(ip6, zeros, 10) != 0) return FALSE;
    if (ip6[10] != 0x00 && ip6[10] != 0xff) return FALSE;
    if (ip6[11] != ip6[10]) return FALSE; // ::a.b.c.d or ::ffff:a.b.c.d only
    memcpy(ip4, ip6 + 12, 4);
    return TRUE;
}

// Ask TDH for the schema of a live event and print every top-level property with its
// value. QueryResults is undocumented and its layout varies by Windows build; guessing
// at the format is what made the first implementation silently drop every answer, so
// this dump is the authoritative answer. The engine runs as a service we cannot run a
// separate admin probe from, so the product has to report its own evidence.
static void etw_sanitize(char *text)
{
    for (size_t i = 0; text[i]; i++)
        if (text[i] == '\n' || text[i] == '\r' || text[i] == '\t') text[i] = ' ';
}

static LONG etw_claim_dump_slot(void)
{
    for (;;)
    {
        LONG used = InterlockedCompareExchange(&g_dns_etw.dumps_logged, 0, 0);
        if (used >= 8) return -1;
        if (InterlockedCompareExchange(&g_dns_etw.dumps_logged, used + 1, used) == used)
            return used;
    }
}

static void etw_dump_fields(EVENT_RECORD *record, const char *reason)
{
    if (etw_claim_dump_slot() < 0) return;

    ULONG info_size = 0;
    ULONG status = TdhGetEventInformation(record, 0, NULL, NULL, &info_size);
    if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS)
    {
        log_message("[DNS-ETW] field dump (%s): TdhGetEventInformation sizing failed (%lu)",
                    reason, status);
        return;
    }
    TRACE_EVENT_INFO *info = (TRACE_EVENT_INFO *)calloc(1, info_size ? info_size : 1);
    if (!info) return;
    if (TdhGetEventInformation(record, 0, NULL, info, &info_size) != ERROR_SUCCESS)
    {
        log_message("[DNS-ETW] field dump (%s): TdhGetEventInformation failed (%lu)",
                    reason, GetLastError());
        free(info);
        return;
    }

    log_message("[DNS-ETW] field dump (%s): id=%u pid=%lu fields=%lu", reason,
                record->EventHeader.EventDescriptor.Id,
                (unsigned long)record->EventHeader.ProcessId,
                (unsigned long)info->TopLevelPropertyCount);

    // Top-level properties occupy the first TopLevelPropertyCount entries; the rest are
    // struct members referenced by index.
    for (ULONG i = 0; i < info->TopLevelPropertyCount && i < 32; i++)
    {
        EVENT_PROPERTY_INFO *prop = &info->EventPropertyInfoArray[i];
        const WCHAR *prop_name = (const WCHAR *)((const BYTE *)info + prop->NameOffset);
        char name[80] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, prop_name, -1, name, sizeof(name), NULL, NULL);

        PROPERTY_DATA_DESCRIPTOR desc;
        desc.PropertyName = (ULONGLONG)(ULONG_PTR)prop_name;
        desc.ArrayIndex = ULONG_MAX;
        desc.Reserved = 0;
        ULONG size = 0;
        if (TdhGetPropertySize(record, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS)
        {
            log_message("[DNS-ETW]   %s = <unavailable>", name);
            continue;
        }
        if (size == 0)
        {
            log_message("[DNS-ETW]   %s = <empty>", name);
            continue;
        }
        if (size > 4096)
        {
            log_message("[DNS-ETW]   %s = <%lu bytes>", name, (unsigned long)size);
            continue;
        }
        BYTE *raw = (BYTE *)calloc(1, (size_t)size + sizeof(WCHAR));
        if (!raw) continue;
        if (TdhGetProperty(record, 0, NULL, 1, &desc, size, raw) != ERROR_SUCCESS)
        {
            log_message("[DNS-ETW]   %s = <read failed>", name);
            free(raw);
            continue;
        }
        if (prop->nonStructType.InType == TDH_INTYPE_UNICODESTRING)
        {
            WCHAR *wide = (WCHAR *)raw;
            wide[size / sizeof(WCHAR)] = L'\0';
            char value[320] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, wide, -1, value, sizeof(value), NULL, NULL);
            etw_sanitize(value);
            log_message("[DNS-ETW]   %s = \"%s\"", name, value);
        }
        else if (size == sizeof(ULONG))
            log_message("[DNS-ETW]   %s = %lu (u32)", name, *(ULONG *)raw);
        else if (size == sizeof(ULONGLONG))
            log_message("[DNS-ETW]   %s = %llu (u64)", name, *(ULONGLONG *)raw);
        else
        {
            char hex[64] = { 0 };
            for (ULONG b = 0; b < size && b < 16; b++)
                _snprintf_s(hex + b * 3, sizeof(hex) - b * 3, _TRUNCATE, "%02x ", raw[b]);
            log_message("[DNS-ETW]   %s = %s(%lu bytes)", name, hex, (unsigned long)size);
        }
        free(raw);
    }
    free(info);
}

// One compact line per interesting event, naming the process that made the query. A
// per-process view is the only way to answer "is this app's DNS reaching us at all"
// versus "we see the query but Windows gave us no addresses for it".
static void etw_log_event_line(EVENT_RECORD *record, const char *query,
                               const char *kind, DWORD status)
{
    char proc[MAX_PROCESS_NAME] = { 0 };
    if (!get_process_name_from_pid(record->EventHeader.ProcessId, proc, sizeof(proc)))
        _snprintf_s(proc, sizeof(proc), _TRUNCATE, "pid-%lu",
                    (unsigned long)record->EventHeader.ProcessId);
    log_message("[DNS-ETW] %s: proc=%s pid=%lu status=%lu query=\"%s\"",
                kind, proc, (unsigned long)record->EventHeader.ProcessId,
                (unsigned long)status, query[0] ? query : "(none)");
}

static void etw_store_results(EVENT_RECORD *record, const WCHAR *query_name,
                              const WCHAR *query_results, const FILETIME *expected_created,
                              ULONGLONG consumed_qpc)
{
    char hostname[256];
    if (!etw_hostname_utf8(query_name, hostname)) return;

    // Dump the first few events unconditionally: a single sample cannot distinguish
    // "this one query failed" from "results are never populated on this build".
    LONG ordinal = InterlockedIncrement(&g_dns_etw.first_dumps_logged);
    if (ordinal <= 3)
    {
        char reason[32];
        _snprintf_s(reason, sizeof(reason), _TRUNCATE, "completion event #%ld", ordinal);
        etw_dump_fields(record, reason);
    }

    DWORD query_status = 0;
    if (etw_read_u32(record, L"QueryStatus", &query_status))
    {
        if (query_status == 0) InterlockedIncrement64(&g_dns_etw.status_ok);
        else
        {
            InterlockedIncrement64(&g_dns_etw.status_failed);
            InterlockedExchange64(&g_dns_etw.last_failed_status, (LONGLONG)query_status);
        }
    }

    if (!query_results || !query_results[0])
    {
        // Either the field is absent on this build or the query genuinely returned
        // nothing. Both look identical to the parser, so dump the whole event.
        InterlockedIncrement64(&g_dns_etw.no_results_field);
        if (InterlockedIncrement(&g_dns_etw.empty_lines_logged) <= 12)
            etw_log_event_line(record, hostname, "no addresses", query_status);
        etw_dump_fields(record, "empty QueryResults");
        return;
    }

    ULONGLONG event_qpc = (ULONGLONG)record->EventHeader.TimeStamp.QuadPart;
    DWORD pid = record->EventHeader.ProcessId;
    UINT32 stored = 0;
    const WCHAR *cursor = query_results;
    while (*cursor)
    {
        while (*cursor == L';' || *cursor == L' ' || *cursor == L'\t') cursor++;
        if (!*cursor) break;
        const WCHAR *end = wcschr(cursor, L';');
        if (!end) end = cursor + wcslen(cursor);
        char token[64];
        if (etw_ip_token(cursor, (size_t)(end - cursor), token))
        {
            struct in_addr ip4;
            struct in6_addr ip6;
            if (InetPtonA(AF_INET, token, &ip4) == 1)
            {
                if (dns_process_cache_store(pid, expected_created, FALSE, ip4.s_addr, NULL,
                                            hostname, 3008, event_qpc, consumed_qpc, FALSE, 0))
                    stored++;
            }
            else if (InetPtonA(AF_INET6, token, &ip6) == 1)
            {
                if (dns_process_cache_store(pid, expected_created, TRUE, 0, (const UINT8 *)&ip6,
                                            hostname, 3008, event_qpc, consumed_qpc, FALSE, 0))
                    stored++;
                UINT32 mapped;
                if (etw_ipv6_to_ipv4((const UINT8 *)&ip6, &mapped) &&
                    dns_process_cache_store(pid, expected_created, FALSE, mapped, NULL,
                                            hostname, 3008, event_qpc, consumed_qpc, FALSE, 0))
                    stored++;
            }
        }
        cursor = *end ? end + 1 : end;
    }

    if (stored)
    {
        InterlockedExchangeAdd64(&g_dns_etw.mapped, stored);
        if (InterlockedIncrement(&g_dns_etw.mapped_lines_logged) <= 5)
            etw_log_event_line(record, hostname, "mapped", query_status);
        if (InterlockedCompareExchange(&g_dns_etw.mapped_dumped, 1, 0) == 0)
            etw_dump_fields(record, "first event that produced an address");
    }
    else
    {
        // No address survived parsing. This is the signal that the QueryResults
        // layout differs from what this parser expects, so capture the whole event.
        InterlockedIncrement64(&g_dns_etw.unparsed_results);
        etw_dump_fields(record, "no address parsed");
    }
}

static void WINAPI dns_etw_event(EVENT_RECORD *record)
{
    if (!IsEqualGUID(&record->EventHeader.ProviderId, &g_dns_client_provider))
        return;
    if (record->EventHeader.EventDescriptor.Id == 3006)
    {
        InterlockedIncrement64(&g_dns_etw.starts);
        if (record->EventHeader.ProcessId == 4) InterlockedIncrement64(&g_dns_etw.starts_pid4);
        else if (record->EventHeader.ProcessId == 0) InterlockedIncrement64(&g_dns_etw.starts_pid0);
        dns_etw_pending_start(record->EventHeader.ProcessId,
                              (ULONGLONG)record->EventHeader.TimeStamp.QuadPart);
        return;
    }
    if (record->EventHeader.EventDescriptor.Id == 8043 ||
        record->EventHeader.EventDescriptor.Id == 8044)
    {
        DWORD client_pid = 0;
        if (record->EventHeader.EventDescriptor.Id == 8043)
        {
            InterlockedIncrement64(&g_dns_etw.doh);
            if (etw_read_u32(record, L"ClientPID", &client_pid) && client_pid == 4)
                InterlockedIncrement64(&g_dns_etw.doh_pid4);
        }
        else
        {
            InterlockedIncrement64(&g_dns_etw.dot);
            if (etw_read_u32(record, L"ClientPID", &client_pid) && client_pid == 4)
                InterlockedIncrement64(&g_dns_etw.dot_pid4);
        }
        return;
    }
    if (record->EventHeader.EventDescriptor.Id != 3008) return;

    LARGE_INTEGER consumed;
    QueryPerformanceCounter(&consumed);
    InterlockedIncrement64(&g_dns_etw.events);
    if (record->EventHeader.ProcessId == 4) InterlockedIncrement64(&g_dns_etw.pid4);
    else if (record->EventHeader.ProcessId == 0) InterlockedIncrement64(&g_dns_etw.pid0);
    // Our own self-test query is the one event whose semantics we control: dump it
    // regardless of how many samples other traffic has already consumed.
    if (record->EventHeader.ProcessId == g_dns_etw.selftest_pid &&
        InterlockedCompareExchange(&g_dns_etw.selftest_dumped, 1, 0) == 0)
        etw_dump_fields(record, "self-test query");

    WCHAR *query = etw_read_string(record, L"QueryName");
    WCHAR *results = etw_read_string(record, L"QueryResults");
    FILETIME expected_created;
    ULONGLONG pending_token = 0;
    if (dns_etw_pending_match(record->EventHeader.ProcessId,
                              (ULONGLONG)record->EventHeader.TimeStamp.QuadPart,
                              &expected_created, &pending_token))
    {
        etw_store_results(record, query, results, &expected_created,
                          (ULONGLONG)consumed.QuadPart);
        dns_etw_pending_complete(pending_token);
    }
    else
    {
        dns_process_cache_note_gap(1);
        if (InterlockedIncrement(&g_dns_etw.empty_lines_logged) <= 12)
            log_message("[DNS-ETW] completion event for pid %lu has no matching query-start identity; ignored",
                        (unsigned long)record->EventHeader.ProcessId);
    }
    free(query);
    free(results);
    dns_etw_record_latency(g_dns_etw.latency,
                           consumed.QuadPart - record->EventHeader.TimeStamp.QuadPart);
    if (g_dns_etw.event_ready) SetEvent(g_dns_etw.event_ready);
}

// Resolve a name from this process and check whether our own DNS event produced a usable
// cache entry. The engine runs as a service, so nobody can attach an elevated probe to
// the live session; this self-test is the only way to prove the whole chain
// (event arrives -> QueryResults is populated -> parser stores it -> lookup finds it)
// without depending on whatever traffic happens to be flowing.
static DWORD WINAPI dns_etw_selftest(LPVOID unused)
{
    (void)unused;
    if (InterlockedCompareExchange(&g_dns_etw.stopping, 0, 0)) return 0;
    Sleep(400); // let the session settle before generating traffic
    if (InterlockedCompareExchange(&g_dns_etw.stopping, 0, 0)) return 0;

    ADDRINFOEXW hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    PADDRINFOEXW result = NULL;
    struct timeval timeout = { 2, 0 };
    int rc = GetAddrInfoExW(L"www.microsoft.com", NULL, NS_DNS, NULL,
                            &hints, &result, &timeout, NULL, NULL, NULL);
    if (InterlockedCompareExchange(&g_dns_etw.stopping, 0, 0))
    {
        if (result) FreeAddrInfoExW(result);
        return 0;
    }
    if (rc != 0 || !result)
    {
        log_message("[DNS-ETW] self-test: GetAddrInfoExW(www.microsoft.com) failed (%d)", rc);
        return 0;
    }

    UINT32 ip4 = 0;
    UINT8 ip6[16] = { 0 };
    BOOL have_v4 = FALSE, have_v6 = FALSE;
    ULONG count = 0;
    for (PADDRINFOEXW node = result; node; node = node->ai_next)
    {
        count++;
        if (node->ai_family == AF_INET && node->ai_addrlen >= sizeof(struct sockaddr_in) && !have_v4)
        {
            struct sockaddr_in *sa = (struct sockaddr_in *)node->ai_addr;
            ip4 = sa->sin_addr.s_addr;
            have_v4 = TRUE;
        }
        else if (node->ai_family == AF_INET6 && node->ai_addrlen >= sizeof(struct sockaddr_in6) && !have_v6)
        {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)node->ai_addr;
            memcpy(ip6, &sa->sin6_addr, 16);
            have_v6 = TRUE;
        }
    }
    FreeAddrInfoExW(result);

    // The session's FlushTimer is 1s, so an event can sit in the buffer for a while.
    char domain[256] = { 0 };
    for (int attempt = 0; attempt < 40; attempt++)
    {
        if (InterlockedCompareExchange(&g_dns_etw.stopping, 0, 0)) return 0;
        if (have_v4 && dns_process_cache_lookup(g_dns_etw.selftest_pid, FALSE, ip4, NULL,
                                                0, domain, sizeof(domain)))
        {
            log_message("[DNS-ETW] self-test: resolved www.microsoft.com and recovered \"%s\" from our own DNS event",
                        domain);
            return 0;
        }
        if (have_v6 && dns_process_cache_lookup(g_dns_etw.selftest_pid, TRUE, 0, ip6,
                                                0, domain, sizeof(domain)))
        {
            log_message("[DNS-ETW] self-test: resolved www.microsoft.com (IPv6) and recovered \"%s\" from our own DNS event",
                        domain);
            return 0;
        }
        Sleep(100);
    }

    char ip_text[64] = "(none)";
    if (have_v4) format_ip_address(ip4, ip_text, sizeof(ip_text));
    log_message("[DNS-ETW] self-test: getaddrinfo returned %lu addresses (%s) but no cache entry was recovered; complete=%lld mapped=%lld empty-results=%lld unparsed=%lld",
                (unsigned long)count, ip_text, g_dns_etw.events, g_dns_etw.mapped,
                g_dns_etw.no_results_field, g_dns_etw.unparsed_results);
    return 0;
}

static DWORD WINAPI dns_etw_consumer(LPVOID unused)
{
    (void)unused;
    TRACEHANDLE consumer = g_dns_etw.consumer;
    ULONG status = ProcessTrace(&consumer, 1, NULL, NULL);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED && !g_dns_etw.stopping)
        log_message("[DNS-ETW] ProcessTrace stopped with error %lu", status);
    return status;
}

static DWORD WINAPI dns_etw_flush_worker(LPVOID unused)
{
    (void)unused;
    while (WaitForSingleObject(g_dns_etw.flush_request, INFINITE) == WAIT_OBJECT_0)
    {
        if (g_dns_etw.stopping) break;
        LARGE_INTEGER start, end;
        QueryPerformanceCounter(&start);
        ULONG status = ControlTraceW(g_dns_etw.session, g_dns_etw.name,
                                     g_dns_etw.properties, EVENT_TRACE_CONTROL_FLUSH);
        QueryPerformanceCounter(&end);
        InterlockedExchange(&g_dns_etw.flush_status, (LONG)status);
        if (status == ERROR_SUCCESS) InterlockedIncrement64(&g_dns_etw.flush_successes);
        else InterlockedIncrement64(&g_dns_etw.flush_failures);
        dns_etw_record_latency(g_dns_etw.flush_latency, end.QuadPart - start.QuadPart);
        SetEvent(g_dns_etw.flush_done);
    }
    return 0;
}

BOOL dns_etw_lookup(DWORD pid, BOOL is_ipv6, UINT32 ip, const UINT8 ip6[16],
                    ULONGLONG before_qpc, BOOL wait_for_flush,
                    char *out_domain, size_t out_size)
{
    if (dns_process_cache_lookup(pid, is_ipv6, ip, ip6, before_qpc,
                                 out_domain, out_size))
        return TRUE;
    if (!wait_for_flush)
    {
        dns_process_cache_note_gap(1);
        return FALSE;
    }
    if (!g_dns_etw.session || !g_dns_etw.flush_thread || !g_dns_etw.event_ready ||
        !g_dns_etw.flush_request || !g_dns_etw.flush_done)
    {
        dns_process_cache_note_gap(1);
        return FALSE;
    }

    BOOL has_pending_query = dns_etw_pending_for_pid(pid, before_qpc);
    BOOL flush_scheduled = dns_etw_schedule_flush(has_pending_query);
    if (!has_pending_query || !flush_scheduled)
    {
        // shortcut: without a preceding 3006, use IP for this packet; revisit if stage-one proves a safe earlier signal.
        dns_process_cache_note_gap(1);
        return FALSE;
    }

    LARGE_INTEGER start;
    QueryPerformanceCounter(&start);
    InterlockedIncrement64(&g_dns_etw.lookup_waits);

    HANDLE events[] = { g_dns_etw.event_ready, g_dns_etw.flush_done };
    for (;;)
    {
        DWORD elapsed = dns_etw_elapsed_ms(start);
        if (elapsed >= DNS_ETW_DECISION_WAIT_MS) break;
        DWORD remaining = DNS_ETW_DECISION_WAIT_MS - elapsed;
        DWORD wait = WaitForMultipleObjects(2, events, FALSE, remaining);
        if (wait == WAIT_TIMEOUT || wait == WAIT_FAILED) break;
        if (dns_process_cache_lookup(pid, is_ipv6, ip, ip6, before_qpc,
                                     out_domain, out_size))
        {
            InterlockedIncrement64(&g_dns_etw.lookup_hits);
            LARGE_INTEGER end;
            QueryPerformanceCounter(&end);
            dns_etw_record_latency(g_dns_etw.wait_latency, end.QuadPart - start.QuadPart);
            return TRUE;
        }
        if (wait == WAIT_OBJECT_0 + 1)
        {
            LONG status = InterlockedCompareExchange(&g_dns_etw.flush_status, 0, 0);
            ResetEvent(g_dns_etw.flush_done);
            if (status != ERROR_SUCCESS) break;
        }
    }

    InterlockedIncrement64(&g_dns_etw.lookup_timeouts);
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    dns_etw_record_latency(g_dns_etw.wait_latency, end.QuadPart - start.QuadPart);
    BOOL found = dns_process_cache_lookup(pid, is_ipv6, ip, ip6, before_qpc,
                                          out_domain, out_size);
    if (found) InterlockedIncrement64(&g_dns_etw.lookup_hits);
    else dns_process_cache_note_gap(1);
    return found;
}

BOOL dns_etw_start(void)
{
    if (g_dns_etw.session || g_dns_etw.thread) return FALSE;
    ZeroMemory(&g_dns_etw, sizeof(g_dns_etw));
    ZeroMemory(g_dns_etw_pending, sizeof(g_dns_etw_pending));
    InterlockedExchange64(&g_dns_etw_pending_token, 0);
    if (!QueryPerformanceFrequency(&g_dns_etw.qpc_frequency) ||
        g_dns_etw.qpc_frequency.QuadPart <= 0)
    {
        log_message("[DNS-ETW] QueryPerformanceFrequency failed; DNS event timing is unavailable");
        return FALSE;
    }
    g_dns_etw.event_ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_dns_etw.flush_request = CreateEventW(NULL, FALSE, FALSE, NULL);
    g_dns_etw.flush_done = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (!g_dns_etw.event_ready || !g_dns_etw.flush_request || !g_dns_etw.flush_done)
    {
        dns_etw_close_events();
        return FALSE;
    }
    _snwprintf_s(g_dns_etw.name, _countof(g_dns_etw.name), _TRUNCATE,
                 L"ProxyBridge DNS Client %lu", GetCurrentProcessId());

    size_t props_size = sizeof(EVENT_TRACE_PROPERTIES) +
                        (_countof(g_dns_etw.name) * sizeof(WCHAR));
    g_dns_etw.properties = (EVENT_TRACE_PROPERTIES *)calloc(1, props_size);
    if (!g_dns_etw.properties)
    {
        dns_etw_close_events();
        return FALSE;
    }
    EVENT_TRACE_PROPERTIES *props = g_dns_etw.properties;
    props->Wnode.BufferSize = (ULONG)props_size;
    props->Wnode.Guid.Data1 = 0x78c9321a;
    props->Wnode.Guid.Data2 = 0x1f2b;
    props->Wnode.Guid.Data3 = 0x4f63;
    DWORD pid = GetCurrentProcessId();
    DWORD tick = GetTickCount();
    memcpy(&props->Wnode.Guid.Data4[0], &pid, sizeof(pid));
    memcpy(&props->Wnode.Guid.Data4[4], &tick, sizeof(tick));
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // ClientContext 1 = QPC clock. This MUST match the domain of WinDivert's
    // WINDIVERT_ADDRESS.Timestamp (also QPC) or every event is "in the future"
    // relative to every packet and the before-SYN lookup filter rejects it all.
    // (2 = system time, 3 = CPU cycle counter.)
    props->Wnode.ClientContext = 1;
    props->BufferSize = 64;
    props->MinimumBuffers = 4;
    props->MaximumBuffers = 16;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer = 1;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((WCHAR *)((BYTE *)props + props->LoggerNameOffset),
             _countof(g_dns_etw.name), g_dns_etw.name);

    ULONG status = StartTraceW(&g_dns_etw.session, g_dns_etw.name, props);
    if (status != ERROR_SUCCESS)
    {
        log_message("[DNS-ETW] StartTrace failed (%lu); process hostname recovery is unavailable", status);
        free(g_dns_etw.properties);
        g_dns_etw.properties = NULL;
        g_dns_etw.session = 0;
        dns_etw_close_events();
        return FALSE;
    }
    // MatchAnyKeyword=0 only enables events whose keyword is 0, so a query-completion
    // event tagged with any keyword bit would never reach us. Ask for every keyword and
    // filter on the event ID instead; DNS-Client is low volume even when fully enabled.
    status = EnableTraceEx2(g_dns_etw.session, &g_dns_client_provider,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                            0xFFFFFFFFFFFFFFFFULL, 0, 0, NULL);
    if (status != ERROR_SUCCESS)
    {
        log_message("[DNS-ETW] EnableTraceEx2 failed (%lu)", status);
        ControlTraceW(g_dns_etw.session, g_dns_etw.name, props, EVENT_TRACE_CONTROL_STOP);
        free(g_dns_etw.properties);
        g_dns_etw.properties = NULL;
        g_dns_etw.session = 0;
        dns_etw_close_events();
        return FALSE;
    }

    EVENT_TRACE_LOGFILEW logfile;
    ZeroMemory(&logfile, sizeof(logfile));
    logfile.LoggerName = g_dns_etw.name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
                               PROCESS_TRACE_MODE_EVENT_RECORD |
                               PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.EventRecordCallback = dns_etw_event;
    g_dns_etw.consumer = OpenTraceW(&logfile);
    if (g_dns_etw.consumer == INVALID_PROCESSTRACE_HANDLE)
    {
        log_message("[DNS-ETW] OpenTrace failed (%lu)", GetLastError());
        ControlTraceW(g_dns_etw.session, g_dns_etw.name, props, EVENT_TRACE_CONTROL_STOP);
        free(g_dns_etw.properties);
        g_dns_etw.properties = NULL;
        g_dns_etw.session = 0;
        dns_etw_close_events();
        return FALSE;
    }
    g_dns_etw.thread = CreateThread(NULL, 0, dns_etw_consumer, NULL, 0, NULL);
    if (!g_dns_etw.thread)
    {
        log_message("[DNS-ETW] Could not start event consumer (%lu)", GetLastError());
        CloseTrace(g_dns_etw.consumer);
        ControlTraceW(g_dns_etw.session, g_dns_etw.name, props, EVENT_TRACE_CONTROL_STOP);
        free(g_dns_etw.properties);
        g_dns_etw.properties = NULL;
        g_dns_etw.session = 0;
        g_dns_etw.consumer = INVALID_PROCESSTRACE_HANDLE;
        dns_etw_close_events();
        return FALSE;
    }
    g_dns_etw.flush_thread = CreateThread(NULL, 0, dns_etw_flush_worker, NULL, 0, NULL);
    if (!g_dns_etw.flush_thread)
    {
        log_message("[DNS-ETW] Could not start flush worker (%lu)", GetLastError());
        InterlockedExchange(&g_dns_etw.stopping, 1);
        CloseTrace(g_dns_etw.consumer);
        ControlTraceW(g_dns_etw.session, g_dns_etw.name, props, EVENT_TRACE_CONTROL_STOP);
        WaitForSingleObject(g_dns_etw.thread, INFINITE);
        CloseHandle(g_dns_etw.thread);
        g_dns_etw.thread = NULL;
        g_dns_etw.consumer = INVALID_PROCESSTRACE_HANDLE;
        free(g_dns_etw.properties);
        g_dns_etw.properties = NULL;
        g_dns_etw.session = 0;
        dns_etw_close_events();
        return FALSE;
    }
    log_message("[DNS-ETW] Listening for DNS Client query-completion events (QPC clock)");
    g_dns_etw.selftest_pid = GetCurrentProcessId();
    g_dns_etw.selftest_thread = CreateThread(NULL, 0, dns_etw_selftest, NULL, 0, NULL);
    if (!g_dns_etw.selftest_thread)
        log_message("[DNS-ETW] Could not start self-test (%lu)", GetLastError());
    return TRUE;
}

void dns_etw_stop(void)
{
    if (!g_dns_etw.session && !g_dns_etw.thread) return;
    ULONG events_lost = 0, realtime_buffers_lost = 0;
    BOOL have_session_stats = FALSE;
    InterlockedExchange(&g_dns_etw.stopping, 1);
    if (g_dns_etw.flush_request) SetEvent(g_dns_etw.flush_request);
    if (g_dns_etw.selftest_thread)
    {
        // The resolver has a finite timeout; join before returning so no diagnostic thread
        // can execute DLL code after the service unloads the engine.
        WaitForSingleObject(g_dns_etw.selftest_thread, INFINITE);
        CloseHandle(g_dns_etw.selftest_thread);
        g_dns_etw.selftest_thread = NULL;
    }
    if (g_dns_etw.flush_thread)
    {
        WaitForSingleObject(g_dns_etw.flush_thread, INFINITE);
        CloseHandle(g_dns_etw.flush_thread);
        g_dns_etw.flush_thread = NULL;
    }
    if (g_dns_etw.session && g_dns_etw.properties)
    {
        ULONG status = ControlTraceW(g_dns_etw.session, g_dns_etw.name,
                                     g_dns_etw.properties, EVENT_TRACE_CONTROL_QUERY);
        if (status == ERROR_SUCCESS)
        {
            have_session_stats = TRUE;
            events_lost = g_dns_etw.properties->EventsLost;
            realtime_buffers_lost = g_dns_etw.properties->RealTimeBuffersLost;
            ULONGLONG lost = events_lost > realtime_buffers_lost ? events_lost : realtime_buffers_lost;
            dns_process_cache_note_gap(lost);
        }
        ControlTraceW(g_dns_etw.session, g_dns_etw.name,
                      g_dns_etw.properties, EVENT_TRACE_CONTROL_STOP);
    }
    if (g_dns_etw.consumer && g_dns_etw.consumer != INVALID_PROCESSTRACE_HANDLE)
        CloseTrace(g_dns_etw.consumer);
    if (g_dns_etw.thread)
    {
        WaitForSingleObject(g_dns_etw.thread, INFINITE);
        CloseHandle(g_dns_etw.thread);
    }
    if (have_session_stats)
        log_message("[DNS-ETW] start=%lld(pid4=%lld,pid0=%lld) complete=%lld(pid4=%lld,pid0=%lld) mapped=%lld doh=%lld(dnscache_pid4=%lld) dot=%lld(dnscache_pid4=%lld) lost=%lu realtime-buffer-lost=%lu",
                    g_dns_etw.starts, g_dns_etw.starts_pid4, g_dns_etw.starts_pid0,
                    g_dns_etw.events, g_dns_etw.pid4, g_dns_etw.pid0, g_dns_etw.mapped,
                    g_dns_etw.doh, g_dns_etw.doh_pid4, g_dns_etw.dot, g_dns_etw.dot_pid4,
                    events_lost, realtime_buffers_lost);
    else
        log_message("[DNS-ETW] session counters unavailable at stop");
    log_message("[DNS-ETW] complete events with no QueryResults field=%lld; events where no address parsed=%lld (both should be 0)",
                g_dns_etw.no_results_field, g_dns_etw.unparsed_results);
    log_message("[DNS-ETW] QueryStatus: success=%lld failed=%lld last-nonzero=%lld (0 means every query reported an answer)",
                g_dns_etw.status_ok, g_dns_etw.status_failed, g_dns_etw.last_failed_status);
    log_message("[DNS-ETW] event-to-callback latency buckets (us <=100/500/1000/5000/10000/50000/100000/>100000): %lld/%lld/%lld/%lld/%lld/%lld/%lld/%lld; cache gaps=%llu",
                g_dns_etw.latency[0], g_dns_etw.latency[1], g_dns_etw.latency[2],
                g_dns_etw.latency[3], g_dns_etw.latency[4], g_dns_etw.latency[5],
                g_dns_etw.latency[6], g_dns_etw.latency[7],
                dns_process_cache_gap_count());
    log_message("[DNS-ETW] on-demand flushes=%lld ok=%lld failed=%lld lookups=%lld hits=%lld timeouts=%lld",
                g_dns_etw.flush_requests, g_dns_etw.flush_successes,
                g_dns_etw.flush_failures, g_dns_etw.lookup_waits,
                g_dns_etw.lookup_hits, g_dns_etw.lookup_timeouts);
    log_message("[DNS-ETW] flush duration buckets (us <=100/500/1000/5000/10000/50000/100000/>100000): %lld/%lld/%lld/%lld/%lld/%lld/%lld/%lld",
                g_dns_etw.flush_latency[0], g_dns_etw.flush_latency[1],
                g_dns_etw.flush_latency[2], g_dns_etw.flush_latency[3],
                g_dns_etw.flush_latency[4], g_dns_etw.flush_latency[5],
                g_dns_etw.flush_latency[6], g_dns_etw.flush_latency[7]);
    log_message("[DNS-ETW] lookup wait buckets (us <=100/500/1000/5000/10000/50000/100000/>100000): %lld/%lld/%lld/%lld/%lld/%lld/%lld/%lld",
                g_dns_etw.wait_latency[0], g_dns_etw.wait_latency[1],
                g_dns_etw.wait_latency[2], g_dns_etw.wait_latency[3],
                g_dns_etw.wait_latency[4], g_dns_etw.wait_latency[5],
                g_dns_etw.wait_latency[6], g_dns_etw.wait_latency[7]);
    if (g_dns_etw.properties) free(g_dns_etw.properties);
    g_dns_etw.properties = NULL;
    g_dns_etw.thread = NULL;
    g_dns_etw.consumer = INVALID_PROCESSTRACE_HANDLE;
    g_dns_etw.session = 0;
    AcquireSRWLockExclusive(&g_dns_etw_pending_lock);
    ZeroMemory(g_dns_etw_pending, sizeof(g_dns_etw_pending));
    ReleaseSRWLockExclusive(&g_dns_etw_pending_lock);
    dns_etw_close_events();
}
