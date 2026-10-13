#include "pb_internal.h"
#include <assert.h>
#include <limits.h>
#include <shlobj.h>
#include <sddl.h>

#pragma comment(lib, "shell32.lib")

typedef struct DNS_PROCESS_ENTRY {
    DWORD pid;
    FILETIME created;
    HANDLE process;
    HANDLE wait;
    volatile LONG exited;
    UINT32 count;
    struct DNS_PROCESS_ENTRY *next;
} DNS_PROCESS_ENTRY;

#define DNS_PROCESS_MAX_ENTRIES 4096
#define DNS_PROCESS_MAX_TOTAL 65536
#define DNS_PROCESS_BUCKETS 4096
#define DNS_SNAPSHOT_VERSION 4
#define DNS_SNAPSHOT_MAX_BYTES (21u * 1024u * 1024u)
#define DNS_NETWORK_MAX_QUERIES 512
#define DNS_NETWORK_QUERY_TTL_MS 30000
#define DNS_TCP_MAX_FLOWS 16
#define DNS_TCP_WINDOW_SIZE 65536
#define DNS_TCP_BITMAP_SIZE (DNS_TCP_WINDOW_SIZE / 8)
#define DNS_TCP_MESSAGE_MAX 65535
#define DNS_TCP_FLOW_TTL_MS 30000
#define DNS_SOURCE_NETWORK_DNS 1
// shortcut: cap DNS TCP reassembly at 16 concurrent streams and a 64 KiB window;
// raise the cap only if capture-gap measurements show real resolver traffic is evicted.

typedef struct DNS_NETWORK_QUERY {
    DWORD pid;
    FILETIME process_created;
    BOOL is_ipv6;
    BOOL is_tcp;
    UINT16 id;
    UINT16 src_port;
    UINT16 dst_port;
    UINT16 qtype;
    UINT16 qclass;
    BOOL ambiguous;
    UINT8 src_ip[16];
    UINT8 dst_ip[16];
    ULONGLONG tick;
    char qname[256];
} DNS_NETWORK_QUERY;

typedef struct DNS_TCP_DIRECTION {
    BOOL initialized;
    UINT32 next_seq;
    UINT32 ring_head;
    UINT32 pending_bytes;
    UINT8 *window;
    UINT8 *present;
    UINT8 *message;
    UINT16 message_size;
    UINT16 message_length;
    UINT8 prefix[2];
    UINT8 prefix_length;
} DNS_TCP_DIRECTION;

typedef struct DNS_TCP_FLOW {
    BOOL used;
    BOOL is_ipv6;
    UINT8 client_ip[16];
    UINT8 server_ip[16];
    UINT16 client_port;
    UINT16 server_port;
    UINT8 fin_mask;
    ULONGLONG tick;
    DNS_TCP_DIRECTION direction[2];
} DNS_TCP_FLOW;

// Written only by the single WinDivert packet thread. Expiration bounds outstanding
// transactions; hostname associations themselves remain tied to process lifetime.
static DNS_NETWORK_QUERY g_dns_network_queries[DNS_NETWORK_MAX_QUERIES];
static DNS_TCP_FLOW g_dns_tcp_flows[DNS_TCP_MAX_FLOWS];

#pragma pack(push, 1)
typedef struct DNS_SNAPSHOT_HEADER {
    char magic[8];
    DWORD version;
    DWORD count;
    ULONGLONG boot_estimate;
    ULONGLONG gaps;
    DWORD flags;
} DNS_SNAPSHOT_HEADER;

typedef struct DNS_SNAPSHOT_RECORD {
    DWORD pid;
    ULONGLONG process_created;
    UINT16 source_event_id;
    DWORD source_ttl_seconds;
    UINT8 has_source_ttl;
    ULONGLONG event_qpc;
    ULONGLONG consumed_qpc;
    ULONGLONG last_used_tick;
    UINT8 family;
    UINT32 ip;
    UINT8 ip6[16];
    char domain[256];
} DNS_SNAPSHOT_RECORD;
#pragma pack(pop)

#define DNS_SNAPSHOT_INCOMPLETE 1

static SRWLOCK g_process_dns_lock;
static DNS_PROCESS_ENTRY *g_dns_processes;
static DNS_HOST_ENTRY *g_process_dns_entries;
static DNS_HOST_ENTRY *g_process_dns_buckets[DNS_PROCESS_BUCKETS];
static UINT32 g_process_dns_count;
static volatile LONG64 g_process_dns_gaps;
static volatile LONG g_process_dns_initialized;
static WCHAR g_dns_snapshot_path[MAX_PATH];
static WCHAR g_dns_running_path[MAX_PATH];
static BOOL g_dns_snapshot_ready;
static volatile LONG64 g_dns_generation;
static volatile LONG64 g_dns_saved_generation;
static volatile LONG64 g_dns_dirty_tick;
static volatile LONG64 g_dns_last_snapshot_tick;
static volatile LONG64 g_dns_snapshot_failed_tick;
static BOOL g_dns_snapshot_incomplete;
static BOOL g_dns_previous_unclean;
static BOOL g_dns_tcp_reassembly_ready;

static void dns_process_discard_locked(DNS_PROCESS_ENTRY *process,
                                       DNS_PROCESS_ENTRY **retired);
static BOOL dns_process_cache_store_locked(DNS_PROCESS_ENTRY *process, BOOL is_ipv6,
                                           UINT32 ip, const UINT8 ip6[16],
                                           const char *normalized, UINT16 source_event_id,
                                           ULONGLONG event_qpc, ULONGLONG consumed_qpc,
                                           BOOL has_ttl, DWORD ttl_seconds);
static void dns_process_cache_restore_last_used(const DNS_SNAPSHOT_RECORD *record);
static BOOL dns_snapshot_prepare_paths(void);
static BOOL dns_snapshot_load(void);
static BOOL dns_snapshot_write(void);
static ULONGLONG dns_boot_estimate(void);
static void dns_snapshot_begin_session(void);
static BOOL dns_tcp_reassembly_selftest(void);

static void dns_process_mark_dirty(void)
{
    InterlockedIncrement64(&g_dns_generation);
    InterlockedExchange64(&g_dns_dirty_tick, (LONG64)GetTickCount64());
}

static void dns_process_note_gap(void)
{
    InterlockedIncrement64(&g_process_dns_gaps);
    dns_process_mark_dirty();
}

void dns_process_cache_note_gap(ULONGLONG count)
{
    if (count)
    {
        InterlockedExchangeAdd64(&g_process_dns_gaps, (LONG64)count);
        dns_process_mark_dirty();
    }
}

static BOOL dns_write_all(HANDLE file, const void *data, DWORD size)
{
    DWORD written = 0;
    return WriteFile(file, data, size, &written, NULL) && written == size;
}

static BOOL dns_read_all(HANDLE file, void *data, DWORD size)
{
    DWORD read = 0;
    return ReadFile(file, data, size, &read, NULL) && read == size;
}

static ULONGLONG dns_boot_estimate(void)
{
    FILETIME now;
    ULARGE_INTEGER value;
    GetSystemTimeAsFileTime(&now);
    value.LowPart = now.dwLowDateTime;
    value.HighPart = now.dwHighDateTime;
    return value.QuadPart - GetTickCount64() * 10000ULL;
}

static BOOL dns_snapshot_prepare_paths(void)
{
    if (g_dns_snapshot_ready) return TRUE;
    if (!g_dns_snapshot_path[0])
    {
        WCHAR program_data[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE,
                             NULL, SHGFP_TYPE_CURRENT, program_data) != S_OK)
            return FALSE;

        _snwprintf_s(g_dns_snapshot_path, _countof(g_dns_snapshot_path), _TRUNCATE,
                     L"%ls\\ProxyBridge\\hostname-cache-%ls.dat", program_data,
                     sizeof(void *) == 8 ? L"x64" : L"x86");
        _snwprintf_s(g_dns_running_path, _countof(g_dns_running_path), _TRUNCATE,
                     L"%ls\\ProxyBridge\\hostname-cache-%ls.running", program_data,
                     sizeof(void *) == 8 ? L"x64" : L"x86");
    }
    WCHAR directory[MAX_PATH];
    wcscpy_s(directory, _countof(directory), g_dns_snapshot_path);
    WCHAR *slash = wcsrchr(directory, L'\\');
    if (!slash) return FALSE;
    *slash = L'\0';

    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &sd, NULL))
        return FALSE;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    BOOL ok = CreateDirectoryW(directory, &sa) || GetLastError() == ERROR_ALREADY_EXISTS;
    if (ok)
        ok = SetFileSecurityW(directory,
             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    g_dns_snapshot_ready = ok;
    return ok;
}

static BOOL dns_snapshot_process_matches(const DNS_SNAPSHOT_RECORD *record)
{
    BOOL known = FALSE, matches = FALSE;
    AcquireSRWLockShared(&g_process_dns_lock);
    for (DNS_PROCESS_ENTRY *p = g_dns_processes; p; p = p->next)
    {
        if (p->pid == record->pid && !p->exited && WaitForSingleObject(p->process, 0) == WAIT_TIMEOUT)
        {
            ULARGE_INTEGER value;
            value.LowPart = p->created.dwLowDateTime;
            value.HighPart = p->created.dwHighDateTime;
            known = TRUE;
            matches = value.QuadPart == record->process_created;
            break;
        }
    }
    ReleaseSRWLockShared(&g_process_dns_lock);
    if (known) return matches;

    FILETIME created;
    HANDLE process = NULL;
    if (!get_process_identity(record->pid, &created, &process)) return FALSE;
    CloseHandle(process);
    ULARGE_INTEGER value;
    value.LowPart = created.dwLowDateTime;
    value.HighPart = created.dwHighDateTime;
    return value.QuadPart == record->process_created;
}

static UINT32 dns_process_bucket(DWORD pid, BOOL is_ipv6, UINT32 ip, const UINT8 ip6[16])
{
    UINT32 hash = 2166136261u ^ pid ^ (is_ipv6 ? 0x9e3779b9u : 0);
    const UINT8 *bytes = is_ipv6 ? ip6 : (const UINT8 *)&ip;
    size_t count = is_ipv6 ? 16 : sizeof(ip);
    for (size_t i = 0; i < count; i++) hash = (hash ^ bytes[i]) * 16777619u;
    return hash & (DNS_PROCESS_BUCKETS - 1);
}

static void dns_process_unlink_hash_locked(DNS_HOST_ENTRY *entry)
{
    UINT32 bucket = dns_process_bucket(entry->process->pid, entry->is_ipv6,
                                       entry->ip, entry->ip6);
    DNS_HOST_ENTRY **link = &g_process_dns_buckets[bucket];
    while (*link && *link != entry) link = &(*link)->hash_next;
    if (*link) *link = entry->hash_next;
}

static void dns_process_remove_entries_locked(DNS_PROCESS_ENTRY *process)
{
    BOOL removed = FALSE;
    DNS_HOST_ENTRY **link = &g_process_dns_entries;
    while (*link)
    {
        DNS_HOST_ENTRY *entry = *link;
        if (entry->process == process)
        {
            assert(process->count > 0 && g_process_dns_count > 0);
            dns_process_unlink_hash_locked(entry);
            *link = entry->next;
            free(entry);
            process->count--;
            g_process_dns_count--;
            removed = TRUE;
        }
        else link = &entry->next;
    }
    if (removed) dns_process_mark_dirty();
}

static VOID CALLBACK dns_process_exit_callback(PVOID context, BOOLEAN timed_out)
{
    (void)timed_out;
    DNS_PROCESS_ENTRY *process = (DNS_PROCESS_ENTRY *)context;
    DWORD pid = process->pid;
    FILETIME created = process->created;
    InterlockedExchange(&process->exited, 1);
    AcquireSRWLockExclusive(&g_process_dns_lock);
    dns_process_remove_entries_locked(process);
    ReleaseSRWLockExclusive(&g_process_dns_lock);
    remove_connections_for_process(pid, &created);
}

void dns_process_cache_init(void)
{
    if (InterlockedCompareExchange(&g_process_dns_initialized, 1, 0) == 0)
    {
        InitializeSRWLock(&g_process_dns_lock);
    }
    else dns_process_cache_clear();
    InterlockedExchange64(&g_process_dns_gaps, 0);
    InterlockedExchange64(&g_dns_generation, 0);
    InterlockedExchange64(&g_dns_saved_generation, 0);
    InterlockedExchange64(&g_dns_dirty_tick, 0);
    InterlockedExchange64(&g_dns_last_snapshot_tick, 0);
    InterlockedExchange64(&g_dns_snapshot_failed_tick, 0);
    g_dns_snapshot_incomplete = FALSE;
    dns_snapshot_load();
    g_dns_tcp_reassembly_ready = dns_tcp_reassembly_selftest();
    if (!g_dns_tcp_reassembly_ready)
    {
        dns_process_cache_note_gap(1);
        log_message("[DNS-TCP] stream reassembly self-check failed; TCP DNS observation is disabled");
    }
}

void dns_process_cache_begin_session(void)
{
    dns_snapshot_begin_session();
}

static void dns_process_dispose(DNS_PROCESS_ENTRY *process)
{
    if (process->wait)
    {
        UnregisterWaitEx(process->wait, INVALID_HANDLE_VALUE);
        process->wait = NULL;
    }
    if (process->process) CloseHandle(process->process);
    free(process);
}

void dns_process_cache_cleanup(void)
{
    DNS_PROCESS_ENTRY *retired = NULL;
    AcquireSRWLockExclusive(&g_process_dns_lock);
    for (DNS_PROCESS_ENTRY *p = g_dns_processes, *next; p; p = next)
    {
        next = p->next;
        if (p->exited || WaitForSingleObject(p->process, 0) != WAIT_TIMEOUT)
        {
            InterlockedExchange(&p->exited, 1);
            dns_process_discard_locked(p, &retired);
        }
    }
    ReleaseSRWLockExclusive(&g_process_dns_lock);
    while (retired)
    {
        DNS_PROCESS_ENTRY *next = retired->next;
        remove_connections_for_process(retired->pid, &retired->created);
        dns_process_dispose(retired);
        retired = next;
    }
}

void dns_process_cache_clear(void)
{
    AcquireSRWLockExclusive(&g_process_dns_lock);
    DNS_HOST_ENTRY *entry = g_process_dns_entries;
    while (entry)
    {
        DNS_HOST_ENTRY *next = entry->next;
        free(entry);
        entry = next;
    }
    g_process_dns_entries = NULL;
    memset(g_process_dns_buckets, 0, sizeof(g_process_dns_buckets));
    g_process_dns_count = 0;
    DNS_PROCESS_ENTRY *processes = g_dns_processes;
    g_dns_processes = NULL;
    ReleaseSRWLockExclusive(&g_process_dns_lock);

    while (processes)
    {
        DNS_PROCESS_ENTRY *next = processes->next;
        dns_process_dispose(processes);
        processes = next;
    }
}

static BOOL dns_domain_copy(char out[256], const char *domain)
{
    size_t len;
    if (!domain || (len = strlen(domain)) == 0 || len >= 256) return FALSE;
    if (domain[len - 1] == '.') len--;
    if (len == 0 || len >= 256) return FALSE;
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)domain[i];
        if (c <= 0x20 || c == 0x7f || c == ';' || c == '\\') return FALSE;
        out[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    out[len] = '\0';
    return TRUE;
}

static void dns_process_discard_locked(DNS_PROCESS_ENTRY *process,
                                       DNS_PROCESS_ENTRY **retired)
{
    DNS_PROCESS_ENTRY **link = &g_dns_processes;
    while (*link && *link != process) link = &(*link)->next;
    if (*link)
    {
        *link = process->next;
        dns_process_remove_entries_locked(process);
        process->next = *retired;
        *retired = process;
    }
}

static void dns_process_trim_locked(DNS_PROCESS_ENTRY *process)
{
    while (process->count >= DNS_PROCESS_MAX_ENTRIES ||
           g_process_dns_count >= DNS_PROCESS_MAX_TOTAL)
    {
        DNS_HOST_ENTRY **oldest_link = NULL;
        LONG64 oldest_tick = LLONG_MAX;
        for (DNS_HOST_ENTRY **link = &g_process_dns_entries; *link; link = &(*link)->next)
        {
            DNS_HOST_ENTRY *candidate = *link;
            if ((g_process_dns_count >= DNS_PROCESS_MAX_TOTAL || candidate->process == process) &&
                candidate->last_used < oldest_tick)
            {
                oldest_tick = candidate->last_used;
                oldest_link = link;
            }
        }
        if (!oldest_link) break;
        DNS_HOST_ENTRY *evicted = *oldest_link;
        *oldest_link = evicted->next;
        dns_process_unlink_hash_locked(evicted);
        evicted->process->count--;
        g_process_dns_count--;
        free(evicted);
        dns_process_note_gap();
    }
    assert(process->count < DNS_PROCESS_MAX_ENTRIES);
    assert(g_process_dns_count < DNS_PROCESS_MAX_TOTAL);
}

BOOL dns_process_cache_store(DWORD pid, const FILETIME *expected_created,
                             BOOL is_ipv6, UINT32 ip, const UINT8 ip6[16],
                             const char *domain, UINT16 source_event_id,
                             ULONGLONG event_qpc, ULONGLONG consumed_qpc,
                             BOOL has_ttl, DWORD ttl_seconds)
{
    char normalized[256];
    if (pid == 0 || (is_ipv6 && !ip6) || (!is_ipv6 && ip == 0) ||
        !dns_domain_copy(normalized, domain))
        return FALSE;

    DNS_PROCESS_ENTRY *retired = NULL;
    AcquireSRWLockExclusive(&g_process_dns_lock);
    DNS_PROCESS_ENTRY *process = NULL;
    for (DNS_PROCESS_ENTRY *p = g_dns_processes; p; p = p->next)
    {
        if (p->pid == pid && !p->exited && WaitForSingleObject(p->process, 0) == WAIT_TIMEOUT)
        {
            if (expected_created && CompareFileTime(&p->created, expected_created) != 0)
            {
                ReleaseSRWLockExclusive(&g_process_dns_lock);
                dns_process_note_gap();
                return FALSE;
            }
            process = p;
            break;
        }
    }
    if (process)
    {
        for (DNS_PROCESS_ENTRY *p = g_dns_processes, *next; p; p = next)
        {
            next = p->next;
            if (p->pid == pid && p != process)
                dns_process_discard_locked(p, &retired);
        }
        BOOL stored = dns_process_cache_store_locked(process, is_ipv6, ip, ip6,
                                                     normalized, source_event_id,
                                                     event_qpc, consumed_qpc,
                                                     has_ttl, ttl_seconds);
        if (!stored && process->count == 0)
            dns_process_discard_locked(process, &retired);
        ReleaseSRWLockExclusive(&g_process_dns_lock);
        while (retired) { DNS_PROCESS_ENTRY *next = retired->next; dns_process_dispose(retired); retired = next; }
        return stored;
    }
    ReleaseSRWLockExclusive(&g_process_dns_lock);

    FILETIME created;
    HANDLE process_handle = NULL;
    if (!get_process_identity(pid, &created, &process_handle))
    {
        dns_process_note_gap();
        return FALSE;
    }
    if (expected_created && CompareFileTime(&created, expected_created) != 0)
    {
        CloseHandle(process_handle);
        dns_process_note_gap();
        return FALSE;
    }
    DNS_PROCESS_ENTRY *candidate = (DNS_PROCESS_ENTRY *)calloc(1, sizeof(*candidate));
    if (!candidate)
    {
        CloseHandle(process_handle);
        dns_process_note_gap();
        return FALSE;
    }
    candidate->pid = pid;
    candidate->created = created;
    candidate->process = process_handle;
    if (!RegisterWaitForSingleObject(&candidate->wait, candidate->process,
                                     dns_process_exit_callback, candidate,
                                     INFINITE, WT_EXECUTEONLYONCE))
    {
        dns_process_dispose(candidate);
        dns_process_note_gap();
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_process_dns_lock);
    process = NULL;
    for (DNS_PROCESS_ENTRY *p = g_dns_processes; p; p = p->next)
    {
        if (p->pid == pid && CompareFileTime(&p->created, &created) == 0 &&
            !p->exited && WaitForSingleObject(p->process, 0) == WAIT_TIMEOUT)
        {
            process = p;
            break;
        }
    }
    if (!process && (candidate->exited || WaitForSingleObject(candidate->process, 0) != WAIT_TIMEOUT))
    {
        ReleaseSRWLockExclusive(&g_process_dns_lock);
        dns_process_dispose(candidate);
        dns_process_note_gap();
        return FALSE;
    }
    for (DNS_PROCESS_ENTRY *p = g_dns_processes, *next; p; p = next)
    {
        next = p->next;
        if (p->pid == pid && p != process)
            dns_process_discard_locked(p, &retired);
    }
    if (!process)
    {
        process = candidate;
        process->next = g_dns_processes;
        g_dns_processes = process;
        candidate = NULL;
    }
    BOOL stored = dns_process_cache_store_locked(process, is_ipv6, ip, ip6,
                                                 normalized, source_event_id,
                                                 event_qpc, consumed_qpc,
                                                 has_ttl, ttl_seconds);
    if (!stored && process->count == 0)
        dns_process_discard_locked(process, &retired);
    ReleaseSRWLockExclusive(&g_process_dns_lock);

    if (candidate) dns_process_dispose(candidate);
    while (retired) { DNS_PROCESS_ENTRY *next = retired->next; dns_process_dispose(retired); retired = next; }
    return stored;
}

static BOOL dns_process_cache_store_locked(DNS_PROCESS_ENTRY *process, BOOL is_ipv6,
                                           UINT32 ip, const UINT8 ip6[16],
                                           const char *normalized, UINT16 source_event_id,
                                           ULONGLONG event_qpc, ULONGLONG consumed_qpc,
                                           BOOL has_ttl, DWORD ttl_seconds)
{
    UINT32 bucket = dns_process_bucket(process->pid, is_ipv6, ip, ip6);
    for (DNS_HOST_ENTRY *entry = g_process_dns_buckets[bucket]; entry; entry = entry->hash_next)
    {
        BOOL same_ip = entry->is_ipv6 == is_ipv6 &&
                       (is_ipv6 ? memcmp(entry->ip6, ip6, 16) == 0 : entry->ip == ip);
        if (entry->process == process && same_ip && strcmp(entry->domain, normalized) == 0)
        {
            if (event_qpc > entry->event_qpc)
            {
                entry->event_qpc = event_qpc;
                entry->consumed_qpc = consumed_qpc;
                entry->source_event_id = source_event_id;
                entry->has_source_ttl = has_ttl;
                entry->source_ttl_seconds = ttl_seconds;
                dns_process_mark_dirty();
            }
            InterlockedExchange64(&entry->last_used, (LONG64)GetTickCount64());
            return TRUE;
        }
    }

    dns_process_trim_locked(process);
    DNS_HOST_ENTRY *entry = (DNS_HOST_ENTRY *)calloc(1, sizeof(*entry));
    if (entry)
    {
        entry->process = process;
        entry->is_ipv6 = is_ipv6;
        entry->ip = ip;
        if (is_ipv6) memcpy(entry->ip6, ip6, 16);
        strncpy_s(entry->domain, sizeof(entry->domain), normalized, _TRUNCATE);
        entry->source_event_id = source_event_id;
        entry->has_source_ttl = has_ttl;
        entry->source_ttl_seconds = ttl_seconds;
        entry->event_qpc = event_qpc;
        entry->consumed_qpc = consumed_qpc;
        entry->last_used = (LONG64)GetTickCount64();
        entry->next = g_process_dns_entries;
        g_process_dns_entries = entry;
        entry->hash_next = g_process_dns_buckets[bucket];
        g_process_dns_buckets[bucket] = entry;
        process->count++;
        g_process_dns_count++;
        assert(process->count <= DNS_PROCESS_MAX_ENTRIES);
        assert(g_process_dns_count <= DNS_PROCESS_MAX_TOTAL);
        dns_process_mark_dirty();
    }
    else dns_process_note_gap();
    return entry != NULL;
}

static BOOL dns_snapshot_load(void)
{
    if (!dns_snapshot_prepare_paths())
    {
        log_message("[DNS-CACHE] persistent cache unavailable; keeping records in memory only");
        return FALSE;
    }
    g_dns_previous_unclean = GetFileAttributesW(g_dns_running_path) != INVALID_FILE_ATTRIBUTES;
    DWORD attrs = GetFileAttributesW(g_dns_snapshot_path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            goto invalid_snapshot;
        if (g_dns_previous_unclean)
        {
            g_dns_snapshot_incomplete = TRUE;
            dns_process_note_gap();
        }
        return TRUE;
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) goto invalid_snapshot;

    HANDLE file = CreateFileW(g_dns_snapshot_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) goto invalid_snapshot;

    LARGE_INTEGER file_size;
    DNS_SNAPSHOT_HEADER header = {0};
    BOOL valid = GetFileSizeEx(file, &file_size) && file_size.QuadPart >= (LONGLONG)sizeof(header) &&
                 file_size.QuadPart <= DNS_SNAPSHOT_MAX_BYTES &&
                 dns_read_all(file, &header, sizeof(header));
    if (valid)
    {
        ULONGLONG expected = sizeof(header) + (ULONGLONG)header.count * sizeof(DNS_SNAPSHOT_RECORD);
        valid = memcmp(header.magic, "PBDNS001", 8) == 0 &&
                header.version == DNS_SNAPSHOT_VERSION &&
                header.count <= DNS_PROCESS_MAX_TOTAL && expected == (ULONGLONG)file_size.QuadPart;
        ULONGLONG current_boot = dns_boot_estimate();
        ULONGLONG boot_delta = current_boot > header.boot_estimate
                             ? current_boot - header.boot_estimate
                             : header.boot_estimate - current_boot;
        if (valid && boot_delta > 600000000ULL) valid = FALSE; // 60 seconds of UTC/boot estimate drift.
    }
    if (!valid)
    {
        CloseHandle(file);
        goto invalid_snapshot;
    }

    InterlockedExchange64(&g_process_dns_gaps, (LONG64)header.gaps);
    g_dns_snapshot_incomplete = (header.flags & DNS_SNAPSHOT_INCOMPLETE) != 0;
    for (DWORD i = 0; i < header.count; i++)
    {
        DNS_SNAPSHOT_RECORD record;
        if (!dns_read_all(file, &record, sizeof(record)) ||
            !memchr(record.domain, '\0', sizeof(record.domain)) ||
            (record.family != 4 && record.family != 6))
        {
            CloseHandle(file);
            dns_process_cache_clear();
            goto invalid_snapshot;
        }
        if (!dns_snapshot_process_matches(&record)) continue;
        FILETIME expected_created;
        ULARGE_INTEGER created;
        created.QuadPart = record.process_created;
        expected_created.dwLowDateTime = created.LowPart;
        expected_created.dwHighDateTime = created.HighPart;
        if (record.family == 4)
        {
            // The snapshot was accepted only when its boot estimate matches this boot,
            // so its QPC timestamps remain comparable to current packet timestamps.
            if (dns_process_cache_store(record.pid, &expected_created, FALSE, record.ip, NULL,
                                        record.domain, record.source_event_id,
                                        record.event_qpc, record.consumed_qpc,
                                        record.has_source_ttl, record.source_ttl_seconds))
                dns_process_cache_restore_last_used(&record);
        }
        else
        {
            if (dns_process_cache_store(record.pid, &expected_created, TRUE, 0, record.ip6,
                                        record.domain, record.source_event_id,
                                        record.event_qpc, record.consumed_qpc,
                                        record.has_source_ttl, record.source_ttl_seconds))
                dns_process_cache_restore_last_used(&record);
        }
    }
    CloseHandle(file);
    if (g_dns_previous_unclean)
    {
        g_dns_snapshot_incomplete = TRUE;
        dns_process_note_gap();
    }
    InterlockedExchange64(&g_dns_saved_generation,
                          InterlockedCompareExchange64(&g_dns_generation, 0, 0));
    InterlockedExchange64(&g_dns_dirty_tick, 0);
    InterlockedExchange64(&g_dns_last_snapshot_tick, (LONG64)GetTickCount64());
    InterlockedExchange64(&g_dns_snapshot_failed_tick, 0);
    return TRUE;

invalid_snapshot:
    g_dns_snapshot_incomplete = TRUE;
    dns_process_note_gap();
    log_message("[DNS-CACHE] snapshot rejected (corrupt, stale boot session, or inaccessible)");
    return FALSE;
}

static void dns_process_cache_restore_last_used(const DNS_SNAPSHOT_RECORD *record)
{
    BOOL is_ipv6 = record->family == 6;
    UINT32 bucket = dns_process_bucket(record->pid, is_ipv6, record->ip, record->ip6);
    ULONGLONG now = GetTickCount64();
    LONG64 last_used = record->last_used_tick && record->last_used_tick <= now
                     ? (LONG64)record->last_used_tick : (LONG64)now;
    AcquireSRWLockExclusive(&g_process_dns_lock);
    for (DNS_HOST_ENTRY *entry = g_process_dns_buckets[bucket]; entry; entry = entry->hash_next)
    {
        if (entry->process->pid == record->pid && entry->is_ipv6 == is_ipv6 &&
            (is_ipv6 ? memcmp(entry->ip6, record->ip6, 16) == 0 : entry->ip == record->ip) &&
            strcmp(entry->domain, record->domain) == 0)
        {
            InterlockedExchange64(&entry->last_used, last_used);
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_process_dns_lock);
}

static void dns_snapshot_begin_session(void)
{
    if (!dns_snapshot_prepare_paths()) return;
    struct { char magic[8]; DWORD pid; ULONGLONG boot_estimate; } marker = { 0 };
    memcpy(marker.magic, "PBRUN001", 8);
    marker.pid = GetCurrentProcessId();
    marker.boot_estimate = dns_boot_estimate();
    HANDLE file = CreateFileW(g_dns_running_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE || !dns_write_all(file, &marker, sizeof(marker)) || !FlushFileBuffers(file))
    {
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        log_message("[DNS-CACHE] could not write the running marker; crash recovery will be incomplete");
        g_dns_snapshot_incomplete = TRUE;
        return;
    }
    CloseHandle(file);
    if (g_dns_previous_unclean)
        log_message("[DNS-CACHE] recovered records came from an unclean stop and may have gaps");
}

static BOOL dns_snapshot_write(void)
{
    if (!dns_snapshot_prepare_paths()) return FALSE;
    UINT32 max_count;
    ULONGLONG generation;
    AcquireSRWLockShared(&g_process_dns_lock);
    max_count = g_process_dns_count;
    generation = (ULONGLONG)InterlockedCompareExchange64(&g_dns_generation, 0, 0);
    DNS_SNAPSHOT_RECORD *records = max_count
        ? (DNS_SNAPSHOT_RECORD *)malloc((size_t)max_count * sizeof(*records)) : NULL;
    if (max_count && !records)
    {
        ReleaseSRWLockShared(&g_process_dns_lock);
        return FALSE;
    }
    UINT32 count = 0;
    for (DNS_HOST_ENTRY *entry = g_process_dns_entries; entry && count < max_count; entry = entry->next)
    {
        DNS_PROCESS_ENTRY *process = entry->process;
        if (process->exited || WaitForSingleObject(process->process, 0) != WAIT_TIMEOUT) continue;
        DNS_SNAPSHOT_RECORD *record = &records[count++];
        ULARGE_INTEGER created;
        created.LowPart = process->created.dwLowDateTime;
        created.HighPart = process->created.dwHighDateTime;
        ZeroMemory(record, sizeof(*record));
        record->pid = process->pid;
        record->process_created = created.QuadPart;
        record->source_event_id = entry->source_event_id;
        record->has_source_ttl = entry->has_source_ttl;
        record->source_ttl_seconds = entry->source_ttl_seconds;
        record->event_qpc = entry->event_qpc;
        record->consumed_qpc = entry->consumed_qpc;
        record->last_used_tick = (ULONGLONG)entry->last_used;
        record->family = entry->is_ipv6 ? 6 : 4;
        record->ip = entry->ip;
        if (entry->is_ipv6) memcpy(record->ip6, entry->ip6, 16);
        memcpy(record->domain, entry->domain, sizeof(record->domain));
    }
    ReleaseSRWLockShared(&g_process_dns_lock);

    DNS_SNAPSHOT_HEADER header;
    memcpy(header.magic, "PBDNS001", 8);
    header.version = DNS_SNAPSHOT_VERSION;
    header.count = count;
    header.boot_estimate = dns_boot_estimate();
    header.gaps = dns_process_cache_gap_count();
    header.flags = g_dns_snapshot_incomplete ? DNS_SNAPSHOT_INCOMPLETE : 0;

    WCHAR temp_path[MAX_PATH];
    if (_snwprintf_s(temp_path, _countof(temp_path), _TRUNCATE, L"%ls.tmp", g_dns_snapshot_path) < 0)
    {
        free(records);
        return FALSE;
    }
    HANDLE file = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, NULL);
    BOOL ok = file != INVALID_HANDLE_VALUE && dns_write_all(file, &header, sizeof(header));
    for (UINT32 i = 0; ok && i < count; i++)
        ok = dns_write_all(file, &records[i], sizeof(records[i]));
    if (file != INVALID_HANDLE_VALUE)
    {
        if (ok) ok = FlushFileBuffers(file);
        CloseHandle(file);
    }
    free(records);
    if (ok) ok = MoveFileExW(temp_path, g_dns_snapshot_path,
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok)
    {
        DeleteFileW(temp_path);
        return FALSE;
    }

    InterlockedExchange64(&g_dns_last_snapshot_tick, (LONG64)GetTickCount64());
    InterlockedExchange64(&g_dns_saved_generation, (LONG64)generation);
    InterlockedExchange64(&g_dns_snapshot_failed_tick, 0);
    return TRUE;
}

BOOL dns_process_cache_snapshot_tick(BOOL final_snapshot)
{
    if (!g_dns_snapshot_ready || !g_dns_snapshot_path[0]) return FALSE;
    ULONGLONG now = GetTickCount64();
    ULONGLONG generation = (ULONGLONG)InterlockedCompareExchange64(&g_dns_generation, 0, 0);
    ULONGLONG saved = (ULONGLONG)InterlockedCompareExchange64(&g_dns_saved_generation, 0, 0);
    ULONGLONG last = (ULONGLONG)InterlockedCompareExchange64(&g_dns_last_snapshot_tick, 0, 0);
    ULONGLONG dirty = (ULONGLONG)InterlockedCompareExchange64(&g_dns_dirty_tick, 0, 0);
    ULONGLONG failed = (ULONGLONG)InterlockedCompareExchange64(&g_dns_snapshot_failed_tick, 0, 0);
    if (!final_snapshot && (generation == saved || (failed && now - failed < 5000) ||
        ((now - dirty < 1000) && (!last || now - last < 30000)))) return TRUE;

    if (dns_snapshot_write()) return TRUE;
    else
    {
        InterlockedExchange64(&g_dns_snapshot_failed_tick, (LONG64)now);
        log_message("[DNS-CACHE] snapshot write failed; current associations remain in memory");
        return FALSE;
    }
}

void dns_process_cache_end_session(void)
{
    if (!g_dns_running_path[0]) return;
    if (!dns_process_cache_snapshot_tick(TRUE))
    {
        log_message("[DNS-CACHE] final snapshot failed; retaining running marker for next-start diagnostics");
        return;
    }
    if (!DeleteFileW(g_dns_running_path) && GetLastError() != ERROR_FILE_NOT_FOUND)
        log_message("[DNS-CACHE] could not remove running marker; next start will report an incomplete recovery");
}

BOOL dns_process_cache_lookup(DWORD pid, BOOL is_ipv6, UINT32 ip, const UINT8 ip6[16],
                              ULONGLONG before_qpc, char *out_domain, size_t out_size)
{
    if (pid == 0 || (is_ipv6 && !ip6) || !out_domain || out_size == 0) return FALSE;
    DNS_HOST_ENTRY *best = NULL;
    UINT32 bucket = dns_process_bucket(pid, is_ipv6, ip, ip6);
    AcquireSRWLockShared(&g_process_dns_lock);
    for (DNS_HOST_ENTRY *entry = g_process_dns_buckets[bucket]; entry; entry = entry->hash_next)
    {
        if (entry->process->pid != pid || entry->process->exited ||
            WaitForSingleObject(entry->process->process, 0) != WAIT_TIMEOUT ||
            entry->is_ipv6 != is_ipv6 ||
            (is_ipv6 ? memcmp(entry->ip6, ip6, 16) != 0 : entry->ip != ip) ||
            (before_qpc && entry->event_qpc > before_qpc))
            continue;
        if (!best || entry->event_qpc > best->event_qpc) best = entry;
    }
    if (best)
    {
        strncpy_s(out_domain, out_size, best->domain, _TRUNCATE);
        InterlockedExchange64(&best->last_used, (LONG64)GetTickCount64());
    }
    BOOL found = best != NULL;
    ReleaseSRWLockShared(&g_process_dns_lock);
    return found;
}

ULONGLONG dns_process_cache_gap_count(void)
{
    return (ULONGLONG)InterlockedCompareExchange64(&g_process_dns_gaps, 0, 0);
}

// Parse a DNS name (with pointer compression) at msg[*offset] into dst.
// Advances *offset past the name on success.
BOOL dns_parse_name(const UINT8 *msg, int msg_len, int *offset, char *dst, int dst_len)
{
    int pos    = *offset;
    int out    = 0;
    int jumps  = 0;
    BOOL jumped      = FALSE;
    int  jumped_end  = -1;

    while (pos < msg_len)
    {
        UINT8 b = msg[pos];
        if (b == 0x00)
        {
            dst[out] = '\0';
            if (!jumped) *offset = pos + 1;
            else         *offset = jumped_end;
            return TRUE;
        }
        if ((b & 0xC0) == 0xC0)
        {
            if (pos + 1 >= msg_len) return FALSE;
            if (!jumped) jumped_end = pos + 2;
            jumped = TRUE;
            pos = ((b & 0x3F) << 8) | msg[pos + 1];
            if (++jumps > 10) return FALSE;
            continue;
        }
        int label_len = (int)b;
        pos++;
        if (pos + label_len > msg_len)       return FALSE;
        if (out + label_len + 2 >= dst_len)  return FALSE;
        if (out > 0) dst[out++] = '.';
        memcpy(&dst[out], &msg[pos], label_len);
        out  += label_len;
        pos  += label_len;
    }
    return FALSE;
}

static BOOL dns_read_question(const UINT8 *payload, int payload_len, UINT16 qdcount,
                              char qname[256], UINT16 *qtype, UINT16 *qclass,
                              int *answers_offset)
{
    int offset = 12;
    if (!qdcount) return FALSE;
    for (UINT16 i = 0; i < qdcount; i++)
    {
        char name[256];
        if (!dns_parse_name(payload, payload_len, &offset, name, sizeof(name)) ||
            offset > payload_len - 4)
            return FALSE;
        if (i == 0)
        {
            strncpy_s(qname, 256, name, _TRUNCATE);
            *qtype = ((UINT16)payload[offset] << 8) | payload[offset + 1];
            *qclass = ((UINT16)payload[offset + 2] << 8) | payload[offset + 3];
        }
        offset += 4;
    }
    *answers_offset = offset;
    return TRUE;
}

static BOOL dns_read_answer(const UINT8 *payload, int payload_len, int *offset,
                            char owner[256], UINT16 *type, UINT16 *rclass,
                            UINT16 *rdlen, DWORD *ttl_seconds, int *rdata_offset)
{
    if (!dns_parse_name(payload, payload_len, offset, owner, 256) ||
        *offset > payload_len - 10)
        return FALSE;
    *type = ((UINT16)payload[*offset] << 8) | payload[*offset + 1];
    *rclass = ((UINT16)payload[*offset + 2] << 8) | payload[*offset + 3];
    *ttl_seconds = ((DWORD)payload[*offset + 4] << 24) |
                   ((DWORD)payload[*offset + 5] << 16) |
                   ((DWORD)payload[*offset + 6] << 8) | payload[*offset + 7];
    *rdlen = ((UINT16)payload[*offset + 8] << 8) | payload[*offset + 9];
    *rdata_offset = *offset + 10;
    if (*rdata_offset > payload_len - *rdlen) return FALSE;
    *offset = *rdata_offset + *rdlen;
    return TRUE;
}

static BOOL dns_query_same(const DNS_NETWORK_QUERY *query, BOOL is_tcp, BOOL is_ipv6,
                           const UINT8 *src_ip, const UINT8 *dst_ip,
                           UINT16 src_port, UINT16 dst_port, UINT16 id,
                           UINT16 qtype, UINT16 qclass, const char *qname)
{
    size_t addr_len = is_ipv6 ? 16 : 4;
    return query->pid && query->is_tcp == is_tcp && query->is_ipv6 == is_ipv6 && query->id == id &&
           query->src_port == src_port && query->dst_port == dst_port &&
           query->qtype == qtype && query->qclass == qclass &&
           memcmp(query->src_ip, src_ip, addr_len) == 0 &&
           memcmp(query->dst_ip, dst_ip, addr_len) == 0 &&
           _stricmp(query->qname, qname) == 0;
}

static void dns_network_record_query(BOOL is_tcp, BOOL is_ipv6, const UINT8 *src_ip,
                                     const UINT8 *dst_ip, UINT16 src_port,
                                     UINT16 dst_port, const UINT8 *payload,
                                     int payload_len)
{
    if (payload_len < 12) return;
    UINT16 flags = ((UINT16)payload[2] << 8) | payload[3];
    if ((flags & 0x8000) || (flags & 0x7800) || (flags & 0x000f)) return;

    char qname[256] = {0};
    int answers_offset = 0;
    UINT16 qdcount = ((UINT16)payload[4] << 8) | payload[5];
    UINT16 qtype = 0, qclass = 0;
    if (!dns_read_question(payload, payload_len, qdcount, qname, &qtype,
                           &qclass, &answers_offset)) return;

    DWORD pid;
    if (is_ipv6)
        pid = is_tcp ? get_process_id_from_connection_v6(src_ip, src_port)
                     : get_process_id_from_udp_connection_v6(src_ip, src_port);
    else
    {
        UINT32 src_v4;
        memcpy(&src_v4, src_ip, sizeof(src_v4));
        pid = is_tcp ? get_process_id_from_connection(src_v4, src_port)
                     : get_process_id_from_udp_connection(src_v4, src_port);
    }
    if (!pid) return;

    FILETIME created;
    HANDLE process = NULL;
    if (!get_process_identity(pid, &created, &process)) return;
    BOOL alive = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    CloseHandle(process);
    if (!alive) return;

    UINT16 id = ((UINT16)payload[0] << 8) | payload[1];
    ULONGLONG now = GetTickCount64();
    int slot = -1, empty = -1, oldest = 0;
    for (int i = 0; i < DNS_NETWORK_MAX_QUERIES; i++)
    {
        DNS_NETWORK_QUERY *query = &g_dns_network_queries[i];
        if (query->pid && now - query->tick > DNS_NETWORK_QUERY_TTL_MS)
            ZeroMemory(query, sizeof(*query));
        if (query->pid && dns_query_same(query, is_tcp, is_ipv6, src_ip, dst_ip,
                                         src_port, dst_port, id, qtype, qclass, qname))
        {
            if (query->pid == pid &&
                CompareFileTime(&query->process_created, &created) == 0)
                query->tick = now; // retransmission of the same transaction
            else
            {
                query->ambiguous = TRUE; // same wire key was reused by another process instance
                query->tick = now;
            }
            return;
        }
        if (!query->pid && empty < 0) empty = i;
        if (g_dns_network_queries[i].tick < g_dns_network_queries[oldest].tick)
            oldest = i;
    }
    if (slot < 0)
    {
        if (empty >= 0) slot = empty;
        else
        {
            slot = oldest;
            dns_process_cache_note_gap(1);
        }
    }
    DNS_NETWORK_QUERY *query = &g_dns_network_queries[slot];
    ZeroMemory(query, sizeof(*query));
    query->pid = pid;
    query->process_created = created;
    query->is_ipv6 = is_ipv6;
    query->is_tcp = is_tcp;
    query->id = id;
    query->src_port = src_port;
    query->dst_port = dst_port;
    query->qtype = qtype;
    query->qclass = qclass;
    memcpy(query->src_ip, src_ip, is_ipv6 ? 16 : 4);
    memcpy(query->dst_ip, dst_ip, is_ipv6 ? 16 : 4);
    query->tick = now;
    strncpy_s(query->qname, sizeof(query->qname), qname, _TRUNCATE);
}

static void dns_network_record_response(BOOL is_tcp, BOOL is_ipv6, const UINT8 *src_ip,
                                        const UINT8 *dst_ip, UINT16 src_port,
                                        UINT16 dst_port, const UINT8 *payload,
                                        int payload_len, ULONGLONG packet_qpc)
{
    if (payload_len < 12) return;
    UINT16 flags = ((UINT16)payload[2] << 8) | payload[3];
    if (!(flags & 0x8000) || (flags & 0x7800) || (flags & 0x000f)) return;
    UINT16 qdcount = ((UINT16)payload[4] << 8) | payload[5];
    UINT16 ancount = ((UINT16)payload[6] << 8) | payload[7];
    if (!ancount || ancount > 512) return;

    char qname[256] = {0};
    int answers_offset = 0;
    UINT16 qtype = 0, qclass = 0;
    if (!dns_read_question(payload, payload_len, qdcount, qname, &qtype,
                           &qclass, &answers_offset)) return;
    UINT16 id = ((UINT16)payload[0] << 8) | payload[1];
    ULONGLONG now = GetTickCount64();
    DNS_NETWORK_QUERY matched = {0};
    for (int i = 0; i < DNS_NETWORK_MAX_QUERIES; i++)
    {
        DNS_NETWORK_QUERY *query = &g_dns_network_queries[i];
        if (query->pid && now - query->tick > DNS_NETWORK_QUERY_TTL_MS)
            ZeroMemory(query, sizeof(*query));
        size_t addr_len = is_ipv6 ? 16 : 4;
        if (query->pid && query->is_tcp == is_tcp && query->is_ipv6 == is_ipv6 && query->id == id &&
            query->src_port == dst_port && query->dst_port == src_port &&
            query->qtype == qtype && query->qclass == qclass &&
            memcmp(query->src_ip, dst_ip, addr_len) == 0 &&
            memcmp(query->dst_ip, src_ip, addr_len) == 0 &&
            _stricmp(query->qname, qname) == 0)
        {
            matched = *query;
            ZeroMemory(query, sizeof(*query));
            break;
        }
    }
    if (!matched.pid || matched.ambiguous) return;

    char aliases[17][256] = {{0}};
    strncpy_s(aliases[0], sizeof(aliases[0]), qname, _TRUNCATE);
    int alias_count = 1;
    for (int depth = 0; depth < 16; depth++)
    {
        int offset = answers_offset;
        BOOL added = FALSE;
        for (UINT16 i = 0; i < ancount; i++)
        {
            char owner[256]; UINT16 type, rclass, rdlen; DWORD ttl; int rdata;
            if (!dns_read_answer(payload, payload_len, &offset, owner, &type,
                                 &rclass, &rdlen, &ttl, &rdata)) return;
            if (type == 5 && rclass == 1 && _stricmp(owner, aliases[alias_count - 1]) == 0)
            {
                char target[256] = {0};
                int cname_offset = rdata;
                if (!dns_parse_name(payload, payload_len, &cname_offset, target, sizeof(target)) ||
                    cname_offset > rdata + rdlen || !target[0])
                    continue;
                BOOL seen = FALSE;
                for (int j = 0; j < alias_count; j++)
                    if (_stricmp(aliases[j], target) == 0) { seen = TRUE; break; }
                if (!seen)
                {
                    strncpy_s(aliases[alias_count++], sizeof(aliases[0]), target, _TRUNCATE);
                    added = TRUE;
                }
                break;
            }
        }
        if (!added) break;
    }

    int offset = answers_offset;
    LARGE_INTEGER consumed;
    QueryPerformanceCounter(&consumed);
    ULONGLONG event_qpc = packet_qpc ? packet_qpc : (ULONGLONG)consumed.QuadPart;
    for (UINT16 i = 0; i < ancount; i++)
    {
        char owner[256]; UINT16 type, rclass, rdlen; DWORD ttl; int rdata;
        if (!dns_read_answer(payload, payload_len, &offset, owner, &type,
                             &rclass, &rdlen, &ttl, &rdata)) return;
        BOOL in_chain = FALSE;
        for (int j = 0; j < alias_count; j++)
            if (_stricmp(owner, aliases[j]) == 0) { in_chain = TRUE; break; }
        if (!in_chain || rclass != 1) continue;
        if (type == 1 && rdlen == 4)
        {
            UINT32 ip;
            memcpy(&ip, &payload[rdata], sizeof(ip));
            dns_process_cache_store(matched.pid, &matched.process_created, FALSE, ip, NULL,
                                    qname, DNS_SOURCE_NETWORK_DNS, event_qpc,
                                    (ULONGLONG)consumed.QuadPart, TRUE, ttl);
        }
        else if (type == 28 && rdlen == 16)
        {
            dns_process_cache_store(matched.pid, &matched.process_created, TRUE, 0,
                                    &payload[rdata], qname, DNS_SOURCE_NETWORK_DNS,
                                    event_qpc, (ULONGLONG)consumed.QuadPart, TRUE, ttl);
        }
    }
}

typedef void (*DNS_TCP_BYTE_CALLBACK)(void *context, UINT8 value);

static void dns_tcp_direction_free(DNS_TCP_DIRECTION *direction)
{
    free(direction->window);
    free(direction->present);
    free(direction->message);
    ZeroMemory(direction, sizeof(*direction));
}

static void dns_tcp_direction_reset(DNS_TCP_DIRECTION *direction)
{
    if (direction->window) ZeroMemory(direction->window, DNS_TCP_WINDOW_SIZE);
    if (direction->present) ZeroMemory(direction->present, DNS_TCP_BITMAP_SIZE);
    direction->initialized = FALSE;
    direction->next_seq = 0;
    direction->ring_head = 0;
    direction->pending_bytes = 0;
    direction->message_size = 0;
    direction->message_length = 0;
    direction->prefix_length = 0;
}

static BOOL dns_tcp_direction_prepare(DNS_TCP_DIRECTION *direction)
{
    if (!direction->window) direction->window = (UINT8 *)malloc(DNS_TCP_WINDOW_SIZE);
    if (!direction->present) direction->present = (UINT8 *)calloc(DNS_TCP_BITMAP_SIZE, 1);
    if (!direction->message) direction->message = (UINT8 *)malloc(DNS_TCP_MESSAGE_MAX);
    if (direction->window && direction->present && direction->message) return TRUE;
    dns_tcp_direction_free(direction);
    return FALSE;
}

static BOOL dns_tcp_bit_is_set(const UINT8 *bitmap, UINT32 bit)
{
    return (bitmap[bit >> 3] & (UINT8)(1u << (bit & 7))) != 0;
}

static void dns_tcp_bit_set(UINT8 *bitmap, UINT32 bit)
{
    bitmap[bit >> 3] |= (UINT8)(1u << (bit & 7));
}

static void dns_tcp_bit_clear(UINT8 *bitmap, UINT32 bit)
{
    bitmap[bit >> 3] &= (UINT8)~(1u << (bit & 7));
}

static BOOL dns_tcp_reassemble(DNS_TCP_DIRECTION *direction, UINT32 seq, BOOL syn,
                               const UINT8 *payload, int payload_len,
                               DNS_TCP_BYTE_CALLBACK consume, void *context)
{
    if (syn)
    {
        if (!direction->initialized)
        {
            direction->next_seq = seq + 1;
            direction->initialized = TRUE;
        }
        seq++;
    }
    else if (!direction->initialized)
    {
        direction->next_seq = seq;
        direction->initialized = TRUE;
    }
    if (!payload || payload_len <= 0) return TRUE;
    if (!dns_tcp_direction_prepare(direction)) return FALSE;

    INT32 delta = (INT32)(seq - direction->next_seq);
    if (delta < 0)
    {
        UINT32 overlap = direction->next_seq - seq;
        if (overlap >= (UINT32)payload_len) return TRUE;
        seq += overlap;
        payload += overlap;
        payload_len -= (int)overlap;
        delta = 0;
    }
    if ((UINT32)delta >= DNS_TCP_WINDOW_SIZE ||
        (UINT32)payload_len > DNS_TCP_WINDOW_SIZE - (UINT32)delta)
    {
        dns_process_cache_note_gap(1);
        dns_tcp_direction_reset(direction);
        direction->initialized = TRUE;
        direction->next_seq = seq;
        if ((UINT32)payload_len > DNS_TCP_WINDOW_SIZE) return FALSE;
        delta = 0;
    }

    for (int i = 0; i < payload_len; i++)
    {
        UINT32 slot = (direction->ring_head + (UINT32)delta + (UINT32)i) &
                      (DNS_TCP_WINDOW_SIZE - 1);
        if (!dns_tcp_bit_is_set(direction->present, slot))
        {
            direction->window[slot] = payload[i];
            dns_tcp_bit_set(direction->present, slot);
            direction->pending_bytes++;
        }
    }

    while (dns_tcp_bit_is_set(direction->present, direction->ring_head))
    {
        UINT8 value = direction->window[direction->ring_head];
        dns_tcp_bit_clear(direction->present, direction->ring_head);
        direction->ring_head = (direction->ring_head + 1) & (DNS_TCP_WINDOW_SIZE - 1);
        direction->pending_bytes--;
        direction->next_seq++;
        consume(context, value);
    }
    return TRUE;
}

typedef struct DNS_TCP_PARSE_CONTEXT {
    DNS_TCP_FLOW *flow;
    int direction;
    ULONGLONG packet_qpc;
} DNS_TCP_PARSE_CONTEXT;

static void dns_tcp_consume_dns_byte(void *opaque, UINT8 value)
{
    DNS_TCP_PARSE_CONTEXT *context = (DNS_TCP_PARSE_CONTEXT *)opaque;
    DNS_TCP_DIRECTION *direction = &context->flow->direction[context->direction];
    if (direction->prefix_length < 2)
    {
        direction->prefix[direction->prefix_length++] = value;
        if (direction->prefix_length == 2)
        {
            direction->message_size = ((UINT16)direction->prefix[0] << 8) |
                                     direction->prefix[1];
            if (direction->message_size < 12)
            {
                direction->prefix_length = 0;
                direction->message_size = 0;
                dns_process_cache_note_gap(1);
            }
        }
        return;
    }

    direction->message[direction->message_length++] = value;
    if (direction->message_length != direction->message_size) return;

    if (context->direction == 0)
        dns_network_record_query(TRUE, context->flow->is_ipv6,
                                 context->flow->client_ip, context->flow->server_ip,
                                 context->flow->client_port, context->flow->server_port,
                                 direction->message, direction->message_length);
    else
        dns_network_record_response(TRUE, context->flow->is_ipv6,
                                   context->flow->server_ip, context->flow->client_ip,
                                   context->flow->server_port, context->flow->client_port,
                                   direction->message, direction->message_length,
                                   context->packet_qpc);

    direction->prefix_length = 0;
    direction->message_size = 0;
    direction->message_length = 0;
}

static BOOL dns_tcp_flow_incomplete(const DNS_TCP_FLOW *flow)
{
    for (int i = 0; i < 2; i++)
    {
        const DNS_TCP_DIRECTION *direction = &flow->direction[i];
        if (direction->pending_bytes || direction->prefix_length || direction->message_length)
            return TRUE;
    }
    return FALSE;
}

static void dns_tcp_flow_free(DNS_TCP_FLOW *flow)
{
    dns_tcp_direction_free(&flow->direction[0]);
    dns_tcp_direction_free(&flow->direction[1]);
    ZeroMemory(flow, sizeof(*flow));
}

static BOOL dns_tcp_flow_matches(const DNS_TCP_FLOW *flow, BOOL is_ipv6,
                                 const UINT8 *client_ip, const UINT8 *server_ip,
                                 UINT16 client_port, UINT16 server_port)
{
    size_t ip_len = is_ipv6 ? 16 : 4;
    return flow->used && flow->is_ipv6 == is_ipv6 &&
           flow->client_port == client_port && flow->server_port == server_port &&
           memcmp(flow->client_ip, client_ip, ip_len) == 0 &&
           memcmp(flow->server_ip, server_ip, ip_len) == 0;
}

static DNS_TCP_FLOW *dns_tcp_flow_get(BOOL is_ipv6, const UINT8 *src_ip,
                                      const UINT8 *dst_ip, UINT16 src_port,
                                      UINT16 dst_port, BOOL create)
{
    if ((src_port == 53) == (dst_port == 53)) return NULL;
    BOOL server_to_client = src_port == 53;
    const UINT8 *client_ip = server_to_client ? dst_ip : src_ip;
    const UINT8 *server_ip = server_to_client ? src_ip : dst_ip;
    UINT16 client_port = server_to_client ? dst_port : src_port;
    UINT16 server_port = server_to_client ? src_port : dst_port;
    ULONGLONG now = GetTickCount64();
    int empty = -1, oldest = 0;

    for (int i = 0; i < DNS_TCP_MAX_FLOWS; i++)
    {
        DNS_TCP_FLOW *flow = &g_dns_tcp_flows[i];
        if (flow->used && now - flow->tick > DNS_TCP_FLOW_TTL_MS)
        {
            if (dns_tcp_flow_incomplete(flow)) dns_process_cache_note_gap(1);
            dns_tcp_flow_free(flow);
        }
        if (dns_tcp_flow_matches(flow, is_ipv6, client_ip, server_ip,
                                 client_port, server_port))
        {
            flow->tick = now;
            return flow;
        }
        if (!flow->used && empty < 0) empty = i;
        if (g_dns_tcp_flows[i].tick < g_dns_tcp_flows[oldest].tick) oldest = i;
    }
    if (!create) return NULL;

    int slot = empty;
    if (slot < 0)
    {
        slot = oldest;
        if (dns_tcp_flow_incomplete(&g_dns_tcp_flows[slot]))
            dns_process_cache_note_gap(1);
        dns_tcp_flow_free(&g_dns_tcp_flows[slot]);
        dns_process_cache_note_gap(1);
    }
    DNS_TCP_FLOW *flow = &g_dns_tcp_flows[slot];
    ZeroMemory(flow, sizeof(*flow));
    flow->used = TRUE;
    flow->is_ipv6 = is_ipv6;
    memcpy(flow->client_ip, client_ip, is_ipv6 ? 16 : 4);
    memcpy(flow->server_ip, server_ip, is_ipv6 ? 16 : 4);
    flow->client_port = client_port;
    flow->server_port = server_port;
    flow->tick = now;
    return flow;
}

void dns_network_observe_tcp(BOOL is_ipv6, const UINT8 *src_ip,
                             const UINT8 *dst_ip, UINT16 src_port, UINT16 dst_port,
                             UINT32 seq, UINT8 flags, const UINT8 *payload,
                             int payload_len, ULONGLONG packet_qpc)
{
    if (!g_dns_tcp_reassembly_ready || !src_ip || !dst_ip ||
        ((src_port == 53) == (dst_port == 53))) return;

    DNS_TCP_FLOW *flow = dns_tcp_flow_get(is_ipv6, src_ip, dst_ip,
                                          src_port, dst_port, TRUE);
    if (!flow) return;
    BOOL server_to_client = src_port == 53;
    int direction_index = server_to_client ? 1 : 0;
    BOOL syn = (flags & 0x02) != 0;
    BOOL ack = (flags & 0x10) != 0;
    BOOL reset = (flags & 0x04) != 0;
    BOOL fin = (flags & 0x01) != 0;

    if (syn && !ack)
    {
        if (dns_tcp_flow_incomplete(flow)) dns_process_cache_note_gap(1);
        flow->fin_mask = 0;
        dns_tcp_direction_reset(&flow->direction[1 - direction_index]);
        dns_tcp_direction_reset(&flow->direction[direction_index]);
        flow->direction[direction_index].initialized = TRUE;
        flow->direction[direction_index].next_seq = seq + 1;
    }
    DNS_TCP_PARSE_CONTEXT context = { flow, direction_index, packet_qpc };
    if (!dns_tcp_reassemble(&flow->direction[direction_index], seq, syn,
                            payload, payload_len, dns_tcp_consume_dns_byte, &context))
    {
        dns_process_cache_note_gap(1);
        dns_tcp_direction_reset(&flow->direction[direction_index]);
    }
    if (fin) flow->fin_mask |= (UINT8)(1u << direction_index);
    if (reset)
    {
        if (dns_tcp_flow_incomplete(flow)) dns_process_cache_note_gap(1);
        dns_tcp_flow_free(flow);
    }
    else if (flow->fin_mask == 3)
    {
        if (dns_tcp_flow_incomplete(flow)) dns_process_cache_note_gap(1);
        dns_tcp_flow_free(flow);
    }
}

typedef struct DNS_TCP_SELFTEST_OUTPUT {
    UINT8 bytes[6];
    UINT32 count;
} DNS_TCP_SELFTEST_OUTPUT;

static void dns_tcp_selftest_collect(void *opaque, UINT8 value)
{
    DNS_TCP_SELFTEST_OUTPUT *output = (DNS_TCP_SELFTEST_OUTPUT *)opaque;
    if (output->count < _countof(output->bytes)) output->bytes[output->count++] = value;
}

static BOOL dns_tcp_reassembly_selftest(void)
{
    static const UINT8 first[] = { 0, 12 };
    static const UINT8 last[] = { 3, 4 };
    static const UINT8 middle[] = { 1, 2 };
    static const UINT8 expected[] = { 0, 12, 1, 2, 3, 4 };
    DNS_TCP_DIRECTION direction = {0};
    DNS_TCP_SELFTEST_OUTPUT output = {0};
    BOOL ok = dns_tcp_reassemble(&direction, 100, FALSE, first, sizeof(first),
                                 dns_tcp_selftest_collect, &output) &&
              dns_tcp_reassemble(&direction, 104, FALSE, last, sizeof(last),
                                 dns_tcp_selftest_collect, &output) &&
              dns_tcp_reassemble(&direction, 102, FALSE, middle, sizeof(middle),
                                 dns_tcp_selftest_collect, &output) &&
              output.count == _countof(expected) &&
              memcmp(output.bytes, expected, sizeof(expected)) == 0;
    dns_tcp_direction_free(&direction);
    return ok;
}

void dns_network_observe_udp(BOOL outbound, BOOL is_ipv6, const UINT8 *src_ip,
                             const UINT8 *dst_ip, UINT16 src_port, UINT16 dst_port,
                             const UINT8 *payload, int payload_len, ULONGLONG packet_qpc)
{
    if (!src_ip || !dst_ip || !payload || payload_len < 12 ||
        ((src_port == 53) == (dst_port == 53))) return;
    if (outbound)
        dns_network_record_query(FALSE, is_ipv6, src_ip, dst_ip, src_port, dst_port,
                                 payload, payload_len);
    else
        dns_network_record_response(FALSE, is_ipv6, src_ip, dst_ip, src_port, dst_port,
                                    payload, payload_len, packet_qpc);
}

void dns_network_query_reset(void)
{
    ZeroMemory(g_dns_network_queries, sizeof(g_dns_network_queries));
    for (int i = 0; i < DNS_TCP_MAX_FLOWS; i++)
        dns_tcp_flow_free(&g_dns_tcp_flows[i]);
}

