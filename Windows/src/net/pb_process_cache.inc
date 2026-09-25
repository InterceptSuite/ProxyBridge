#define PB_PROCESS_CACHE_SIZE 128
typedef struct {
    DWORD pid;
    HANDLE process;
    char *name;
    size_t bytes;
} PB_PROCESS_CACHE_ENTRY;
static PB_PROCESS_CACHE_ENTRY process_cache[PB_PROCESS_CACHE_SIZE];
static SRWLOCK process_cache_lock = SRWLOCK_INIT;
static UINT64 process_cache_epoch;

static unsigned process_cache_bucket(DWORD pid)
{
    UINT32 hash = pid;
    hash ^= hash >> 16; hash *= 0x7feb352du; hash ^= hash >> 15;
    return hash & (PB_PROCESS_CACHE_SIZE - 1);
}
static void process_cache_remove(PB_PROCESS_CACHE_ENTRY *entry)
{
    if (entry->process != NULL) CloseHandle(entry->process);
    free(entry->name);
    memset(entry, 0, sizeof(*entry));
}
// Only with readers quiescent; also used for explicit DLL unload without locks.
void pb_process_cache_dispose(void)
{
    ++process_cache_epoch;
    for (unsigned i = 0; i < PB_PROCESS_CACHE_SIZE; ++i) process_cache_remove(&process_cache[i]);
}
void pb_process_cache_clear(void)
{
    AcquireSRWLockExclusive(&process_cache_lock);
    pb_process_cache_dispose();
    ReleaseSRWLockExclusive(&process_cache_lock);
}
static BOOL process_copy_name(char *out, DWORD capacity, const char *name, size_t bytes)
{
    if (bytes > capacity) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(out, name, bytes);
    return TRUE;
}
BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size)
{
    if (pid == 0 || name == NULL || name_size == 0) return FALSE;
    if (pid == 4) { strncpy_s(name, name_size, "System", _TRUNCATE); return TRUE; }
    unsigned bucket = process_cache_bucket(pid);
    AcquireSRWLockShared(&process_cache_lock);
    UINT64 epoch = process_cache_epoch;
    PB_PROCESS_CACHE_ENTRY *entry = &process_cache[bucket];
    if (entry->process != NULL && entry->pid == pid && WaitForSingleObject(entry->process, 0) == WAIT_TIMEOUT) {
        BOOL ok = process_copy_name(name, name_size, entry->name, entry->bytes);
        ReleaseSRWLockShared(&process_cache_lock);
        return ok;
    }
    ReleaseSRWLockShared(&process_cache_lock);
    AcquireSRWLockExclusive(&process_cache_lock);
    if (entry->process != NULL && entry->pid == pid && WaitForSingleObject(entry->process, 0) != WAIT_TIMEOUT)
        process_cache_remove(entry);
    ReleaseSRWLockExclusive(&process_cache_lock);

    BOOL cacheable = TRUE;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (process == NULL) {
        cacheable = FALSE;
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }
    if (process == NULL) return FALSE;
    WCHAR wide[MAX_PATH];
    DWORD length = MAX_PATH;
    char utf8[4 * MAX_PATH];
    int bytes = 0;
    if (QueryFullProcessImageNameW(process, 0, wide, &length))
        bytes = WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, sizeof(utf8), NULL, NULL);
    BOOL ok = bytes > 0 && process_copy_name(name, name_size, utf8, (size_t)bytes);
    if (ok && cacheable && WaitForSingleObject(process, 0) == WAIT_TIMEOUT) {
        char *copy = malloc((size_t)bytes);
        if (copy != NULL) {
            memcpy(copy, utf8, (size_t)bytes);
            AcquireSRWLockExclusive(&process_cache_lock);
            if (epoch == process_cache_epoch) {
                process_cache_remove(entry);
                entry->pid = pid; entry->process = process; entry->name = copy; entry->bytes = (size_t)bytes;
                process = NULL; copy = NULL;
            }
            ReleaseSRWLockExclusive(&process_cache_lock);
            free(copy);
        }
    }
    if (process != NULL) CloseHandle(process);
    return ok;
}
