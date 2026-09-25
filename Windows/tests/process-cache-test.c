#include "pb_internal.h"
typedef struct { const WCHAR *name; BOOL exited; } OBJECT;
static OBJECT old_object = {L"old.exe", FALSE}, new_object = {L"new.exe", FALSE};
static OBJECT *current = &old_object;
static unsigned opens, queries;
static int handles, names;
static BOOL deny_sync, deny_all, fail_query, fail_wait, fail_alloc, clear_during_query;
static HANDLE test_open(DWORD access, BOOL inherit, DWORD pid) {
    (void)inherit; (void)pid; ++opens;
    if (deny_all || (deny_sync && (access & SYNCHRONIZE))) return NULL;
    ++handles; return current;
}
static BOOL test_close(HANDLE handle) { (void)handle; --handles; return TRUE; }
static DWORD test_wait(HANDLE handle, DWORD timeout) {
    (void)timeout; if (fail_wait) return WAIT_FAILED;
    return ((OBJECT *)handle)->exited ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
}
static BOOL test_query(HANDLE handle, DWORD flags, WCHAR *out, DWORD *size) {
    (void)flags; ++queries;
    if (clear_during_query) { clear_during_query = FALSE; pb_process_cache_clear(); }
    if (fail_query) return FALSE;
    wcscpy_s(out, *size, ((OBJECT *)handle)->name); *size = (DWORD)wcslen(out); return TRUE;
}
static void *test_malloc(size_t size) { if (fail_alloc) return NULL; void *p = malloc(size); if (p) ++names; return p; }
static void test_free(void *p) { if (p) --names; free(p); }
#define OpenProcess test_open
#define CloseHandle test_close
#define WaitForSingleObject test_wait
#define QueryFullProcessImageNameW test_query
#define malloc test_malloc
#define free test_free
#include "../src/net/pb_process_cache.inc"
#undef OpenProcess
#undef CloseHandle
#undef WaitForSingleObject
#undef QueryFullProcessImageNameW
#undef malloc
#undef free
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d handles=%d names=%d\n", __LINE__, handles, names); return 1; } } while (0)
int main(void)
{
    char out[1024];
    CHECK(!get_process_name_from_pid(0, out, sizeof(out)));
    CHECK(get_process_name_from_pid(4, out, sizeof(out)) && !strcmp(out, "System") && opens == 0);
    CHECK(get_process_name_from_pid(100, out, sizeof(out)) && !strcmp(out, "old.exe"));
    CHECK(get_process_name_from_pid(100, out, sizeof(out)) && opens == 1 && queries == 1);
    CHECK(!get_process_name_from_pid(100, out, 2) && GetLastError() == ERROR_INSUFFICIENT_BUFFER);
    old_object.exited = TRUE; current = &new_object;
    CHECK(get_process_name_from_pid(100, out, sizeof(out)) && !strcmp(out, "new.exe") && handles == 1);
    fail_wait = TRUE;
    CHECK(get_process_name_from_pid(100, out, sizeof(out)) && handles == 0 && names == 0);
    fail_wait = FALSE; deny_sync = TRUE;
    unsigned before = opens;
    CHECK(get_process_name_from_pid(100, out, sizeof(out)) && opens == before + 2 && handles == 0);
    deny_sync = FALSE; fail_query = TRUE;
    CHECK(!get_process_name_from_pid(100, out, sizeof(out)) && handles == 0);
    fail_query = FALSE; fail_alloc = TRUE;
    CHECK(get_process_name_from_pid(100, out, sizeof(out)) && handles == 0 && names == 0);
    fail_alloc = FALSE; clear_during_query = TRUE;
    CHECK(get_process_name_from_pid(100, out, sizeof(out)) && handles == 0 && names == 0);
    deny_all = TRUE; CHECK(!get_process_name_from_pid(100, out, sizeof(out))); deny_all = FALSE;
    for (DWORD pid = 8; pid < 4096; pid += 4) CHECK(get_process_name_from_pid(pid, out, sizeof(out)));
    CHECK(handles <= PB_PROCESS_CACHE_SIZE && names == handles);
    pb_process_cache_clear(); CHECK(handles == 0 && names == 0);
    CHECK(get_process_name_from_pid(100, out, sizeof(out)));
    pb_process_cache_dispose(); CHECK(handles == 0 && names == 0);
    puts("PASS: live hit, replaced PID object, wait/query/access failures, fallback, OOM, clear epoch, bounds and cleanup");
    return 0;
}
