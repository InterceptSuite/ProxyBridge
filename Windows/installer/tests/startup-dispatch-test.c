#include "../startup-task.h"
#include <stdio.h>
#include <wchar.h>
typedef struct Fixture {
    PB_STARTUP_SNAPSHOT state;
    DWORD readError, writeError;
    unsigned reads, writes;
    BOOL create;
    PB_STARTUP_OPERATION operation;
} Fixture;
static DWORD read_state(void *ctx, PB_STARTUP_SNAPSHOT *out) {
    Fixture *f = ctx; ++f->reads; *out = f->state; return f->readError;
}
static DWORD write_state(void *ctx, PB_STARTUP_OPERATION op, BOOL create, const WCHAR *launcher) {
    Fixture *f = ctx; (void)launcher;
    ++f->writes; f->create = create; f->operation = op;
    return f->writeError;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
    const WCHAR *root = L"C:\\ProgramData";
    const WCHAR *path = L"C:\\ProgramData\\InterceptSuite.ProxyBridge\\bootstrap\\0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\ProxyBridgeLauncher.exe";
    unsigned cases = 0;
    for (int op = PB_STARTUP_QUERY; op <= PB_STARTUP_REMOVE; ++op)
    for (unsigned flags = 0; flags < 8; ++flags)
    for (unsigned failure = 0; failure < 4; ++failure) {
        Fixture f = {0}; BOOL enabled = TRUE;
        f.state.exists = !!(flags & 1); f.state.owned = !!(flags & 2); f.state.enabled = !!(flags & 4);
        if (failure == 1) f.readError = ERROR_INVALID_DATA;
        if (failure == 2) f.writeError = ERROR_WRITE_FAULT;
        if (failure == 3) f.writeError = 0x0004131b; // SCHED_S_SOME_TRIGGERS_FAILED
        PB_STARTUP_BACKEND backend = {&f, read_state, write_state};
        DWORD result = pb_startup_dispatch(&backend, (PB_STARTUP_OPERATION)op, root, path, &enabled);
        CHECK(f.reads == 1);
        if (failure == 1) { CHECK(result == ERROR_INVALID_DATA && f.writes == 0 && !enabled); }
        else if (f.state.exists && !f.state.owned) { CHECK(result == ERROR_ACCESS_DENIED && f.writes == 0 && !enabled); }
        else {
            BOOL write = op != PB_STARTUP_QUERY && (f.state.exists || op == PB_STARTUP_ENABLE);
            CHECK(f.writes == (unsigned)write);
            CHECK(result == (write ? f.writeError : 0));
            if (write) CHECK(f.create == !f.state.exists && f.operation == op);
            BOOL expected = f.state.exists && f.state.enabled;
            if (write && !f.writeError) {
                if (op == PB_STARTUP_ENABLE) expected = TRUE;
                if (op == PB_STARTUP_DISABLE || op == PB_STARTUP_REMOVE) expected = FALSE;
            }
            CHECK(enabled == expected);
        }
        ++cases;
    }
    Fixture f = {0}; BOOL enabled;
    f.state.exists = f.state.owned = TRUE;
    PB_STARTUP_BACKEND backend = {&f, read_state, write_state};
    CHECK(pb_startup_dispatch(&backend, PB_STARTUP_RETARGET, root, L"C:\\foreign.exe", &enabled) == ERROR_INVALID_NAME);
    CHECK(f.writes == 0);
    CHECK(pb_startup_dispatch(&backend, PB_STARTUP_ENABLE, root, NULL, &enabled) == ERROR_INVALID_NAME);
    CHECK(f.writes == 0);
    CHECK(pb_startup_dispatch(NULL, PB_STARTUP_QUERY, root, path, &enabled) == ERROR_INVALID_PARAMETER);
    CHECK(pb_startup_dispatch(&backend, (PB_STARTUP_OPERATION)99, root, path, &enabled) == ERROR_INVALID_PARAMETER);
    CHECK(pb_startup_dispatch(&backend, PB_STARTUP_QUERY, root, path, NULL) == ERROR_INVALID_PARAMETER);
    printf("PASS %u startup dispatch cases plus invalid target/API inputs; no Windows task operations\n", cases);
    return 0;
}
