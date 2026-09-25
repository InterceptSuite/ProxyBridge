#include "../startup-installed.h"
#include "../install-journal.h"
#include <stdio.h>
static DWORD phase, readError, schedulerError;
static unsigned reads, writes;
static DWORD read_transaction(PB_INSTALL_JOURNAL *out) { ++reads; out->phase=phase; return readError; }
DWORD pb_startup_installed(PB_STARTUP_OPERATION operation, BOOL *enabled) {
    (void)operation; ++writes; *enabled=TRUE; return schedulerError;
}
#include "../startup-recorded.inc"
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d phase=%lu: %s\n",__LINE__,phase,#x); return 1; } } while(0)
int main(void) {
    unsigned cases=0;
    for(phase=PB_INSTALL_PREPARED;phase<=PB_INSTALL_CLEANED;++phase)
    for(int op=PB_STARTUP_QUERY;op<=PB_STARTUP_REMOVE;++op)
    for(unsigned fail=0;fail<3;++fail) {
        readError=fail==1 ? ERROR_INVALID_DATA : 0;
        schedulerError=fail==2 ? ERROR_ACCESS_DENIED : 0;
        reads=writes=0; BOOL enabled=FALSE;
        DWORD error=startup_recorded((PB_STARTUP_OPERATION)op,&enabled);
        BOOL needsRead=op==PB_STARTUP_ENABLE || op==PB_STARTUP_RETARGET || op==PB_STARTUP_REMOVE;
        CHECK(reads==(unsigned)needsRead);
        if(needsRead && readError) CHECK(error==readError && !writes);
        else {
            BOOL allowed=TRUE;
            if(op==PB_STARTUP_REMOVE) allowed=phase==PB_INSTALL_REMOVED || phase==PB_INSTALL_CLEANED;
            if(op==PB_STARTUP_ENABLE) allowed=phase==PB_INSTALL_COMMITTED || phase==PB_INSTALL_ROLLED_BACK;
            if(op==PB_STARTUP_RETARGET) allowed=phase==PB_INSTALL_COMMITTED || phase==PB_INSTALL_ROLLED_BACK ||
                phase==PB_INSTALL_DRIVER_PENDING || phase==PB_INSTALL_ROLLBACK_PENDING;
            CHECK(writes==(unsigned)allowed);
            CHECK(error==(allowed ? schedulerError : ERROR_INSTALL_SUSPEND));
            if(!allowed) CHECK(!enabled);
        }
        ++cases;
    }
    // Delayed old uninstaller, after a new transaction has already started.
    phase=PB_INSTALL_PREPARED; readError=schedulerError=0; writes=0; BOOL enabled;
    CHECK(startup_recorded(PB_STARTUP_REMOVE,&enabled)==ERROR_INSTALL_SUSPEND && !writes);
    phase=PB_INSTALL_COMMITTED;
    CHECK(startup_recorded(PB_STARTUP_REMOVE,&enabled)==ERROR_INSTALL_SUSPEND && !writes);
    CHECK(startup_recorded(PB_STARTUP_QUERY,NULL)==ERROR_INVALID_PARAMETER);
    printf("PASS %u startup journal/operation/error cases; stale removal rejected before scheduler call\n",cases);
    return 0;
}
