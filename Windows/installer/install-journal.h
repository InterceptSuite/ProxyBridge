#pragma once
#include <windows.h>

// One REG_BINARY value is the commit unit. The coordinator owns the global
// installation mutex for the entire transaction, including reads and writes.
// The key must be opened in the 64-bit registry view with administrator-only
// write access; never accept a journal key or recovery path from an unelevated UI.
#define PB_JOURNAL_VERSION 6u
typedef enum PB_INSTALL_PHASE {
    PB_INSTALL_PREPARED = 1,
    PB_INSTALL_DRIVER_CHANGING,
    PB_INSTALL_DRIVER_PENDING,
    PB_INSTALL_DRIVER_VERIFIED,
    PB_INSTALL_APP_CHANGING,
    PB_INSTALL_COMMITTED,
    PB_INSTALL_ROLLING_BACK,
    PB_INSTALL_ROLLBACK_PENDING,
    PB_INSTALL_ROLLED_BACK,
    PB_INSTALL_RECOVERY_REQUIRED,
    PB_INSTALL_REMOVING,
    PB_INSTALL_REMOVE_PENDING,
    PB_INSTALL_REMOVED,
    PB_INSTALL_CLEANING,
    PB_INSTALL_CLEANED,
    // Separate states: the single-folder route must never enter old rollback.
    PB_INSTALL_FLAT_COPYING,
    PB_INSTALL_FLAT_DRIVER,
    PB_INSTALL_FLAT_PENDING,
    PB_INSTALL_FLAT_REGISTERING,
    PB_INSTALL_FLAT_REMOVING,
    PB_INSTALL_FLAT_REMOVED
} PB_INSTALL_PHASE;

typedef struct PB_INSTALL_JOURNAL {
    DWORD size;
    DWORD version;
    GUID transaction;
    DWORD phase;
    DWORD lastError;
    DWORD targetProtocol;
    DWORD targetDriverVersion;
    DWORD previousProtocol;
    DWORD previousDriverVersion;
    DWORD deviceExisted;
    WCHAR deviceInstance[200];
    BYTE targetManifestHash[32];
    BYTE previousManifestHash[32];
    WCHAR targetDirectory[MAX_PATH];
    WCHAR previousDirectory[MAX_PATH];
    WCHAR previousInf[MAX_PATH];
    WCHAR removalInf[MAX_PATH];
} PB_INSTALL_JOURNAL;

BOOL pb_journal_transition_allowed(DWORD from, DWORD to);
BOOL pb_journal_blocks_launch(DWORD phase);
DWORD pb_journal_validate(const PB_INSTALL_JOURNAL *record);
DWORD pb_journal_read(HKEY key, PB_INSTALL_JOURNAL *record);
DWORD pb_journal_begin(HKEY key, const PB_INSTALL_JOURNAL *record);
DWORD pb_journal_begin_remove(HKEY key, PB_INSTALL_JOURNAL *record, const WCHAR *inf);
DWORD pb_journal_advance(HKEY key, PB_INSTALL_JOURNAL *record,
                         DWORD nextPhase, DWORD error);
// Single-folder coordinator only: caller holds both lifecycle locks, validates
// fixed-root identity and all external input. expected==NULL requires absence.
DWORD pb_journal_replace_flat(HKEY key, const PB_INSTALL_JOURNAL *expected,
                              const PB_INSTALL_JOURNAL *next);
