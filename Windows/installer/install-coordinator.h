#pragma once
#include "install-journal.h"

// Callers hold the installation mutex throughout and provide callbacks which
// validate recorded identities, never paths supplied by the launching process.
// Verification callbacks are read-only. ERROR_SUCCESS_REBOOT_REQUIRED means
// verification cannot yet complete; it must never be treated as verified.
typedef struct PB_INSTALL_OPERATIONS {
    void *context;
    DWORD (*validate)(void *, const PB_INSTALL_JOURNAL *);
    DWORD (*installDriver)(void *, const PB_INSTALL_JOURNAL *);
    DWORD (*verifyDriver)(void *, const PB_INSTALL_JOURNAL *);
    DWORD (*publishApp)(void *, const PB_INSTALL_JOURNAL *);
    DWORD (*verifyPair)(void *, const PB_INSTALL_JOURNAL *);
    DWORD (*restorePair)(void *, const PB_INSTALL_JOURNAL *);
    DWORD (*verifyPreviousPair)(void *, const PB_INSTALL_JOURNAL *);
    // Rollback validates only the retained previous payload (or first-install
    // removal identity). It must not depend on the failed target being intact.
    DWORD (*validateRollback)(void *, const PB_INSTALL_JOURNAL *);
} PB_INSTALL_OPERATIONS;

DWORD pb_install_continue(HKEY key, const PB_INSTALL_OPERATIONS *operations);
