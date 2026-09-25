#pragma once
#include "install-journal.h"
typedef struct PB_INSTALL_STEPS {
    DWORD (*read)(PB_INSTALL_JOURNAL *);
    DWORD (*apply)(void);
    DWORD (*verifyPending)(void);
    DWORD (*publish)(void);
    DWORD (*rollback)(void);
    DWORD (*restore)(void);
    DWORD (*markRollback)(DWORD);
} PB_INSTALL_STEPS;
// Native primitives own durable phase writes; caller holds both global guards
// for the entire dispatch, including automatic recovery after an install error.
DWORD pb_resume_install(const PB_INSTALL_STEPS *steps);
