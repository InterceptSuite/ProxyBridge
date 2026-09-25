#pragma once
#include "install-journal.h"

// Caller holds the install mutex and a validated, writable transaction key.
// Flush immutable ownership receipts BEFORE replacing the only journal.
DWORD pb_owned_begin(HKEY key, const PB_INSTALL_JOURNAL *old, const PB_INSTALL_JOURNAL *next);
// Retain current target + rollback payloads; CLEANED permits both to be removed.
// The retained versions root and per-file manifest/security checks remain mandatory.
DWORD pb_owned_cleanup(HKEY key, HANDLE root, const PB_INSTALL_JOURNAL *current);
// One pending intent under the install mutex; flush before creating its directory.
DWORD pb_owned_stage_prepare(HKEY key, HANDLE root, PB_INSTALL_JOURNAL *next);
// current may be zero only when the caller observed no transaction journal.
DWORD pb_owned_stage_recover(HKEY key, HANDLE root, const PB_INSTALL_JOURNAL *current);
