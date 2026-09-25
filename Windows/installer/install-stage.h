#pragma once
#include "install-payload.h"
// Validate recorded current/legacy-root staging intent without creating paths.
DWORD pb_stage_validate_target(HANDLE root, const GUID *transaction, const WCHAR *directory);

// Copy an already-open source into an empty destination, then flush it. Does
// not own either handle. No source path is reopened after verification.
DWORD pb_stage_copy_file(HANDLE source, HANDLE destination);
DWORD pb_stage_target_path(HANDLE root, const GUID *transaction, WCHAR destination[MAX_PATH]);
// Only for a durably recorded unpublished staging intent, never an active payload.
DWORD pb_stage_cleanup_partial(HANDLE root, const GUID *transaction, const WCHAR *directory);
// Creates/verifies the fixed ProgramData product staging root. root is borrowed
// from guard and stays valid until pb_payload_close(guard). Never repairs ACLs.
DWORD pb_stage_root_open(PB_VERIFIED_PAYLOAD *guard, HANDLE *root);
DWORD pb_stage_root_read(PB_VERIFIED_PAYLOAD *guard, HANDLE *root);
// Fixed ProgramData bootstrap/<SHA256> path, same strict owner/ACL/reparse
// checks as version staging. Only a 64-character hexadecimal leaf is accepted.
DWORD pb_bootstrap_root_open(const WCHAR *hash, PB_VERIFIED_PAYLOAD *guard, HANDLE *root);
// Same validation/retained handles, but NEVER creates or repairs directories.
DWORD pb_bootstrap_root_read(const WCHAR *hash, PB_VERIFIED_PAYLOAD *guard, HANDLE *root);
DWORD pb_programs_root_open(BOOL create, PB_VERIFIED_PAYLOAD *guard, HANDLE *root);

// root is a protected, local canonical directory retained by the coordinator
// together with its ancestor handles for this call. Refuses any existing target.
// Caller must flush PendingStage before this call. On failure partial output
// stays covered by that intent and must not become a journal target.
DWORD pb_stage_payload(HANDLE root, const GUID *transaction, PB_VERIFIED_PAYLOAD *source,
                        const BYTE manifestHash[32], WCHAR destination[MAX_PATH]);
// Delete only verified payload files in a direct GUID child of the retained
// protected versions root. Keep manifest/directories as retry receipts.
DWORD pb_stage_cleanup_files(HANDLE root, const WCHAR *directory, const BYTE hash[32], DWORD protocol, DWORD version);
