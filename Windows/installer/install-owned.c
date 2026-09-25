#include "install-owned.h"
#include "install-stage.h"
#include <objbase.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

typedef struct PB_OWNED_PAYLOAD {
    DWORD size, version, protocol, driverVersion;
    BYTE hash[32];
    WCHAR directory[MAX_PATH];
} PB_OWNED_PAYLOAD;
static const WCHAR ownedPrefix[] = L"OwnedPayload-";
static const WCHAR stagingValue[] = L"PendingStage";

DWORD pb_owned_stage_prepare(HKEY key, HANDLE root, PB_INSTALL_JOURNAL *next)
{
    if (!next) return ERROR_INVALID_PARAMETER;
    DWORD error = pb_stage_target_path(root, &next->transaction, next->targetDirectory);
    if (!error) error = pb_journal_validate(next);
    if (!error && next->phase != PB_INSTALL_PREPARED) error = ERROR_INVALID_STATE;
    if (error) return error;
    DWORD bytes = 0;
    error = RegQueryValueExW(key, stagingValue, NULL, NULL, NULL, &bytes);
    if (!error || error == ERROR_MORE_DATA) return ERROR_BUSY;
    if (error != ERROR_FILE_NOT_FOUND) return error;
    // A random GUID collision must not claim a pre-existing directory.
    if (GetFileAttributesW(next->targetDirectory) != INVALID_FILE_ATTRIBUTES) return ERROR_ALREADY_EXISTS;
    error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) return error;
    error = RegSetValueExW(key, stagingValue, 0, REG_BINARY, (const BYTE *)next, sizeof(*next));
    return error ? error : RegFlushKey(key);
}

static DWORD receipt_name(const PB_OWNED_PAYLOAD *receipt, WCHAR name[64])
{
    static const BYTE empty[32] = {0};
    if (receipt->size != sizeof(*receipt) || receipt->version != 1 ||
        !receipt->protocol || !receipt->driverVersion || !memcmp(receipt->hash, empty, 32) ||
        wcsnlen_s(receipt->directory, MAX_PATH) >= MAX_PATH) return ERROR_INVALID_DATA;
    const WCHAR *leaf = wcsrchr(receipt->directory, L'\\');
    GUID id; WCHAR canonical[40];
    if (!leaf || wcslen(++leaf) != 38 || FAILED(CLSIDFromString(leaf, &id)) ||
        !StringFromGUID2(&id, canonical, ARRAYSIZE(canonical)) || _wcsicmp(leaf, canonical)) return ERROR_INVALID_NAME;
    return swprintf_s(name, 64, L"%s%s", ownedPrefix, canonical) < 0 ? ERROR_INVALID_NAME : 0;
}
static DWORD remember(HKEY key, const WCHAR *directory, const BYTE hash[32], DWORD protocol, DWORD version)
{
    if (!directory[0]) return 0;
    PB_OWNED_PAYLOAD receipt = {0}, existing = {0};
    receipt.size = sizeof(receipt); receipt.version = 1;
    receipt.protocol = protocol; receipt.driverVersion = version;
    memcpy(receipt.hash, hash, 32);
    if (wcscpy_s(receipt.directory, MAX_PATH, directory)) return ERROR_INVALID_NAME;
    WCHAR name[64]; DWORD error = receipt_name(&receipt, name); if (error) return error;
    DWORD bytes = sizeof(existing), type = 0;
    error = RegQueryValueExW(key, name, NULL, &type, (BYTE *)&existing, &bytes);
    if (!error) {
        if (type != REG_BINARY || bytes != sizeof(existing) || memcmp(&existing, &receipt, sizeof(receipt)))
            return ERROR_REVISION_MISMATCH;
        return 0;
    }
    if (error != ERROR_FILE_NOT_FOUND) return error;
    return RegSetValueExW(key, name, 0, REG_BINARY, (const BYTE *)&receipt, sizeof(receipt));
}
static DWORD remember_journal(HKEY key, const PB_INSTALL_JOURNAL *record)
{
    DWORD error = pb_journal_validate(record); if (error) return error;
    error = remember(key, record->targetDirectory, record->targetManifestHash, record->targetProtocol, record->targetDriverVersion);
    if (!error) error = remember(key, record->previousDirectory, record->previousManifestHash, record->previousProtocol, record->previousDriverVersion);
    return error;
}

DWORD pb_owned_stage_recover(HKEY key, HANDLE root, const PB_INSTALL_JOURNAL *current)
{
    if (!current) return ERROR_INVALID_PARAMETER;
    DWORD error = current->size ? pb_journal_validate(current) : 0;
    if (error) return error;
    PB_INSTALL_JOURNAL pending = {0}; DWORD bytes = sizeof(pending), type = 0;
    error = RegQueryValueExW(key, stagingValue, NULL, &type, (BYTE *)&pending, &bytes);
    if (error == ERROR_FILE_NOT_FOUND) return 0;
    if (error) return error;
    if (type != REG_BINARY || bytes != sizeof(pending)) return ERROR_INVALID_DATA;
    error = pb_journal_validate(&pending); if (error) return error;
    if (pending.phase != PB_INSTALL_PREPARED) return ERROR_INVALID_STATE;
    error = pb_stage_validate_target(root, &pending.transaction, pending.targetDirectory); if (error) return error;
    // A durable ordinary receipt means staging completed and permanent retention
    // now owns the bytes. It remains authoritative even if journal flush failed.
    PB_OWNED_PAYLOAD wanted = {0}, owned = {0}; WCHAR name[64];
    wanted.size = sizeof(wanted); wanted.version = 1;
    wanted.protocol = pending.targetProtocol; wanted.driverVersion = pending.targetDriverVersion;
    memcpy(wanted.hash, pending.targetManifestHash, 32);
    wcscpy_s(wanted.directory, MAX_PATH, pending.targetDirectory);
    error = receipt_name(&wanted, name); if (error) return error;
    bytes = sizeof(owned); type = 0;
    error = RegQueryValueExW(key, name, NULL, &type, (BYTE *)&owned, &bytes);
    if (!error) {
        if (type != REG_BINARY || bytes != sizeof(owned) || memcmp(&owned, &wanted, sizeof(owned))) return ERROR_REVISION_MISMATCH;
        // Ensure a previously failed receipt flush is durable before forgetting intent.
        error = RegFlushKey(key); if (error) return error;
    } else {
        if (error != ERROR_FILE_NOT_FOUND) return error;
        if (current->size) {
            if (!_wcsicmp(pending.targetDirectory, current->targetDirectory) ||
                (current->previousDirectory[0] && !_wcsicmp(pending.targetDirectory, current->previousDirectory)))
                return ERROR_INVALID_STATE; // Referenced but missing ownership proof: never delete.
            if (current->phase != PB_INSTALL_COMMITTED && current->phase != PB_INSTALL_ROLLED_BACK && current->phase != PB_INSTALL_CLEANED)
                return ERROR_BUSY;
        }
        error = pb_stage_cleanup_partial(root, &pending.transaction, pending.targetDirectory);
        if (error) return error; // Leave durable intent for retry after partial deletion.
    }
    error = RegDeleteValueW(key, stagingValue);
    return error ? error : RegFlushKey(key);
}
DWORD pb_owned_begin(HKEY key, const PB_INSTALL_JOURNAL *old, const PB_INSTALL_JOURNAL *next)
{
    if (!old || !next) return ERROR_INVALID_PARAMETER;
    DWORD error = old->size ? remember_journal(key, old) : 0;
    if (!error) error = remember_journal(key, next);
    if (!error) error = RegFlushKey(key);
    if (!error) error = pb_journal_begin(key, next);
    return error;
}
DWORD pb_owned_cleanup(HKEY key, HANDLE root, const PB_INSTALL_JOURNAL *current)
{
    DWORD error = pb_journal_validate(current); if (error) return error;
    if (current->phase != PB_INSTALL_COMMITTED && current->phase != PB_INSTALL_ROLLED_BACK &&
        current->phase != PB_INSTALL_CLEANED) return ERROR_INVALID_STATE;
    for (DWORD index = 0;;) {
        WCHAR name[64], expected[64]; DWORD length = ARRAYSIZE(name);
        error = RegEnumValueW(key, index, name, &length, NULL, NULL, NULL, NULL);
        if (error == ERROR_NO_MORE_ITEMS) return 0;
        // A longer name cannot be one of our fixed-length receipt names.
        if (error == ERROR_MORE_DATA) { ++index; continue; }
        if (error) return error;
        if (wcsncmp(name, ownedPrefix, ARRAYSIZE(ownedPrefix)-1)) { ++index; continue; }
        PB_OWNED_PAYLOAD receipt = {0}; DWORD bytes = sizeof(receipt), type = 0;
        error = RegQueryValueExW(key, name, NULL, &type, (BYTE *)&receipt, &bytes);
        if (error) return error;
        if (type != REG_BINARY || bytes != sizeof(receipt)) return ERROR_INVALID_DATA;
        error = receipt_name(&receipt, expected); if (error) return error;
        if (_wcsicmp(name, expected)) return ERROR_INVALID_DATA;
        if (current->phase != PB_INSTALL_CLEANED) {
            BOOL target = !_wcsicmp(receipt.directory, current->targetDirectory);
            BOOL previous = current->previousDirectory[0] && !_wcsicmp(receipt.directory, current->previousDirectory);
            if (target || previous) {
                const BYTE *hash = target ? current->targetManifestHash : current->previousManifestHash;
                DWORD protocol = target ? current->targetProtocol : current->previousProtocol;
                DWORD version = target ? current->targetDriverVersion : current->previousDriverVersion;
                if (memcmp(hash, receipt.hash, 32) || protocol != receipt.protocol || version != receipt.driverVersion)
                    return ERROR_REVISION_MISMATCH;
                ++index; continue;
            }
        }
        error = pb_stage_cleanup_files(root, receipt.directory, receipt.hash, receipt.protocol, receipt.driverVersion);
        if (error) return error; // Preserve receipt for retry, including partial deletion.
        error = RegDeleteValueW(key, name); if (error) return error;
        error = RegFlushKey(key); if (error) return error;
        // Registry enumeration order is unspecified after mutation.
        index = 0;
    }
}
