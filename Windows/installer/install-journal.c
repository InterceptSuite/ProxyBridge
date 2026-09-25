#include "install-journal.h"
#include <wchar.h>
#include <string.h>

static const WCHAR valueName[] = L"Transaction";

static BOOL valid_removal_inf(const WCHAR *inf)
{
    if (_wcsnicmp(inf, L"oem", 3)) return FALSE;
    unsigned i = 3;
    if (inf[i] < L'0' || inf[i] > L'9') return FALSE;
    while (i < MAX_PATH - 5 && inf[i] >= L'0' && inf[i] <= L'9') ++i;
    return _wcsicmp(inf + i, L".inf") == 0;
}

BOOL pb_journal_transition_allowed(DWORD from, DWORD to)
{
    switch (from) {
    case PB_INSTALL_REMOVED: return to == PB_INSTALL_CLEANING;
    case PB_INSTALL_CLEANING: return to == PB_INSTALL_CLEANED;
    case PB_INSTALL_REMOVING:
        return to == PB_INSTALL_REMOVE_PENDING || to == PB_INSTALL_REMOVED;
    case PB_INSTALL_REMOVE_PENDING:
        return to == PB_INSTALL_REMOVING || to == PB_INSTALL_REMOVED;
    case PB_INSTALL_PREPARED:
        return to == PB_INSTALL_DRIVER_CHANGING || to == PB_INSTALL_ROLLING_BACK;
    case PB_INSTALL_DRIVER_CHANGING:
        return to == PB_INSTALL_DRIVER_PENDING || to == PB_INSTALL_DRIVER_VERIFIED ||
               to == PB_INSTALL_ROLLING_BACK || to == PB_INSTALL_RECOVERY_REQUIRED;
    case PB_INSTALL_DRIVER_PENDING:
        return to == PB_INSTALL_DRIVER_VERIFIED || to == PB_INSTALL_ROLLING_BACK ||
               to == PB_INSTALL_RECOVERY_REQUIRED;
    case PB_INSTALL_DRIVER_VERIFIED:
        return to == PB_INSTALL_APP_CHANGING || to == PB_INSTALL_ROLLING_BACK;
    case PB_INSTALL_APP_CHANGING:
        return to == PB_INSTALL_COMMITTED || to == PB_INSTALL_ROLLING_BACK ||
               to == PB_INSTALL_RECOVERY_REQUIRED;
    case PB_INSTALL_ROLLING_BACK:
        return to == PB_INSTALL_ROLLBACK_PENDING || to == PB_INSTALL_ROLLED_BACK ||
               to == PB_INSTALL_RECOVERY_REQUIRED;
    case PB_INSTALL_ROLLBACK_PENDING:
        return to == PB_INSTALL_ROLLING_BACK || to == PB_INSTALL_ROLLED_BACK ||
               to == PB_INSTALL_RECOVERY_REQUIRED;
    case PB_INSTALL_RECOVERY_REQUIRED:
        return to == PB_INSTALL_ROLLING_BACK;
    default:
        return FALSE;
    }
}

BOOL pb_journal_blocks_launch(DWORD phase)
{
    // Unknown/corrupt state is not equivalent to a completed transaction.
    return phase != PB_INSTALL_COMMITTED && phase != PB_INSTALL_ROLLED_BACK;
}

DWORD pb_journal_validate(const PB_INSTALL_JOURNAL *record)
{
    static const GUID empty = {0};
    static const BYTE emptyHash[32] = {0};
    if (!record || record->size != sizeof(*record) || record->version != PB_JOURNAL_VERSION ||
        IsEqualGUID(&record->transaction, &empty) ||
        record->phase < PB_INSTALL_PREPARED || record->phase > PB_INSTALL_FLAT_REMOVED ||
        !record->targetProtocol || !record->targetDriverVersion ||
        record->deviceExisted > 1 || !record->deviceInstance[0] || record->deviceInstance[199] ||
        !memcmp(record->targetManifestHash, emptyHash, sizeof(emptyHash)) ||
        (record->previousDirectory[0] && (!record->previousProtocol || !record->previousDriverVersion ||
            !memcmp(record->previousManifestHash, emptyHash, sizeof(emptyHash)))) ||
        !record->targetDirectory[0] ||
        record->targetDirectory[MAX_PATH - 1] || record->previousDirectory[MAX_PATH - 1] ||
        record->previousInf[MAX_PATH - 1] || record->removalInf[MAX_PATH - 1] ||
        (record->phase >= PB_INSTALL_REMOVING && record->phase <= PB_INSTALL_CLEANED && !valid_removal_inf(record->removalInf)) ||
        (record->phase >= PB_INSTALL_FLAT_COPYING && record->previousDirectory[0]) ||
        (record->phase >= PB_INSTALL_FLAT_COPYING && record->removalInf[0] && !valid_removal_inf(record->removalInf)))
        return ERROR_INVALID_DATA;
    // Paths are identities only. Recovery must independently validate canonical
    // paths, ownership, manifest and signatures before any copy/remove action.
    return ERROR_SUCCESS;
}

DWORD pb_journal_read(HKEY key, PB_INSTALL_JOURNAL *record)
{
    if (!record) return ERROR_INVALID_PARAMETER;
    PB_INSTALL_JOURNAL candidate = {0};
    DWORD bytes = sizeof(candidate), type = 0;
    LSTATUS error = RegQueryValueExW(key, valueName, NULL, &type, (BYTE *)&candidate, &bytes);
    if (error != ERROR_SUCCESS) return (DWORD)error;
    if (type != REG_BINARY || bytes != sizeof(candidate)) return ERROR_INVALID_DATA;
    DWORD validation = pb_journal_validate(&candidate);
    if (validation != ERROR_SUCCESS) return validation;
    *record = candidate;
    return ERROR_SUCCESS;
}

static DWORD persist(HKEY key, const PB_INSTALL_JOURNAL *record)
{
    LSTATUS error = RegSetValueExW(key, valueName, 0, REG_BINARY,
                                  (const BYTE *)record, sizeof(*record));
    if (error != ERROR_SUCCESS) return (DWORD)error;
    // Mutations may begin only after the write-ahead state has reached storage.
    // If flushing fails, the caller must stop and reread; the value may exist.
    return (DWORD)RegFlushKey(key);
}

DWORD pb_journal_replace_flat(HKEY key, const PB_INSTALL_JOURNAL *expected,
                              const PB_INSTALL_JOURNAL *next)
{
    DWORD error = pb_journal_validate(next);
    if (error) return error;
    if (next->previousDirectory[0] || (next->phase < PB_INSTALL_FLAT_COPYING && next->phase != PB_INSTALL_COMMITTED))
        return ERROR_INVALID_STATE;
    PB_INSTALL_JOURNAL stored;
    error = pb_journal_read(key, &stored);
    if (expected) {
        if (error) return error;
        if (memcmp(expected, &stored, sizeof(stored))) return ERROR_REVISION_MISMATCH;
    } else if (error != ERROR_FILE_NOT_FOUND) return error ? error : ERROR_REVISION_MISMATCH;
    return persist(key, next);
}

DWORD pb_journal_begin(HKEY key, const PB_INSTALL_JOURNAL *record)
{
    DWORD error = pb_journal_validate(record);
    if (error != ERROR_SUCCESS) return error;
    if (record->phase != PB_INSTALL_PREPARED) return ERROR_INVALID_STATE;
    PB_INSTALL_JOURNAL previous;
    error = pb_journal_read(key, &previous);
    if (error == ERROR_SUCCESS) {
        if (previous.phase != PB_INSTALL_REMOVED && previous.phase != PB_INSTALL_CLEANED && pb_journal_blocks_launch(previous.phase)) return ERROR_BUSY;
        if (IsEqualGUID(&previous.transaction, &record->transaction)) return ERROR_INVALID_DATA;
    } else if (error != ERROR_FILE_NOT_FOUND) {
        return error; // Never overwrite an unreadable or newer-format journal.
    }
    return persist(key, record);
}

DWORD pb_journal_begin_remove(HKEY key, PB_INSTALL_JOURNAL *record, const WCHAR *inf)
{
    DWORD error = pb_journal_validate(record);
    if (error) return error;
    if (!inf || wcsnlen(inf, MAX_PATH) == 0 || wcsnlen(inf, MAX_PATH) >= MAX_PATH)
        return ERROR_INVALID_PARAMETER;
    if (!valid_removal_inf(inf)) return ERROR_INVALID_PARAMETER;
    if (record->phase != PB_INSTALL_COMMITTED && record->phase != PB_INSTALL_ROLLED_BACK)
        return ERROR_INVALID_STATE;
    PB_INSTALL_JOURNAL stored;
    error = pb_journal_read(key, &stored);
    if (error) return error;
    if (memcmp(&stored, record, sizeof(stored))) return ERROR_REVISION_MISMATCH;
    wcscpy_s(stored.removalInf, MAX_PATH, inf);
    stored.phase = PB_INSTALL_REMOVING; stored.lastError = 0;
    error = persist(key, &stored);
    if (!error) *record = stored;
    return error;
}

DWORD pb_journal_advance(HKEY key, PB_INSTALL_JOURNAL *record, DWORD nextPhase, DWORD error)
{
    DWORD validation = pb_journal_validate(record);
    if (validation != ERROR_SUCCESS) return validation;
    PB_INSTALL_JOURNAL stored;
    DWORD result = pb_journal_read(key, &stored);
    if (result != ERROR_SUCCESS) return result;
    // Compare the entire snapshot, not just phase: stale recovery must not
    // overwrite a different transaction's paths or version identity.
    if (memcmp(&stored, record, sizeof(stored)) != 0) return ERROR_REVISION_MISMATCH;
    if (!pb_journal_transition_allowed(stored.phase, nextPhase)) return ERROR_INVALID_STATE;
    stored.phase = nextPhase;
    stored.lastError = error;
    result = persist(key, &stored);
    if (result == ERROR_SUCCESS) *record = stored;
    return result;
}
