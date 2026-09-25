#include "install-coordinator.h"

DWORD pb_install_continue(HKEY key, const PB_INSTALL_OPERATIONS *op)
{
    if (!op || !op->validate || !op->installDriver || !op->verifyDriver ||
        !op->publishApp || !op->verifyPair || !op->restorePair || !op->verifyPreviousPair || !op->validateRollback)
        return ERROR_INVALID_PARAMETER;
    PB_INSTALL_JOURNAL record;
    DWORD result = pb_journal_read(key, &record);
    if (result != ERROR_SUCCESS) return result;
    if (record.phase == PB_INSTALL_COMMITTED) return ERROR_SUCCESS;
    if (record.phase == PB_INSTALL_ROLLED_BACK)
        return record.lastError ? record.lastError : ERROR_INSTALL_FAILURE;
    // These write-ahead phases found on entry mean interruption at an unknown
    // point. Never blindly replay an installation or publication operation.
    if (record.phase == PB_INSTALL_DRIVER_CHANGING ||
        record.phase == PB_INSTALL_APP_CHANGING) {
        result = pb_journal_advance(key, &record, PB_INSTALL_RECOVERY_REQUIRED,
                                    ERROR_OPERATION_ABORTED);
        if (result != ERROR_SUCCESS) return result;
    }
    if (record.phase == PB_INSTALL_PREPARED || record.phase == PB_INSTALL_DRIVER_PENDING ||
        record.phase == PB_INSTALL_DRIVER_VERIFIED) {
        result = op->validate(op->context, &record);
        if (result != ERROR_SUCCESS) {
            // Before the first mutation the candidate can simply be rejected.
            // After a driver change, damaged target files must not prevent a
            // separately validated rollback to the previous pair.
            if (record.phase == PB_INSTALL_PREPARED) return result;
            result = pb_journal_advance(key, &record, PB_INSTALL_ROLLING_BACK, result);
            if (result != ERROR_SUCCESS) return result;
        }
    }
    for (;;) {
        DWORD next = 0, operationError = ERROR_SUCCESS;
        switch (record.phase) {
        case PB_INSTALL_PREPARED:
            result = pb_journal_advance(key, &record, PB_INSTALL_DRIVER_CHANGING, 0);
            if (result != ERROR_SUCCESS) return result;
            operationError = op->installDriver(op->context, &record);
            if (operationError == ERROR_SUCCESS_REBOOT_REQUIRED) {
                result = pb_journal_advance(key, &record, PB_INSTALL_DRIVER_PENDING, operationError);
                return result == ERROR_SUCCESS ? operationError : result;
            }
            if (operationError == ERROR_SUCCESS)
                operationError = op->verifyDriver(op->context, &record);
            if (operationError == ERROR_SUCCESS_REBOOT_REQUIRED) {
                result = pb_journal_advance(key, &record, PB_INSTALL_DRIVER_PENDING, operationError);
                return result == ERROR_SUCCESS ? operationError : result;
            }
            next = operationError == ERROR_SUCCESS ? PB_INSTALL_DRIVER_VERIFIED : PB_INSTALL_ROLLING_BACK;
            break;
        case PB_INSTALL_DRIVER_PENDING:
            operationError = op->verifyDriver(op->context, &record);
            if (operationError == ERROR_SUCCESS_REBOOT_REQUIRED) return operationError;
            next = operationError == ERROR_SUCCESS ? PB_INSTALL_DRIVER_VERIFIED : PB_INSTALL_ROLLING_BACK;
            break;
        case PB_INSTALL_DRIVER_VERIFIED:
            // A resume may occur after this phase was persisted. Verify again
            // before publishing; a persisted past observation is not live proof.
            operationError = op->verifyDriver(op->context, &record);
            if (operationError != ERROR_SUCCESS) {
                next = PB_INSTALL_ROLLING_BACK;
                break;
            }
            result = pb_journal_advance(key, &record, PB_INSTALL_APP_CHANGING, 0);
            if (result != ERROR_SUCCESS) return result;
            operationError = op->publishApp(op->context, &record);
            if (operationError == ERROR_SUCCESS) operationError = op->verifyPair(op->context, &record);
            next = operationError == ERROR_SUCCESS ? PB_INSTALL_COMMITTED : PB_INSTALL_ROLLING_BACK;
            break;
        case PB_INSTALL_RECOVERY_REQUIRED:
            next = PB_INSTALL_ROLLING_BACK;
            operationError = record.lastError;
            break;
        case PB_INSTALL_ROLLING_BACK:
            operationError = op->validateRollback(op->context, &record);
            if (operationError != ERROR_SUCCESS) {
                next = PB_INSTALL_RECOVERY_REQUIRED;
                break;
            }
            // Restore must be idempotent and validate which pair is installed:
            // the preceding process could have died after restoration succeeded.
            operationError = op->restorePair(op->context, &record);
            if (operationError == ERROR_SUCCESS_REBOOT_REQUIRED) {
                result = pb_journal_advance(key, &record, PB_INSTALL_ROLLBACK_PENDING, record.lastError);
                return result == ERROR_SUCCESS ? operationError : result;
            }
            if (operationError == ERROR_SUCCESS)
                operationError = op->verifyPreviousPair(op->context, &record);
            if (operationError == ERROR_SUCCESS_REBOOT_REQUIRED) {
                result = pb_journal_advance(key, &record, PB_INSTALL_ROLLBACK_PENDING, record.lastError);
                return result == ERROR_SUCCESS ? operationError : result;
            }
            next = operationError == ERROR_SUCCESS ? PB_INSTALL_ROLLED_BACK : PB_INSTALL_RECOVERY_REQUIRED;
            break;
        case PB_INSTALL_ROLLBACK_PENDING:
            operationError = op->validateRollback(op->context, &record);
            if (operationError != ERROR_SUCCESS) {
                next = PB_INSTALL_RECOVERY_REQUIRED;
                break;
            }
            operationError = op->verifyPreviousPair(op->context, &record);
            if (operationError == ERROR_SUCCESS_REBOOT_REQUIRED) return operationError;
            next = operationError == ERROR_SUCCESS ? PB_INSTALL_ROLLED_BACK : PB_INSTALL_RECOVERY_REQUIRED;
            break;
        default:
            return ERROR_INVALID_STATE;
        }
        // Keep the original installation failure after successful restoration.
        DWORD savedError = operationError ? operationError : record.lastError;
        result = pb_journal_advance(key, &record, next, savedError);
        if (result != ERROR_SUCCESS) return result;
        if (next == PB_INSTALL_COMMITTED) return ERROR_SUCCESS;
        if (next == PB_INSTALL_ROLLED_BACK)
            return savedError ? savedError : ERROR_INSTALL_FAILURE;
        if (next == PB_INSTALL_RECOVERY_REQUIRED)
            return operationError ? operationError : ERROR_INSTALL_FAILURE;
    }
}
