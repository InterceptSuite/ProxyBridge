#include "install-pair.h"

void pb_transaction_payloads_close(PB_TRANSACTION_PAYLOADS *payloads)
{
    if (!payloads) return;
    pb_payload_close(&payloads->previous);
    pb_payload_close(&payloads->target);
}

DWORD pb_transaction_payloads_open(const PB_INSTALL_JOURNAL *record, PB_TRANSACTION_PAYLOADS *payloads)
{
    if (!payloads) return ERROR_INVALID_PARAMETER;
    ZeroMemory(payloads, sizeof(*payloads));
    DWORD error = pb_journal_validate(record);
    if (error != ERROR_SUCCESS) return error;
    error = pb_payload_open(record->targetDirectory, record->targetManifestHash,
                            record->targetProtocol, record->targetDriverVersion, &payloads->target);
    if (error == ERROR_SUCCESS && record->previousDirectory[0])
        error = pb_payload_open(record->previousDirectory, record->previousManifestHash,
                                record->previousProtocol, record->previousDriverVersion, &payloads->previous);
    if (error != ERROR_SUCCESS) pb_transaction_payloads_close(payloads);
    return error;
}

DWORD pb_rollback_payload_open(const PB_INSTALL_JOURNAL *record, PB_TRANSACTION_PAYLOADS *payloads)
{
    if (!payloads) return ERROR_INVALID_PARAMETER;
    ZeroMemory(payloads, sizeof(*payloads));
    DWORD error = pb_journal_validate(record);
    if (error != ERROR_SUCCESS) return error;
    // First installation has no previous payload. The native rollback adapter
    // must still verify ownership of the new device before removing it.
    if (!record->previousDirectory[0]) return ERROR_SUCCESS;
    return pb_payload_open(record->previousDirectory, record->previousManifestHash,
                            record->previousProtocol, record->previousDriverVersion, &payloads->previous);
}
