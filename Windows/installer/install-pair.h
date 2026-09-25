#pragma once
#include "install-journal.h"
#include "install-payload.h"

typedef struct PB_TRANSACTION_PAYLOADS {
    PB_VERIFIED_PAYLOAD target;
    PB_VERIFIED_PAYLOAD previous;
} PB_TRANSACTION_PAYLOADS;

// Coordinator adapter building block: validate both persisted identities and
// retain files/ancestor directories for the complete operation. Output must be
// fresh/closed. Signature verification must follow before any mutation.
DWORD pb_transaction_payloads_open(const PB_INSTALL_JOURNAL *record, PB_TRANSACTION_PAYLOADS *payloads);
DWORD pb_rollback_payload_open(const PB_INSTALL_JOURNAL *record, PB_TRANSACTION_PAYLOADS *payloads);
void pb_transaction_payloads_close(PB_TRANSACTION_PAYLOADS *payloads);
