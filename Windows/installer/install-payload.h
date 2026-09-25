#pragma once
#include <windows.h>

#define PB_PAYLOAD_FILES 7
#define PB_MANIFEST_MAGIC 0x314d4250u
typedef struct PB_PAYLOAD_MANIFEST {
    DWORD magic, size, format, protocol, driverVersion;
    DWORD appVersion[4];
    BYTE hashes[PB_PAYLOAD_FILES][32];
} PB_PAYLOAD_MANIFEST;

typedef struct PB_VERIFIED_PAYLOAD {
    PB_PAYLOAD_MANIFEST manifest;
    HANDLE files[PB_PAYLOAD_FILES + 1];
    HANDLE directories[MAX_PATH / 2];
    DWORD directoryCount;
} PB_VERIFIED_PAYLOAD;

// expectedHash MUST come from trusted installer metadata or a protected journal,
// not from an untrusted adjacent hash file. This verifies byte identity only;
// signature policy and protected canonical staging are separate mandatory gates.
// Retain the returned handles until consumption finishes (no write/delete share).
DWORD pb_payload_open(const WCHAR *directory, const BYTE expectedHash[32],
                       DWORD protocol, DWORD driverVersion, PB_VERIFIED_PAYLOAD *payload);
void pb_payload_close(PB_VERIFIED_PAYLOAD *payload);
const WCHAR *pb_payload_file_name(unsigned index);
// For a coordinator-owned staging root. Retains ancestors in a fresh guard.
DWORD pb_payload_lock_directory(const WCHAR *directory, PB_VERIFIED_PAYLOAD *guard);
// Read-only cleanup gate: rejects all entries outside the fixed payload list.
// Caller must retain verified payload directory handles during this check.
DWORD pb_payload_check_inventory(const WCHAR *directory);
// Cleanup-only: absent payload files allowed; manifest and driver directory
// required, remaining files hashed and unknown entries rejected. Never use to
// authorize installation, launch or rollback. Does not delete anything.
DWORD pb_payload_open_remaining(const WCHAR *directory, const BYTE expectedHash[32],
                       DWORD protocol, DWORD driverVersion, PB_VERIFIED_PAYLOAD *payload);
