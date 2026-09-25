#pragma once
#include "install-journal.h"

// Caller closes the returned handle and owns the install mutex when writing.
// Read mode NEVER creates a key. Existing unexpected permissions are rejected,
// not silently repaired. Descriptor validation also supports offline tests.
DWORD pb_install_store_open(BOOL create, HKEY *key);
DWORD pb_install_store_open_existing_write(HKEY *key);
DWORD pb_install_store_check_security(PSECURITY_DESCRIPTOR descriptor);
