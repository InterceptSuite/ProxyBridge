#pragma once
#include "startup-task.h"
// Caller owns the installation mutex. Does not acquire the Core update guard:
// changing GUI autostart is allowed while traffic forwarding remains active.
DWORD pb_startup_installed(PB_STARTUP_OPERATION operation, BOOL *enabled);
DWORD pb_startup_file_security(PSECURITY_DESCRIPTOR descriptor);
