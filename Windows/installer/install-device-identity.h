#pragma once
#include "install-journal.h"

// For a first install, reserve a deterministic root instance before registering
// it. Reusing the recorded name after interruption must not create another node.
DWORD pb_plan_device_instance(const GUID *transaction, WCHAR instance[200]);
DWORD pb_check_device_instance(const PB_INSTALL_JOURNAL *record, BOOL exists, const WCHAR *instance);
DWORD pb_check_device_before_install(const PB_INSTALL_JOURNAL *record, BOOL exists,
                                     const WCHAR *instance, const WCHAR *currentInf);
