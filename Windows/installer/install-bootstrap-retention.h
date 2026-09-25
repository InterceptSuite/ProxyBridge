#pragma once
#include "install-journal.h"
// Call under the installation mutex, with the protected installation store.
// Retirement is recorded only after all owned registration/task links moved.
typedef DWORD (*PB_BOOTSTRAP_REFERENCED)(void *context, const WCHAR *directory, BOOL *referenced);
DWORD pb_bootstrap_retire(HKEY key, const WCHAR *hash);
// activeHash is the bootstrap executing the package operation. The callback
// checks remaining registration/shortcut references; task retarget/removal must
// already have succeeded under the same mutex. Busy files retain their receipt.
DWORD pb_bootstrap_collect(HKEY key, const PB_INSTALL_JOURNAL *current, const WCHAR *activeHash,
    PB_BOOTSTRAP_REFERENCED referenced, void *context);
