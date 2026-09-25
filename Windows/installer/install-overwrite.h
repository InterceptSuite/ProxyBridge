#pragma once
#include "install-layout.h"

// The caller holds the runtime guard + setup mutex and has DURABLY blocked
// launch in the journal before calling this function. Source is already
// manifest-verified and remains pinned. The two support handles originate
// from the signed installer's private extraction directory.
// No old bytes are saved. On any failure, keep launch blocked and rerun Setup.
DWORD pb_product_overwrite(PB_VERIFIED_PAYLOAD *source, HANDLE launcher,
                           HANDLE uninstaller, const BYTE manifestHash[32]);
