#include "install-selection.h"
#include <string.h>
#include <wchar.h>

DWORD pb_select_application(const PB_INSTALL_JOURNAL *record, PB_APP_SELECTION *selection)
{
    if (!selection) return ERROR_INVALID_PARAMETER;
    ZeroMemory(selection, sizeof(*selection));
    DWORD error = pb_journal_validate(record);
    if (error != ERROR_SUCCESS) return error;
    if (record->phase == PB_INSTALL_REMOVED || record->phase == PB_INSTALL_CLEANED) return ERROR_NOT_FOUND;
    if (pb_journal_blocks_launch(record->phase)) return ERROR_INSTALL_SUSPEND;
    BOOL previous = record->phase == PB_INSTALL_ROLLED_BACK;
    const WCHAR *directory = previous ? record->previousDirectory : record->targetDirectory;
    if (!directory[0]) return ERROR_NOT_FOUND;
    wcscpy_s(selection->directory, MAX_PATH, directory);
    memcpy(selection->manifestHash, previous ? record->previousManifestHash : record->targetManifestHash, 32);
    selection->protocol = previous ? record->previousProtocol : record->targetProtocol;
    selection->driverVersion = previous ? record->previousDriverVersion : record->targetDriverVersion;
    return ERROR_SUCCESS;
}
