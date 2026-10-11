// pbver.inc - VERSIONINFO shared by the non-GUI binaries (Properties > Details).
// Including .rc defines PB_FILE_DESC, PB_ORIG_NAME and PB_FTYPE (VFT_APP / VFT_DLL); the version
// numbers come from resource.h, same as the GUI's app.rc.
#include <windows.h>
#include "resource.h"

VS_VERSION_INFO VERSIONINFO
 FILEVERSION    PB_VER_MAJOR,PB_VER_MINOR,PB_VER_PATCH,PB_VER_BUILD
 PRODUCTVERSION PB_VER_MAJOR,PB_VER_MINOR,PB_VER_PATCH,PB_VER_BUILD
 FILEFLAGSMASK  0x3fL
 FILEFLAGS      0x0L
 FILEOS         VOS_NT_WINDOWS32
 FILETYPE       PB_FTYPE
 FILESUBTYPE    0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "InterceptSuite"
            VALUE "FileDescription",  PB_FILE_DESC
            VALUE "FileVersion",      PB_VER_STR
            VALUE "InternalName",     PB_ORIG_NAME
            VALUE "OriginalFilename", PB_ORIG_NAME
            VALUE "ProductName",      "ProxyBridge"
            VALUE "ProductVersion",   PB_VER_STR
            VALUE "LegalCopyright",   "Copyright (c) 2026 InterceptSuite"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
