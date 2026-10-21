// "Start at boot" when the window itself runs as root: installs proxybridge.service, which runs "ProxyBridge --daemon". The service
// starts the profile that was active when the window last saved its settings.
#ifndef PROXYBRIDGE_GUI_BOOT_H
#define PROXYBRIDGE_GUI_BOOT_H

#include <glib.h>
#include <stdbool.h>

// Text of the unit file (see src/pb_unit.h). NULL (with *error set) if the program path cannot be written safely.
char *boot_unit_text(const char *cli_path, char **error);
// True when path (a file) and every directory above it belong to root and are writable by root only.
bool boot_path_trusted(const char *path, char **why);
// True when the unit file exists.
bool boot_is_enabled(void);
// Writes the unit and enables it, or disables it and removes the file. On failure returns false with a message in *error
// (g_malloc'd). The program the unit starts is the ProxyBridge next to this program, or /usr/local/bin/ProxyBridge; it must
// pass boot_path_trusted().
bool boot_set(bool enable, char **error);

#endif
