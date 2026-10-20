// "Start at boot": a systemd service that runs the command line program with the active profile.
#ifndef PROXYBRIDGE_GUI_BOOT_H
#define PROXYBRIDGE_GUI_BOOT_H

#include <glib.h>
#include <stdbool.h>

// Text of the unit file. NULL (with *error set) if the profile name cannot be written safely (control characters).
char *boot_unit_text(const char *cli_path, const char *profile, char **error);
// True when the unit file exists.
bool boot_is_enabled(void);
// Writes the unit and enables it, or disables it and removes the file. On failure returns false with a message in *error
// (g_malloc'd). The program the unit starts is the ProxyBridge next to this program, or /usr/local/bin/ProxyBridge.
bool boot_set(bool enable, const char *profile, char **error);
// Rewrites the unit for another active profile if it is enabled.
bool boot_refresh(const char *profile, char **error);

#endif
