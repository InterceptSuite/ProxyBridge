// "Start at boot": a systemd service that runs the command line program with the active profile.
#ifndef PROXYBRIDGE_GUI_BOOT_H
#define PROXYBRIDGE_GUI_BOOT_H

#include <glib.h>
#include <stdbool.h>

// Text of the unit file. profile_path is the stored profile file (absolute). NULL (with *error set) if a value cannot be
// written safely (control characters, relative path).
char *boot_unit_text(const char *cli_path, const char *profile_path, char **error);
// True when path (a file) and every directory above it belong to root and are writable by root only.
bool boot_path_trusted(const char *path, char **why);
// True when the unit file exists.
bool boot_is_enabled(void);
// Writes the unit and enables it, or disables it and removes the file. On failure returns false with a message in *error
// (g_malloc'd). The program the unit starts is the ProxyBridge next to this program, or /usr/local/bin/ProxyBridge; it must
// pass boot_path_trusted(). profile is the absolute path of the profile file.
bool boot_set(bool enable, const char *profile, char **error);
// Rewrites the unit for another active profile if it is enabled.
bool boot_refresh(const char *profile, char **error);

#endif
