// The systemd unit that runs "ProxyBridge --daemon". One text for everything that installs it: setup.sh (through
// "ProxyBridge --print-unit"), the window's Start at Boot in embedded mode, and the tests.
#ifndef PB_UNIT_H
#define PB_UNIT_H

#define PB_UNIT_NAME "proxybridge.service"

// exe: absolute path of the ProxyBridge program. Returns the malloc'd unit text, or NULL with *error (static string) set when the
// path cannot be written safely into a service file (relative, control characters).
char *pb_unit_text(const char *exe, const char **error);

#endif
