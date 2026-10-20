// "ProxyBridge --daemon": the root part of ProxyBridge. It owns the engine and the profile files and serves the GUI (and anything
// else that speaks pb_ipc) over a Unix socket, so the window itself does not need root.
#ifndef PB_DAEMON_H
#define PB_DAEMON_H

// Runs until SIGTERM/SIGINT. socket_path: where to listen (PB_IPC_SOCKET_PATH by default). verbose: as --verbose of the CLI.
// Returns the process exit status.
int pb_daemon_run(const char *socket_path, int verbose);

#endif
