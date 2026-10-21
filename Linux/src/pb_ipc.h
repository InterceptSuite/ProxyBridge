// Messages between the ProxyBridge service (root, "ProxyBridge --daemon") and its clients (the GUI), over a Unix socket.
//
//   frame   = u32 length (big endian, bytes after this field) | u16 field count | field...
//   field   = u32 length | bytes
//
// Every message is a list of byte strings. Numbers are decimal text. The first field is the kind:
//   request   "q" <id> <command> <argument>...
//   response  "r" <id> "ok" <result>...   or   "r" <id> "err" <reason>
//   event     "e" <name> <argument>...
// Limits are enforced while reading, before anything is allocated, so a client cannot make the service allocate more than
// PB_IPC_MAX_FRAME for one message.
#ifndef PB_IPC_H
#define PB_IPC_H

#include <stddef.h>
#include <stdint.h>

#define PB_IPC_PROTOCOL   1
#define PB_IPC_MAX_FRAME  (8u << 20)      // a .pbprofile may be 4 MiB; a list of flows or names is far smaller
#define PB_IPC_MAX_FIELDS 4096
#define PB_IPC_SOCKET_DIR  "/run/proxybridge"
#define PB_IPC_SOCKET_PATH "/run/proxybridge/ctl.sock"

typedef struct {
    unsigned n;
    char   **f;        // f[i] is NUL terminated (it may also contain NULs: use len[i])
    size_t  *len;
    char    *pool;     // all fields live here
} pb_msg;

void pb_msg_free(pb_msg *m);

// Blocking. 0 = ok, -1 = connection closed or I/O error, -2 = the peer broke the format (the connection must be dropped).
int pb_ipc_recv(int fd, pb_msg *m);
// The same, but once the header of a frame has arrived the rest must follow within body_ms (a peer that announces a frame and never
// sends it would otherwise hold a thread and its buffer for ever). Waiting for the header itself has no limit. -1 also on timeout.
int pb_ipc_recv_timeout(int fd, pb_msg *m, int body_ms);
// len may be NULL (every field is a C string). 0 or -1.
int pb_ipc_send(int fd, unsigned n, const char *const *f, const size_t *len);
// Convenience: the arguments are C strings, the list ends with NULL.
int pb_ipc_sendv(int fd, ...);

// Pure encoding and decoding (the I/O functions use these; they are also what the tests and the fuzzer drive).
// pb_ipc_encode returns a malloc'd frame (*out_len bytes) or NULL when the message is too big.
unsigned char *pb_ipc_encode(unsigned n, const char *const *f, const size_t *len, size_t *out_len);
// Decodes the payload of a frame (without the 4 length bytes). 0 or -2.
int pb_ipc_decode(const unsigned char *payload, size_t plen, pb_msg *m);

#endif
