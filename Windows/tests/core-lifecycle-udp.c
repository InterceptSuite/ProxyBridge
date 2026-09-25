#include "pb_internal.h"
// Avoid taking the installed application's fixed UDP port in this test.
#undef LOCAL_UDP_RELAY_PORT
#define LOCAL_UDP_RELAY_PORT 0
#include "../src/relay/pb_relay_udp.c"
