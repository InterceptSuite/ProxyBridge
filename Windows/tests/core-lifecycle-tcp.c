#include "../src/relay/pb_relay_tcp.c"
// Test entry points bypass driver destination lookup only. Real async setup,
// socket registry, IOCP handoff and shutdown code stay unchanged.
BOOL test_start_handshake(CONNECTION_CONFIG* config) { return start_tcp_worker(config); }
BOOL test_tcp_clean(void)
{
    for(int i=0;i<PB_TCP_IO_WORKER_COUNT;i++) if(tcpIoWorkers[i]) return FALSE;
    return !tcpSetups && !tcpSetupCount && !tcpIoPairs && !tcpIoPort;
}
