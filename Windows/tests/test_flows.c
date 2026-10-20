// test_flows.c - live connections in the engine: the relay (src\pb_relay.c) really forwards bytes between two
// loopback socket pairs, and the flow list that ProxyBridge_GetFlows() returns follows it:
//   - a proxied TCP connection appears with its owner (pid + process name), destination and proxy id
//   - the Sent / Received counters equal the bytes that were forwarded in each direction
//   - it disappears when either side closes, and nothing is leaked (the relay count returns to zero)
//   - the caller's limit is respected, bad arguments are harmless
// No driver is opened and nothing leaves the machine.
#include "pb_internal.h"
#include "pbtest.h"
#include <stddef.h>
#include "../gui/api/pb_api.h"

/* The app mirrors the engine's flow record (PBFlow in pb_api.h = PB_FLOW in ProxyBridge.h): when the engine DLL is
   loaded directly the two must be byte for byte the same. */
typedef char flow_size_matches[sizeof(PBFlow) == sizeof(PB_FLOW) ? 1 : -1];
typedef char flow_fields_match[(offsetof(PBFlow, id) == offsetof(PB_FLOW, id) && offsetof(PBFlow, pid) == offsetof(PB_FLOW, pid) &&
    offsetof(PBFlow, proxy_config_id) == offsetof(PB_FLOW, proxy_config_id) && offsetof(PBFlow, rule_id) == offsetof(PB_FLOW, rule_id) && offsetof(PBFlow, age_ms) == offsetof(PB_FLOW, age_ms) &&
    offsetof(PBFlow, sent) == offsetof(PB_FLOW, sent) && offsetof(PBFlow, received) == offsetof(PB_FLOW, received) &&
    offsetof(PBFlow, port) == offsetof(PB_FLOW, port) && offsetof(PBFlow, is_udp) == offsetof(PB_FLOW, is_udp) &&
    offsetof(PBFlow, is_ipv6) == offsetof(PB_FLOW, is_ipv6) && offsetof(PBFlow, dest) == offsetof(PB_FLOW, dest) &&
    offsetof(PBFlow, name) == offsetof(PB_FLOW, name) && offsetof(PBFlow, host) == offsetof(PB_FLOW, host) &&
    PB_FLOWS_MAX_GUI == PB_FLOWS_MAX) ? 1 : -1];

static BOOL make_pair(SOCKET* a, SOCKET* b)
{
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; int len = sizeof(sa);
    memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) || listen(ls, 1) || getsockname(ls, (struct sockaddr*)&sa, &len)) { closesocket(ls); return FALSE; }
    *a = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(*a, (struct sockaddr*)&sa, sizeof(sa))) { closesocket(ls); closesocket(*a); return FALSE; }
    *b = accept(ls, NULL, NULL);
    closesocket(ls);
    return *b != INVALID_SOCKET;
}

static BOOL send_n(SOCKET s, int n) { char buf[4096]; memset(buf, 'x', sizeof buf); while (n > 0) { int c = n > (int)sizeof buf ? (int)sizeof buf : n; int r = send(s, buf, c, 0); if (r <= 0) return FALSE; n -= r; } return TRUE; }
static BOOL recv_n_bytes(SOCKET s, int n) { char buf[4096]; while (n > 0) { int r = recv(s, buf, n > (int)sizeof buf ? (int)sizeof buf : n, 0); if (r <= 0) return FALSE; n -= r; } return TRUE; }

// polls the engine until `pred` holds or ~4 s pass
static PB_FLOW g_f[PB_FLOWS_MAX];
static UINT32  g_n;
static BOOL wait_flows(UINT32 want, UINT64 sent, UINT64 recv)
{
    for (int i = 0; i < 400; i++)
    {
        g_n = ProxyBridge_GetFlows(g_f, PB_FLOWS_MAX);
        if (g_n == want && (want == 0 || (g_f[0].sent == sent && g_f[0].received == recv))) return TRUE;
        Sleep(10);
    }
    return FALSE;
}

int main(void)
{
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    running = TRUE;                                              /* relay_start() refuses to work on a stopped engine */
    CHECK(relay_pool_start());

    CHECK(ProxyBridge_GetFlows(NULL, 10) == 0);                  /* bad arguments are harmless */
    { PB_FLOW one; CHECK(ProxyBridge_GetFlows(&one, 0) == 0); }
    CHECK(wait_flows(0, 0, 0));

    /* app <-> [relay] <-> proxy, as two loopback pairs */
    SOCKET app, relayClient, relayProxy, proxy;
    CHECK(make_pair(&app, &relayClient) && make_pair(&relayProxy, &proxy));
    FLOW_META m; ZeroMemory(&m, sizeof m);
    m.pid = GetCurrentProcessId(); m.proxy_id = 9; m.rule_id = 17; m.port = 443; m.v6 = FALSE;
    UINT32 dest = 0x08080808u; memcpy(m.dest, &dest, 4);        /* 8.8.8.8 */
    CHECK(relay_start(relayClient, relayProxy, &m));

    CHECK(wait_flows(1, 0, 0));
    CHECK(g_n == 1 && g_f[0].pid == m.pid && g_f[0].proxy_config_id == 9 && g_f[0].rule_id == 17 && g_f[0].port == 443 && !g_f[0].is_udp && !g_f[0].is_ipv6);
    CHECK(strlen(g_f[0].name) > 0 && _stricmp(g_f[0].name, "test_flows.exe") == 0);        /* the process name, not the path */
    CHECK(!strcmp(g_f[0].host, "8.8.8.8"));                                                /* no domain known: the address */
    CHECK(g_f[0].age_ms != 0xFFFFFFFFu && g_f[0].id != 0);
    UINT64 id = g_f[0].id;

    /* bytes are forwarded and counted per direction */
    CHECK(send_n(app, 1000) && recv_n_bytes(proxy, 1000));
    CHECK(send_n(proxy, 250000) && recv_n_bytes(app, 250000));       /* more than one read, so the counter must add up */
    CHECK(wait_flows(1, 1000, 250000));
    CHECK(g_f[0].id == id && g_f[0].sent == 1000 && g_f[0].received == 250000);

    /* a second connection (IPv6 label) is listed newest first; the first one keeps its identity */
    SOCKET app2, rc2, rp2, px2;
    CHECK(make_pair(&app2, &rc2) && make_pair(&rp2, &px2));
    FLOW_META m2; ZeroMemory(&m2, sizeof m2); m2.pid = GetCurrentProcessId(); m2.proxy_id = 3; m2.port = 80; m2.v6 = TRUE; m2.dest[15] = 1;   /* ::1 */
    CHECK(relay_start(rc2, rp2, &m2));
    CHECK(wait_flows(2, 0, 0) || g_n == 2);
    CHECK(g_n == 2 && g_f[0].id != id && g_f[0].is_ipv6 && !strcmp(g_f[0].host, "::1") && g_f[1].id == id && g_f[1].sent == 1000);
    { PB_FLOW lim[1]; CHECK(ProxyBridge_GetFlows(lim, 1) == 1); }                          /* the caller's limit is respected */

    /* closing the app side ends the flow; the other one is untouched */
    closesocket(app);
    CHECK(wait_flows(1, 0, 0) || g_n == 1);
    CHECK(g_n == 1 && g_f[0].id != id);
    char c; CHECK(recv(proxy, &c, 1, 0) <= 0);                                              /* the proxy side saw the close too */
    closesocket(proxy);

    closesocket(app2);
    CHECK(wait_flows(0, 0, 0));
    for (int i = 0; i < 300 && g_active_relays > 0; i++) Sleep(10);
    CHECK(g_active_relays == 0);                                                            /* nothing leaked */
    closesocket(px2);

    relay_pool_stop();
    CHECK(relay_flows_snapshot(g_f, PB_FLOWS_MAX) == 0);
    running = FALSE;
    WSACleanup();
    return pbtest_done("test_flows");
}
