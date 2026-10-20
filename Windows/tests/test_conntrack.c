// test_conntrack.c - the connection table (src\pb_conntrack.c) and the Connections-log rules.
//   - issue #209: a TCP flow and a UDP flow (or IPv4 and IPv6) on the same local port are separate entries
//   - "Log every connection": default de-duplication, every TCP connection, one row per UDP flow
// Linked from the real core sources; no driver is opened.
#include "pb_internal.h"
#include "pbtest.h"

static UINT32 ip4(const char* s) { struct in_addr a; inet_pton(AF_INET, s, &a); return a.S_un.S_addr; }

int main(void)
{
    UINT32 d1 = ip4("193.124.56.249"), d2 = ip4("8.8.8.8"), lanA = ip4("192.168.0.136"), lanB = ip4("10.8.0.5");
    UINT32 dip; UINT16 dport;

    /* 1. the reported case: a UDP flow on local port 55123 exists; a fresh TCP SYN uses the same numeric port */
    add_connection(55123, TRUE, lanA, d1, 41001, 0, 4242, 0);                                    /* UDP seed */
    CHECK(is_connection_tracked(55123, TRUE,  FALSE) == TRUE);
    CHECK(is_connection_tracked(55123, FALSE, FALSE) == FALSE);                         /* the TCP flow is NOT "already tracked" */
    CHECK(get_connection(55123, FALSE, &dip, &dport) == FALSE);                         /* and borrows no destination from the UDP flow */
    add_connection(55123, FALSE, lanA, d2, 41002, 0, 4242, 0);
    CHECK(get_connection(55123, TRUE,  &dip, &dport) && dip == d1 && dport == 41001);   /* UDP entry untouched */
    CHECK(get_connection(55123, FALSE, &dip, &dport) && dip == d2 && dport == 41002);   /* TCP entry independent */
    remove_connection(55123, FALSE, FALSE);
    CHECK(is_connection_tracked(55123, TRUE, FALSE) && !is_connection_tracked(55123, FALSE, FALSE));   /* removing TCP keeps UDP */
    remove_connection(55123, TRUE, FALSE);
    CHECK(!is_connection_tracked(55123, TRUE, FALSE));

    /* 2. IPv4 and IPv6 on the same numeric port */
    UINT8 s6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    UINT8 dst6[16] = {0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
    add_connection(50000, FALSE, lanA, d1, 443, 0, 4242, 0);
    CHECK(is_connection_tracked(50000, FALSE, FALSE) && !is_connection_tracked(50000, FALSE, TRUE));
    add_connection_v6(50000, FALSE, s6, dst6, 443, 0, 4242, 0);
    CHECK(is_connection_tracked(50000, FALSE, TRUE) && is_connection_tracked(50000, FALSE, FALSE));
    remove_connection(50000, FALSE, TRUE);
    CHECK(is_connection_tracked(50000, FALSE, FALSE) && !is_connection_tracked(50000, FALSE, TRUE));
    remove_connection(50000, FALSE, FALSE);

    /* 3. KNOWN LIMITATION (not a failure): two local addresses using the same port and protocol share one entry,
          because the local address is stored but not part of the lookup key. Reported so a future fix shows up here. */
    add_connection(51000, FALSE, lanA, d1, 443, 0, 4242, 0);
    add_connection(51000, FALSE, lanB, d2, 80, 0, 4242, 0);
    { UINT32 gd; UINT16 gp; BOOL ok = get_connection(51000, FALSE, &gd, &gp);
      printf("  note: multi-IP, same port+protocol: second flow %s the first\n", (ok && gd == d2) ? "OVERWROTE (known limitation)" : "kept separate from"); }
    remove_connection(51000, FALSE, FALSE);

    /* 4. Connections log: default = one row per (process, destination, port, action) */
    CHECK(g_log_every_connection == FALSE);
    CHECK(connection_log_wanted(100, d1, 443, 50001, FALSE, RULE_ACTION_DIRECT) == TRUE);
    add_logged_connection(100, d1, 443, RULE_ACTION_DIRECT);
    CHECK(connection_log_wanted(100, d1, 443, 50002, FALSE, RULE_ACTION_DIRECT) == FALSE);   /* same process+dest+port+action: skipped */
    CHECK(connection_log_wanted(100, d1, 443, 50003, FALSE, RULE_ACTION_PROXY) == TRUE);     /* different action: logged */
    CHECK(connection_log_wanted(101, d1, 443, 50004, FALSE, RULE_ACTION_DIRECT) == TRUE);    /* different process: logged */

    /* 5. Log every connection: every new TCP connection, one row per UDP flow */
    ProxyBridge_SetLogEveryConnection(TRUE);
    CHECK(g_log_every_connection == TRUE);
    for (int i = 0; i < 50; i++)
    {
        CHECK(connection_log_wanted(100, d1, 443, (UINT16)(51000 + i), FALSE, RULE_ACTION_DIRECT) == TRUE);
        add_logged_connection(100, d1, 443, RULE_ACTION_DIRECT);
    }
    CHECK(connection_log_wanted(100, d1, 443, 51000, FALSE, RULE_ACTION_DIRECT) == TRUE);    /* same TCP tuple again = a new connection: logged */
    CHECK(connection_log_wanted(100, d1, 53, 52000, TRUE, RULE_ACTION_DIRECT) == TRUE);      /* new UDP flow */
    CHECK(connection_log_wanted(100, d1, 53, 52000, TRUE, RULE_ACTION_DIRECT) == FALSE);     /* same flow again: not re-logged */
    CHECK(connection_log_wanted(100, d1, 53, 52000, TRUE, RULE_ACTION_DIRECT) == FALSE);     /* a repeating (e.g. blocked) sender does not flood */
    CHECK(connection_log_wanted(100, d1, 53, 52001, TRUE, RULE_ACTION_DIRECT) == TRUE);      /* other local port = another flow */
    CHECK(connection_log_wanted(100, d1, 54, 52000, TRUE, RULE_ACTION_DIRECT) == TRUE);      /* other destination port */
    CHECK(connection_log_wanted(100, d1, 53, 52000, TRUE, RULE_ACTION_BLOCK) == TRUE);       /* other action = new row */
    CHECK(connection_log_wanted(102, d1, 53, 52000, TRUE, RULE_ACTION_DIRECT) == TRUE);      /* other process */
    int logged = 0;                                                                           /* many flows: the table recycles, never crashes */
    for (int i = 0; i < 5000; i++) logged += connection_log_wanted(200, (UINT32)i, 443, (UINT16)(10000 + (i % 40000)), TRUE, RULE_ACTION_DIRECT) ? 1 : 0;
    CHECK(logged == 5000);

    /* 6. back to the default: de-duplication works again from a clean slate */
    ProxyBridge_SetLogEveryConnection(FALSE);
    CHECK(connection_log_wanted(300, d1, 443, 1, FALSE, RULE_ACTION_DIRECT) == TRUE);
    add_logged_connection(300, d1, 443, RULE_ACTION_DIRECT);
    CHECK(connection_log_wanted(300, d1, 443, 2, FALSE, RULE_ACTION_DIRECT) == FALSE);

    /* 7. live connections: proxied UDP flows, their owner and byte counters */
    { PB_FLOW f[PB_FLOWS_MAX];
      UINT8 d6[16] = {0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
      CHECK(udp_flows_snapshot(f, PB_FLOWS_MAX) == 0);                                       /* nothing tracked yet */
      add_connection(60001, TRUE, lanA, d1, 3478, 5, 1111, 31);                                  /* proxied UDP flow, owner pid 1111 */
      add_connection(60002, FALSE, lanA, d2, 443, 5, 2222, 32);                                  /* TCP is shown by the relay, not from here */
      add_connection_v6(60003, TRUE, s6, d6, 443, 6, 3333, 33);
      CHECK(udp_flows_snapshot(f, PB_FLOWS_MAX) == 2);
      int v4 = -1, v6 = -1; for (int i = 0; i < 2; i++) { if (f[i].is_ipv6) v6 = i; else v4 = i; }
      CHECK(v4 >= 0 && v6 >= 0);
      if (v4 >= 0) CHECK(f[v4].is_udp && f[v4].pid == 1111 && f[v4].proxy_config_id == 5 && f[v4].rule_id == 31 && f[v4].port == 3478 && memcmp(f[v4].dest, &d1, 4) == 0 && f[v4].sent == 0 && f[v4].received == 0 && f[v4].age_ms == 0xFFFFFFFFu);
      if (v6 >= 0) CHECK(f[v6].rule_id == 33 && f[v6].pid == 3333 && f[v6].port == 443 && memcmp(f[v6].dest, d6, 16) == 0 && f[v6].id != f[v4].id);
      UINT64 id4 = f[v4].id;

      UINT32 xd; UINT16 xp; UINT32 cfg = 0, rule = 0; DWORD pid = 0;                                    /* app -> proxy: counted by the lookup the relay already does */
      CHECK(get_connection_full_x(60001, TRUE, &xd, &xp, &cfg, &pid, &rule, 1200) && xd == d1 && xp == 3478 && cfg == 5 && pid == 1111 && rule == 31);
      CHECK(get_connection_full_x(60001, TRUE, &xd, &xp, &cfg, &pid, &rule, 300));
      UINT8 dd6[16]; CHECK(get_connection_full_v6_x(60003, TRUE, dd6, &xp, &cfg, &pid, &rule, 77) && pid == 3333);
      UINT8 sr[16]; UINT16 sp;                                                                 /* proxy -> app on IPv6 */
      CHECK(find_v6_udp_sender(d6, 443, sr, &sp, 5000) && sp == 60003);
      CHECK(udp_flows_snapshot(f, PB_FLOWS_MAX) == 2);
      for (int i = 0; i < 2; i++)
      {
          if (!f[i].is_ipv6) CHECK(f[i].id == id4 && f[i].sent == 1500 && f[i].received == 0);
          else               CHECK(f[i].sent == 77 && f[i].received == 5000);
      }
      CHECK(get_connection_full(60001, TRUE, &xd, &xp, &cfg) && xd == d1);                    /* the old entry point still works and counts nothing */
      CHECK(udp_flows_snapshot(f, 1) == 1);                                                   /* the caller's limit is respected */
      CHECK(udp_flows_snapshot(f, 0) == 0);
      remove_connection(60001, TRUE, FALSE); remove_connection(60002, FALSE, FALSE); remove_connection(60003, TRUE, TRUE);
      CHECK(udp_flows_snapshot(f, PB_FLOWS_MAX) == 0); }

    /* a flow that has been silent for longer than the live window is no longer listed */
    { PB_FLOW f[4];
      add_connection(60010, TRUE, lanA, d1, 53, 0, 1, 0);
      CHECK(udp_flows_snapshot(f, 4) == 1);
      AcquireSRWLockExclusive(&lock);
      for (CONNECTION_INFO* c = connection_hash_table[60010 % CONNECTION_HASH_SIZE]; c; c = c->next)
          if (c->src_port == 60010) c->last_activity = GetTickCount64() - (UDP_FLOW_LIVE_MS + 5000);
      ReleaseSRWLockExclusive(&lock);
      CHECK(udp_flows_snapshot(f, 4) == 0);
      remove_connection(60010, TRUE, FALSE); }

    return pbtest_done("test_conntrack");
}
