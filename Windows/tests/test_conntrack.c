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
    add_connection(55123, TRUE, lanA, d1, 41001, 0);                                    /* UDP seed */
    CHECK(is_connection_tracked(55123, TRUE,  FALSE) == TRUE);
    CHECK(is_connection_tracked(55123, FALSE, FALSE) == FALSE);                         /* the TCP flow is NOT "already tracked" */
    CHECK(get_connection(55123, FALSE, &dip, &dport) == FALSE);                         /* and borrows no destination from the UDP flow */
    add_connection(55123, FALSE, lanA, d2, 41002, 0);
    CHECK(get_connection(55123, TRUE,  &dip, &dport) && dip == d1 && dport == 41001);   /* UDP entry untouched */
    CHECK(get_connection(55123, FALSE, &dip, &dport) && dip == d2 && dport == 41002);   /* TCP entry independent */
    remove_connection(55123, FALSE, FALSE);
    CHECK(is_connection_tracked(55123, TRUE, FALSE) && !is_connection_tracked(55123, FALSE, FALSE));   /* removing TCP keeps UDP */
    remove_connection(55123, TRUE, FALSE);
    CHECK(!is_connection_tracked(55123, TRUE, FALSE));

    /* 2. IPv4 and IPv6 on the same numeric port */
    UINT8 s6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    UINT8 dst6[16] = {0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
    add_connection(50000, FALSE, lanA, d1, 443, 0);
    CHECK(is_connection_tracked(50000, FALSE, FALSE) && !is_connection_tracked(50000, FALSE, TRUE));
    add_connection_v6(50000, FALSE, s6, dst6, 443, 0);
    CHECK(is_connection_tracked(50000, FALSE, TRUE) && is_connection_tracked(50000, FALSE, FALSE));
    remove_connection(50000, FALSE, TRUE);
    CHECK(is_connection_tracked(50000, FALSE, FALSE) && !is_connection_tracked(50000, FALSE, TRUE));
    remove_connection(50000, FALSE, FALSE);

    /* 3. KNOWN LIMITATION (not a failure): two local addresses using the same port and protocol share one entry,
          because the local address is stored but not part of the lookup key. Reported so a future fix shows up here. */
    add_connection(51000, FALSE, lanA, d1, 443, 0);
    add_connection(51000, FALSE, lanB, d2, 80, 0);
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

    return pbtest_done("test_conntrack");
}
