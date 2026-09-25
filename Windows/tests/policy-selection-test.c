#include "pb_internal.h"
#include "../src/rules/pb_policy_selection.inc"

SRWLOCK g_rules_lock = SRWLOCK_INIT;
static RuleAction action = RULE_ACTION_PROXY;
static UINT32 rule_id = 17;
static PROXY_CONFIG definition;
static BOOL exists = TRUE;
static unsigned matches4, matches6, copies, lock_failures;

static void verify_reader_lock(void)
{
    if (TryAcquireSRWLockExclusive(&g_rules_lock)) {
        ++lock_failures;
        ReleaseSRWLockExclusive(&g_rules_lock);
    }
}
RuleAction match_rule_inner(const char *name, UINT32 ip, UINT16 port, BOOL udp, UINT32 *id)
{
    (void)name; (void)ip; (void)port; (void)udp;
    verify_reader_lock(); ++matches4; *id = rule_id; return action;
}
RuleAction match_rule_v6_inner(const char *name, const UINT8 ip[16], UINT16 port, BOOL udp, UINT32 *id)
{
    (void)name; (void)ip; (void)port; (void)udp;
    verify_reader_lock(); ++matches6; *id = rule_id; return action;
}
BOOL find_proxy_config_copy(UINT32 id, PROXY_CONFIG *out)
{
    verify_reader_lock(); ++copies;
    if (!exists || (id != 0 && id != definition.config_id)) return FALSE;
    *out = definition;
    return TRUE;
}
static DWORD WINAPI publish_profiles(LPVOID unused)
{
    (void)unused;
    for (unsigned i = 0; i < 20000; ++i) {
        AcquireSRWLockExclusive(&g_rules_lock);
        rule_id = 17 + (i & 1);
        definition.config_id = rule_id;
        ++definition.revision;
        ReleaseSRWLockExclusive(&g_rules_lock);
        if ((i & 31) == 0) SwitchToThread();
    }
    return 0;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    UINT32 id;
    BOOL available;
    UINT8 ip6[16] = {0};
    PROXY_CONFIG selected;
    definition.config_id = 17; definition.revision = 3;
    strcpy_s(definition.host, sizeof(definition.host), "old.example");
    CHECK(pb_select_proxy("app.exe", FALSE, 0, NULL, 443, FALSE, &id, &selected, &available) == RULE_ACTION_PROXY);
    CHECK(available && id == 17 && selected.revision == 3 && matches4 == 1 && copies == 1);
    // A later publication cannot mutate the settings handed to a TCP worker.
    CHECK(TryAcquireSRWLockExclusive(&g_rules_lock));
    definition.revision = 4;
    strcpy_s(definition.host, sizeof(definition.host), "new.example");
    ReleaseSRWLockExclusive(&g_rules_lock);
    CHECK(selected.revision == 3 && !strcmp(selected.host, "old.example"));
    CHECK(pb_select_proxy("app.exe", TRUE, 0, ip6, 53, TRUE, &id, &selected, &available) == RULE_ACTION_PROXY);
    CHECK(available && matches6 == 1 && selected.revision == 4);
    exists = FALSE;
    pb_select_proxy("app.exe", FALSE, 0, NULL, 443, FALSE, &id, &selected, &available);
    CHECK(!available && id == 17);
    exists = TRUE; action = RULE_ACTION_BLOCK;
    unsigned before = copies;
    CHECK(pb_select_proxy("app.exe", FALSE, 0, NULL, 443, FALSE, &id, &selected, &available) == RULE_ACTION_BLOCK);
    CHECK(!available && copies == before);
    // Unknown process retains default-proxy behavior, without calling the matcher.
    unsigned matched = matches4 + matches6;
    CHECK(pb_select_proxy(NULL, FALSE, 0, NULL, 443, FALSE, &id, &selected, &available) == RULE_ACTION_PROXY);
    CHECK(available && id == 0 && matches4 + matches6 == matched);
    // Existing redirected TCP DIRECT behavior still selects a proxy definition.
    action = RULE_ACTION_DIRECT; rule_id = 0;
    CHECK(pb_select_proxy("app.exe", FALSE, 0, NULL, 443, FALSE, &id, &selected, &available) == RULE_ACTION_DIRECT);
    CHECK(available && selected.config_id == 17 && lock_failures == 0);
    CHECK(TryAcquireSRWLockExclusive(&g_rules_lock));
    ReleaseSRWLockExclusive(&g_rules_lock);
    action = RULE_ACTION_PROXY; rule_id = definition.config_id;
    HANDLE publisher = CreateThread(NULL, 0, publish_profiles, NULL, 0, NULL);
    CHECK(publisher != NULL);
    for (unsigned i = 0; i < 20000; ++i) {
        CHECK(pb_select_proxy("app.exe", FALSE, 0, NULL, 443, TRUE, &id, &selected, &available) == RULE_ACTION_PROXY);
        CHECK(available && id == selected.config_id);
        if ((i & 31) == 0) SwitchToThread();
    }
    CHECK(WaitForSingleObject(publisher, 5000) == WAIT_OBJECT_0);
    CloseHandle(publisher);
    CHECK(lock_failures == 0);
    puts("PASS: IPv4/IPv6 selection, rule/copy lock coverage, detached snapshot, missing proxy, block, unknown process and direct compatibility");
    puts("PASS: 20000 selections concurrent with 20000 profile publications");
    return 0;
}
