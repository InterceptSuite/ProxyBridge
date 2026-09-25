#define main engine_regression_main
#include "rule-engine-test.c"
#undef main
static DWORD WINAPI cache_writer(LPVOID unused)
{
    (void)unused;
    for (unsigned i = 0; i < 1000; ++i) {
        AcquireSRWLockExclusive(&g_rules_lock);
        rules_list->action = i & 1 ? RULE_ACTION_BLOCK : RULE_ACTION_PROXY;
        rules_list->proxy_config_id = i & 1 ? 11 : 22;
        ++g_rules_generation;
        ReleaseSRWLockExclusive(&g_rules_lock);
    }
    return 0;
}
static DWORD WINAPI cache_reader(LPVOID unused)
{
    (void)unused;
    for (unsigned i = 0; i < 10000; ++i) {
        UINT32 id;
        RuleAction action = match_rule("app.exe", htonl(0x08080808), 443, FALSE, &id);
        if (!((action == RULE_ACTION_BLOCK && id == 11) || (action == RULE_ACTION_PROXY && id == 22))) return 1;
    }
    return 0;
}
int main(void)
{
    CHECK(engine_regression_main() == 0);
    g_has_domain_rules = FALSE;
    for (unsigned count = 1; count <= 64; count *= 64) {
        ++g_rules_generation;
        PROCESS_RULE **tail = &rules_list;
        for (unsigned i = 0; i < count; ++i) {
            PROCESS_RULE source = {0};
            strcpy_s(source.process_name, sizeof(source.process_name), i+1 == count ? "app.exe" : "other.exe");
            source.target_hosts = source.target_ports = source.target_domains = "*";
            source.enabled = TRUE; source.protocol = RULE_PROTOCOL_BOTH; source.action = RULE_ACTION_PROXY; source.proxy_config_id = 22;
            *tail = copy_rule(&source); CHECK(*tail != NULL); tail = &(*tail)->next;
        }
        UINT32 id;
        CHECK(match_rule("app.exe", htonl(0x08080808), 443, FALSE, &id) == RULE_ACTION_PROXY && id == 22);
        LARGE_INTEGER frequency, start, middle, end;
        QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
        for (unsigned i = 0; i < 20000; ++i) {
            AcquireSRWLockShared(&g_rules_lock);
            RuleAction action = match_rule_uncached("app.exe", htonl(0x08080808), 443, FALSE, &id);
            ReleaseSRWLockShared(&g_rules_lock);
            CHECK(action == RULE_ACTION_PROXY && id == 22);
        }
        QueryPerformanceCounter(&middle);
        for (unsigned i = 0; i < 20000; ++i) CHECK(match_rule("app.exe", htonl(0x08080808), 443, FALSE, &id) == RULE_ACTION_PROXY && id == 22);
        QueryPerformanceCounter(&end);
        printf("rules=%u 20000-prepared-uncached-ms=%.3f cached-ms=%.3f\n", count, (middle.QuadPart-start.QuadPart)*1000.0/frequency.QuadPart, (end.QuadPart-middle.QuadPart)*1000.0/frequency.QuadPart);
        free_rules(rules_list); rules_list = NULL;
    }
    PROCESS_RULE source = {0};
    strcpy_s(source.process_name, sizeof(source.process_name), "app.exe");
    source.target_hosts = source.target_ports = source.target_domains = "*";
    source.enabled = TRUE; source.protocol = RULE_PROTOCOL_BOTH; source.action = RULE_ACTION_PROXY; source.proxy_config_id = 22;
    rules_list = copy_rule(&source); CHECK(rules_list != NULL); ++g_rules_generation;
    strcpy_s(source.process_name, sizeof(source.process_name), "other.exe");
    rules_list->next = copy_rule(&source); CHECK(rules_list->next != NULL);
    HANDLE threads[5];
    for (unsigned i = 0; i < 5; ++i) { threads[i] = CreateThread(NULL, 0, i == 4 ? cache_writer : cache_reader, NULL, 0, NULL); CHECK(threads[i] != NULL); }
    CHECK(WaitForMultipleObjects(5, threads, TRUE, 10000) == WAIT_OBJECT_0);
    for (unsigned i = 0; i < 5; ++i) { DWORD code; CHECK(GetExitCodeThread(threads[i], &code) && code == 0); CloseHandle(threads[i]); }
    free_rules(rules_list); rules_list = NULL; ++g_rules_generation;
    UINT32 id;
    CHECK(match_rule("app.exe", htonl(0x08080808), 443, FALSE, &id) == RULE_ACTION_DIRECT && id == 0);
    strcpy_s(source.process_name, sizeof(source.process_name), "app.exe");
    source.target_domains = "*.example.com";
    rules_list = copy_rule(&source); CHECK(rules_list != NULL);
    strcpy_s(source.process_name, sizeof(source.process_name), "*");
    source.target_domains = "*"; source.action = RULE_ACTION_BLOCK; source.proxy_config_id = 33;
    rules_list->next = copy_rule(&source); CHECK(rules_list->next != NULL);
    ++g_rules_generation; g_has_domain_rules = TRUE;
    known_domain = FALSE;
    CHECK(match_rule("app.exe", htonl(0x08080808), 443, FALSE, &id) == RULE_ACTION_BLOCK && id == 33);
    known_domain = TRUE;
    CHECK(match_rule("app.exe", htonl(0x08080808), 443, FALSE, &id) == RULE_ACTION_PROXY && id == 22);
    known_domain = FALSE;
    CHECK(match_rule("app.exe", htonl(0x08080808), 443, FALSE, &id) == RULE_ACTION_BLOCK && id == 33);
    for (unsigned i = 0; i < PB_RULE_CACHE_SIZE; ++i) CHECK(!rule_cache[i].valid || rule_cache[i].generation != g_rules_generation);
    free_rules(rules_list); rules_list = NULL; ++g_rules_generation;
    puts("PASS: domain appearance/expiry bypasses decision cache");
    printf("PASS: concurrent 40000 reads + 1000 generations, deletion invalidation; cache bytes=%zu\n", sizeof(rule_cache));
    return 0;
}
