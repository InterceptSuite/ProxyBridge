#define main engine_regression_main
#include "rule-engine-test.c"
#undef main
PROXY_CONFIG g_proxy_configs[MAX_PROXY_CONFIGS];
int g_proxy_config_count;
UINT32 g_next_config_id=1,g_next_rule_id=1;
volatile LONG64 g_proxy_revision;
SRWLOCK g_proxy_lock=SRWLOCK_INIT;
volatile BOOL running,g_has_active_rules;
BOOL g_localhost_via_proxy;
struct _PBDRV_WATCHLIST {int value;};
static BOOL acceptDriver=TRUE,changeDuringPreparation;
static unsigned applyCalls;
struct _PBDRV_WATCHLIST *pb_driver_prepare_rules(const PROCESS_RULE *rules){(void)rules;return calloc(1,sizeof(struct _PBDRV_WATCHLIST));}
BOOL pb_driver_apply_rules(const struct _PBDRV_WATCHLIST *watch){(void)watch;++applyCalls;if(!acceptDriver)SetLastError(ERROR_GEN_FAILURE);return acceptDriver;}
BOOL pb_driver_apply_profile_rules(const struct _PBDRV_WATCHLIST *watch,BOOL loopback){(void)loopback;return pb_driver_apply_rules(watch);}
BOOL pb_proxy_prepare_definition(const ProxyBridgeProxySpec *spec,PROXY_CONFIG *out){
    ZeroMemory(out,sizeof(*out));out->type=spec->type;out->port=spec->port;out->resolved_ip=1;
    strcpy_s(out->host,sizeof(out->host),spec->host);
    if(changeDuringPreparation)InterlockedIncrement64(&g_proxy_revision);return TRUE;
}
void flush_dns_resolver_cache(void){}
void log_message(const char *format,...){(void)format;}
int main(void){
    ProxyBridgeProxySpec config={PROXY_TYPE_SOCKS5,"proxy",1080,"","",FALSE};
    char process[32]="original.exe";
    ProxyBridgeRuleSpec rule={process,"*","*","*",RULE_PROTOCOL_BOTH,RULE_ACTION_PROXY,1,TRUE};
    UINT32 configId=999,ruleId=999;
    CHECK(pb_rules_begin_update()); // Preparation must work without taking the writer gate.
    void *handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,FALSE);CHECK(handle);
    pb_rules_end_update();strcpy_s(process,sizeof(process),"modified.exe");
    CHECK(ProxyBridge_CommitProfile(handle,&configId,&ruleId));
    CHECK(configId==1 && ruleId==1 && !strcmp(rules_list->process_name,"original.exe") && applyCalls==1);
    PROCESS_RULE *active=rules_list;UINT64 generation=g_rules_generation;
    handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,TRUE);CHECK(handle);
    CHECK(ProxyBridge_DisableRule(ruleId));unsigned calls=applyCalls;
    configId=ruleId=999;
    CHECK(!ProxyBridge_CommitProfile(handle,&configId,&ruleId) && GetLastError()==ERROR_REVISION_MISMATCH);
    CHECK(configId==999 && ruleId==999 && applyCalls==calls && !rules_list->enabled);
    active=rules_list;generation=g_rules_generation;
    changeDuringPreparation=TRUE;handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,TRUE);changeDuringPreparation=FALSE;
    CHECK(handle && !ProxyBridge_CommitProfile(handle,&configId,&ruleId) && GetLastError()==ERROR_REVISION_MISMATCH);
    CHECK(active==rules_list && generation==g_rules_generation && applyCalls==calls);
    handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,TRUE);CHECK(handle);acceptDriver=FALSE;
    CHECK(!ProxyBridge_CommitProfile(handle,&configId,&ruleId) && GetLastError()==ERROR_GEN_FAILURE);
    CHECK(configId==999 && ruleId==999 && active==rules_list && !g_localhost_via_proxy);acceptDriver=TRUE;
    handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,FALSE);CHECK(handle);CHECK(pb_rules_begin_update());
    CHECK(!ProxyBridge_CommitProfile(handle,&configId,&ruleId) && GetLastError()==ERROR_BUSY);pb_rules_end_update();
    handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,FALSE);CHECK(handle);
    CHECK(!ProxyBridge_CommitProfile(handle,NULL,&ruleId) && GetLastError()==ERROR_INVALID_PARAMETER);
    handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,FALSE);CHECK(handle);ProxyBridge_DiscardProfile(handle);ProxyBridge_DiscardProfile(NULL);
    g_next_rule_id=0;handle=ProxyBridge_PrepareProfile(&config,1,&rule,1,FALSE);CHECK(handle);
    CHECK(!ProxyBridge_CommitProfile(handle,&configId,&ruleId) && GetLastError()==ERROR_ARITHMETIC_OVERFLOW);g_next_rule_id=2;
    CHECK(ProxyBridge_ReplaceProfile(&config,1,&rule,1,&configId,&ruleId,TRUE) && configId==1 && ruleId==2 && g_localhost_via_proxy);
    CHECK(ProxyBridge_ReplaceProfile(NULL,0,NULL,0,NULL,NULL,FALSE) && !rules_list && !g_proxy_config_count);
    puts("PASS real prepared profile API: private inputs, writer-free preparation, stale rules/proxy, driver failure, busy gate, output validation, discard, ID exhaustion, compatibility wrapper");return 0;
}
