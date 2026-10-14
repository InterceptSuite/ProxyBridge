// hostile-input test of the rules json parser/writer (gui_json.c)
#include "gui.h"

void free_rule_data(RuleData *r) {
    g_free(r->process_name); g_free(r->target_hosts); g_free(r->target_ports); g_free(r->proxy_name); g_free(r);
}

static int failures = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

typedef struct { int n, named, disabled; RuleAction last_action; RuleProtocol last_proto; size_t max_len; } Stats;

static void cb(const RuleData *r, int index, void *ud) {
    Stats *s = (Stats *)ud;
    s->n++;
    if (r->process_name) {
        s->named++;
        if (strlen(r->process_name) > s->max_len) s->max_len = strlen(r->process_name);
    }
    if (!r->enabled) s->disabled++;
    s->last_action = r->action;
    s->last_proto = r->protocol;
}

static Stats parse(const char *json) {
    Stats s = {0};
    rules_from_json(json, cb, &s);
    return s;
}

int main() {
    Stats s = parse("[{\"processNames\":\"a\",\"action\":\"DIRECT\",\"protocol\":\"udp\",\"enabled\":false}]");
    CHECK(s.n == 1 && s.named == 1 && s.disabled == 1 && s.last_action == RULE_ACTION_DIRECT && s.last_proto == RULE_PROTOCOL_UDP);

    // macOS style: proxy uuid as action, ruleProtocol/ruleAction keys
    s = parse("{\"processNames\":\"a\",\"ruleAction\":\"6F1C-uuid\",\"ruleProtocol\":\"TCP\"}");
    CHECK(s.n == 1 && s.last_action == RULE_ACTION_PROXY && s.last_proto == RULE_PROTOCOL_TCP && s.disabled == 0);

    // hostile small inputs must not crash
    const char *bad[] = {"", "{", "}", "{{{{", "{\"processNames\":", "{\"processNames\":\"unterminated", "{\"processNames\":5}",
                         "{\"processNames\":null,\"enabled\":\"yes\"}", "{\"a\":\"}\"}", "[{\"processNames\":\"x\\", "{\"processNames\":\"x\\\"}", NULL};
    for (int i = 0; bad[i]; i++) parse(bad[i]);
    s = parse("{\"processNames\":\"a}b\"}");
    CHECK(s.n == 1 && s.max_len == 3);
    s = parse("{\"processNames\":5}");
    CHECK(s.n == 1 && s.named == 0);

    // huge string
    size_t big = 20 * 1024 * 1024;
    char *json = g_malloc(big + 64);
    strcpy(json, "[{\"processNames\":\"");
    memset(json + strlen(json), 'A', big);
    strcpy(json + 18 + big, "\"}]");
    s = parse(json);
    CHECK(s.n == 1 && s.max_len == big);
    g_free(json);

    GString *deep = g_string_new("");
    for (int i = 0; i < 1000000; i++) g_string_append_c(deep, '{');
    parse(deep->str);
    g_string_free(deep, TRUE);

    // 100k rules round trip through the writer
    GList *rules = NULL;
    for (int i = 0; i < 100000; i++) {
        RuleData *r = g_malloc0(sizeof(RuleData));
        r->process_name = g_strdup_printf("proc\"%d\\", i);
        r->target_hosts = g_strdup("*.example.com;10.0.0.0/8");
        r->target_ports = g_strdup("80;443");
        r->protocol = i % 3; r->action = i % 3; r->enabled = i % 2;
        r->proxy_name = i % 3 == 0 ? g_strdup("px") : NULL;
        r->selected = true;
        rules = g_list_append(rules, r);
    }
    char *out = rules_to_json(rules, true);
    s = parse(out);
    CHECK(s.n == 100000 && s.named == 100000 && s.disabled == 50000);
    g_free(out);
    g_list_free_full(rules, (GDestroyNotify)free_rule_data);

    if (!failures) printf("json_test: all passed\n");
    return failures ? 1 : 0;
}
