package com.interceptsuite.proxybridge.router;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.ProxyConfig;
import com.interceptsuite.proxybridge.model.ProxyRule;
import com.interceptsuite.proxybridge.model.RuleAction;
import com.interceptsuite.proxybridge.model.RuleProtocol;

import java.util.Collections;
import java.util.List;

import org.junit.Test;

public class RuleEngineTest {
    private final ProxyConfig first = new ProxyConfig("first");
    private final ProxyConfig second = new ProxyConfig("second");
    private final AppConfig config = new AppConfig();

    public RuleEngineTest() {
        config.proxies.add(first);
        config.proxies.add(second);
    }

    private ProxyRule rule(String hosts, String ports, RuleProtocol protocol, RuleAction action, String proxyId) {
        ProxyRule rule = new ProxyRule();
        rule.hosts = hosts;
        rule.ports = ports;
        rule.protocol = protocol;
        rule.action = action;
        rule.proxyId = proxyId;
        config.rules.add(rule);
        return rule;
    }

    private Route route(String ip, int port, boolean udp, String... domains) {
        return new RuleEngine(config).route(IpAddress.parse(ip), port, udp, List.of(domains));
    }

    @Test
    public void defaultActionAppliesWithoutRules() {
        assertSame(Route.DIRECT, route("1.2.3.4", 80, false));
        config.defaultAction = RuleAction.BLOCK;
        assertSame(Route.BLOCK, route("1.2.3.4", 80, false));
    }

    @Test
    public void firstMatchingRuleWins() {
        rule("10.0.0.0/8", "", RuleProtocol.ANY, RuleAction.BLOCK, null);
        rule("*", "", RuleProtocol.ANY, RuleAction.PROXY, "second");
        assertSame(Route.BLOCK, route("10.1.2.3", 80, false));
        assertEquals(second.id, route("8.8.8.8", 80, false).proxy.id);
    }

    @Test
    public void disabledRulesAreSkipped() {
        rule("*", "", RuleProtocol.ANY, RuleAction.BLOCK, null).enabled = false;
        assertSame(Route.DIRECT, route("8.8.8.8", 80, false));
    }

    @Test
    public void portsAndRanges() {
        rule("*", "80;8000-8100", RuleProtocol.ANY, RuleAction.BLOCK, null);
        assertSame(Route.BLOCK, route("8.8.8.8", 80, false));
        assertSame(Route.BLOCK, route("8.8.8.8", 8050, false));
        assertSame(Route.DIRECT, route("8.8.8.8", 443, false));
    }

    @Test
    public void protocolIsMatched() {
        rule("*", "", RuleProtocol.UDP, RuleAction.BLOCK, null);
        assertSame(Route.BLOCK, route("8.8.8.8", 443, true));
        assertSame(Route.DIRECT, route("8.8.8.8", 443, false));
    }

    @Test
    public void domainWildcardMatchesSubdomainsAndApex() {
        rule("*.example.com", "", RuleProtocol.ANY, RuleAction.BLOCK, null);
        assertSame(Route.BLOCK, route("1.1.1.1", 443, false, "api.example.com"));
        assertSame(Route.BLOCK, route("1.1.1.1", 443, false, "example.com"));
        assertSame(Route.DIRECT, route("1.1.1.1", 443, false, "example.org"));
        assertSame(Route.DIRECT, route("1.1.1.1", 443, false));
    }

    @Test
    public void ipv6Cidr() {
        rule("fd00::/8", "", RuleProtocol.ANY, RuleAction.BLOCK, null);
        assertSame(Route.BLOCK, route("fd12::1", 80, false));
        assertSame(Route.DIRECT, route("2001:db8::1", 80, false));
    }

    @Test
    public void unknownProxyFallsBackToFirst() {
        rule("*", "", RuleProtocol.ANY, RuleAction.PROXY, "gone");
        assertEquals(first.id, route("8.8.8.8", 80, false).proxy.id);
    }

    @Test
    public void proxyActionWithoutProxiesIsDirect() {
        config.proxies.clear();
        rule("*", "", RuleProtocol.ANY, RuleAction.PROXY, null);
        assertEquals(Route.Type.DIRECT, route("8.8.8.8", 80, false).type);
    }

    @Test
    public void emptyDomainListNeverMatchesDomainRule() {
        rule("example.com", "", RuleProtocol.ANY, RuleAction.BLOCK, null);
        assertSame(Route.DIRECT, new RuleEngine(config).route(IpAddress.parse("1.1.1.1"), 80, false, Collections.emptyList()));
    }
}
