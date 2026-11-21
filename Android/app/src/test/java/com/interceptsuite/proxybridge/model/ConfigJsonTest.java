package com.interceptsuite.proxybridge.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ConfigJsonTest {
    @Test
    public void roundTrip() {
        AppConfig config = new AppConfig();
        ProxyConfig proxy = new ProxyConfig("p1");
        proxy.name = "Burp";
        proxy.kind = ProxyKind.HTTP;
        proxy.host = "192.168.1.5";
        proxy.port = 8080;
        proxy.username = "user";
        proxy.password = "secret";
        proxy.sendHostname = false;
        config.proxies.add(proxy);
        ProxyRule rule = new ProxyRule("r1");
        rule.name = "Block ads";
        rule.hosts = "*.ads.example.com";
        rule.ports = "443";
        rule.protocol = RuleProtocol.TCP;
        rule.action = RuleAction.BLOCK;
        rule.enabled = false;
        config.rules.add(rule);
        config.defaultAction = RuleAction.PROXY;
        config.appMode = AppMode.ONLY_SELECTED;
        config.packages.add("com.example.app");

        AppConfig read = ConfigJson.fromJson(ConfigJson.toJson(config));

        assertEquals(1, read.proxies.size());
        ProxyConfig p = read.proxies.get(0);
        assertEquals("p1", p.id);
        assertEquals(ProxyKind.HTTP, p.kind);
        assertEquals("192.168.1.5", p.host);
        assertEquals(8080, p.port);
        assertEquals("secret", p.password);
        assertEquals(false, p.sendHostname);
        ProxyRule r = read.rules.get(0);
        assertEquals(RuleAction.BLOCK, r.action);
        assertEquals(RuleProtocol.TCP, r.protocol);
        assertEquals(false, r.enabled);
        assertEquals(RuleAction.PROXY, read.defaultAction);
        assertEquals(AppMode.ONLY_SELECTED, read.appMode);
        assertTrue(read.packages.contains("com.example.app"));
    }

    @Test
    public void emptyOrBrokenInputGivesDefaults() {
        assertTrue(ConfigJson.fromJson("").proxies.isEmpty());
        assertTrue(ConfigJson.fromJson("{not json").rules.isEmpty());
        assertEquals(AppMode.ALL, ConfigJson.fromJson("{}").appMode);
    }

    @Test
    public void removingProxyClearsRuleReferences() {
        AppConfig config = new AppConfig();
        config.proxies.add(new ProxyConfig("p1"));
        ProxyRule rule = new ProxyRule("r1");
        rule.proxyId = "p1";
        config.rules.add(rule);
        config.removeProxy("p1");
        assertTrue(config.proxies.isEmpty());
        assertEquals(null, config.rules.get(0).proxyId);
    }
}
