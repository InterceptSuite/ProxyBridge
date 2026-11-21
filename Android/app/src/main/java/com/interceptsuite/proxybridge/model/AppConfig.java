package com.interceptsuite.proxybridge.model;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Everything the app edits and the tunnel reads. The first proxy is the default one. */
public final class AppConfig {
    public final List<ProxyConfig> proxies = new ArrayList<>();
    public final List<ProxyRule> rules = new ArrayList<>();
    public RuleAction defaultAction = RuleAction.DIRECT;
    public AppMode appMode = AppMode.ALL;
    public final Set<String> packages = new LinkedHashSet<>();

    public ProxyConfig proxy(String id) {
        for (ProxyConfig proxy : proxies) {
            if (proxy.id.equals(id)) {
                return proxy;
            }
        }
        return null;
    }

    /** Removes a proxy. A rule that pointed at it falls back to the default proxy. */
    public void removeProxy(String id) {
        proxies.removeIf(proxy -> proxy.id.equals(id));
        for (ProxyRule rule : rules) {
            if (id.equals(rule.proxyId)) {
                rule.proxyId = null;
            }
        }
    }

    public ProxyConfig defaultProxy() {
        return proxies.isEmpty() ? null : proxies.get(0);
    }
}
