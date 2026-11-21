package com.interceptsuite.proxybridge.model;

import java.util.UUID;

/** A rule describes a destination only: Android does not tell the tunnel which app made a connection. */
public final class ProxyRule {
    public final String id;
    public String name = "";
    /** Domains (wildcards allowed), IP addresses or CIDR blocks, separated by semicolons. Empty matches any host. */
    public String hosts = "";
    /** Ports and port ranges such as 8000-9000, separated by semicolons. Empty matches any port. */
    public String ports = "";
    public RuleProtocol protocol = RuleProtocol.ANY;
    public RuleAction action = RuleAction.PROXY;
    /** The proxy used when the action is PROXY. Null means the default proxy. */
    public String proxyId;
    public boolean enabled = true;

    public ProxyRule() {
        this(UUID.randomUUID().toString());
    }

    public ProxyRule(String id) {
        this.id = id;
    }

    public ProxyRule copy() {
        ProxyRule copy = new ProxyRule(id);
        copy.name = name;
        copy.hosts = hosts;
        copy.ports = ports;
        copy.protocol = protocol;
        copy.action = action;
        copy.proxyId = proxyId;
        copy.enabled = enabled;
        return copy;
    }
}
