package com.interceptsuite.proxybridge.model;

import java.util.UUID;

public final class ProxyConfig {
    public final String id;
    public String name = "";
    public ProxyKind kind = ProxyKind.SOCKS5;
    public String host = "";
    public int port = 1080;
    public String username = "";
    public String password = "";
    /** Give the proxy the site's name instead of its IP address when the device looked the name up. */
    public boolean sendHostname = true;

    public ProxyConfig() {
        this(UUID.randomUUID().toString());
    }

    public ProxyConfig(String id) {
        this.id = id;
    }

    public ProxyConfig copy() {
        ProxyConfig copy = new ProxyConfig(id);
        copy.name = name;
        copy.kind = kind;
        copy.host = host;
        copy.port = port;
        copy.username = username;
        copy.password = password;
        copy.sendHostname = sendHostname;
        return copy;
    }

    public boolean hasCredentials() {
        return !username.isEmpty();
    }

    public String displayName() {
        return name.isEmpty() ? host + ":" + port : name;
    }
}
