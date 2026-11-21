package com.interceptsuite.proxybridge.router;

import com.interceptsuite.proxybridge.model.ProxyConfig;

final class Route {
    enum Type {
        DIRECT,
        BLOCK,
        PROXY
    }

    static final Route DIRECT = new Route(Type.DIRECT, null);
    static final Route BLOCK = new Route(Type.BLOCK, null);

    final Type type;
    final ProxyConfig proxy;

    private Route(Type type, ProxyConfig proxy) {
        this.type = type;
        this.proxy = proxy;
    }

    static Route via(ProxyConfig proxy) {
        return new Route(Type.PROXY, proxy);
    }
}
