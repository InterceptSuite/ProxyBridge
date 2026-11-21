package com.interceptsuite.proxybridge.router;

/** Addresses of the virtual interface. Queries sent to the DNS address are answered by the router, not by a server. */
public final class TunnelNetwork {
    public static final String ADDRESS = "10.64.0.2";
    public static final int PREFIX_LENGTH = 24;
    public static final String ADDRESS_V6 = "fd00::2";
    public static final int PREFIX_LENGTH_V6 = 64;
    public static final String DNS_SERVER = "10.64.0.1";
    public static final int MTU = 1500;

    private TunnelNetwork() {
    }
}
