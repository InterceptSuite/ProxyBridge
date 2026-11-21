package com.interceptsuite.proxybridge.vpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class UpstreamDns {
    private static final byte[] CLOUDFLARE = {1, 1, 1, 1};
    private static final byte[] GOOGLE = {8, 8, 8, 8};

    private UpstreamDns() {
    }

    /**
     * The DNS servers of the current network. Read before the tunnel is up, while the active network is still the
     * real one. If none can be found, public servers are used.
     */
    static List<InetAddress> servers(Context context) throws UnknownHostException {
        ConnectivityManager connectivity = context.getSystemService(ConnectivityManager.class);
        Network network = connectivity.getActiveNetwork();
        LinkProperties properties = network == null ? null : connectivity.getLinkProperties(network);
        List<InetAddress> servers = new ArrayList<>();
        if (properties != null) {
            servers.addAll(properties.getDnsServers());
        }
        if (servers.isEmpty()) {
            servers.addAll(Arrays.asList(InetAddress.getByAddress(CLOUDFLARE), InetAddress.getByAddress(GOOGLE)));
        }
        return servers;
    }
}
