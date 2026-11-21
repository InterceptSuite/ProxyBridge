package com.interceptsuite.proxybridge.vpn;

import java.io.File;

/** The packet stack: hev-socks5-tunnel reads the tunnel device and sends every flow to the router as a SOCKS5 request. */
final class HevTunnel {
    static {
        System.loadLibrary("hev-socks5-tunnel");
    }

    private HevTunnel() {
    }

    static boolean start(File config, int tunnelFd) {
        return TProxyStartService(config.getAbsolutePath(), tunnelFd);
    }

    static void stop() {
        TProxyStopService();
    }

    // The names and signatures below are fixed by hev's JNI wrapper, which registers all four.
    private static native boolean TProxyStartService(String configPath, int fd);

    private static native boolean TProxyStopService();

    private static native boolean TProxyIsRunning();

    private static native long[] TProxyGetStats();
}
