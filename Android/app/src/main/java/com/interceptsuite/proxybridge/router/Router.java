package com.interceptsuite.proxybridge.router;

import com.interceptsuite.proxybridge.model.AppConfig;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The one place where rules are applied. hev turns every connection and UDP flow of the device into a SOCKS5 request to
 * this router, which sends it direct, through a proxy, or drops it.
 */
public final class Router implements Closeable {
    private static final int MAX_WORKERS = 256;

    private final DnsMap dnsMap = new DnsMap();
    private final List<InetAddress> dnsUpstreams;
    private final ExecutorService executor = new ThreadPoolExecutor(0, MAX_WORKERS, 20, TimeUnit.SECONDS,
            new SynchronousQueue<>(), new NamedThreads("router-worker"));
    private final RelayLoop relay = new RelayLoop();
    private final SocksServer server;
    private final UdpRelay udp;
    private volatile RuleEngine engine;

    /**
     * @param dnsUpstreams where the device's DNS queries are forwarded to, in order of preference
     */
    public Router(AppConfig config, List<InetAddress> dnsUpstreams) throws IOException {
        this.dnsUpstreams = new ArrayList<>(dnsUpstreams);
        engine = new RuleEngine(config);
        try {
            udp = new UdpRelay(this);
            server = new SocksServer(this);
        } catch (IOException e) {
            close();
            throw e;
        }
    }

    /** Starts the router and returns the TCP port that hev should connect to. */
    public int start() {
        new NamedThreads("router-relay").newThread(relay).start();
        new NamedThreads("router-udp").newThread(udp).start();
        new NamedThreads("router-accept").newThread(server).start();
        return server.port();
    }

    public void update(AppConfig config) {
        engine = new RuleEngine(config);
    }

    @Override
    public void close() {
        if (server != null) {
            server.close();
        }
        if (udp != null) {
            udp.close();
        }
        relay.close();
        executor.shutdownNow();
    }

    Route route(byte[] ip, int port, boolean udp) {
        return engine.route(ip, port, udp, dnsMap.domains(IpAddress.format(ip)));
    }

    DnsMap dnsMap() {
        return dnsMap;
    }

    List<InetAddress> dnsUpstreams() {
        return dnsUpstreams;
    }

    ExecutorService executor() {
        return executor;
    }

    RelayLoop relay() {
        return relay;
    }

    int udpPort() {
        return udp.port();
    }

    private static final class NamedThreads implements java.util.concurrent.ThreadFactory {
        private final String name;
        private final AtomicInteger count = new AtomicInteger();

        NamedThreads(String name) {
            this.name = name;
        }

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, name + "-" + count.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }
}
