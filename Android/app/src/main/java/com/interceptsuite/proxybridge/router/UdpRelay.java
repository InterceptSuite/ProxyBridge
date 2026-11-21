package com.interceptsuite.proxybridge.router;

import com.interceptsuite.proxybridge.model.ProxyConfig;
import com.interceptsuite.proxybridge.model.ProxyKind;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Receives the datagrams hev wraps in SOCKS5 UDP framing, applies the rules and sends each one direct or through a
 * proxy. Replies go back to hev in the same framing. DNS is always answered here, so the names can be remembered
 * for domain rules. Everything runs on one thread, so none of the state needs a lock.
 */
final class UdpRelay implements Runnable, Closeable {
    private static final int DNS_PORT = 53;
    private static final long DNS_TIMEOUT_MS = 2_000;
    private static final long DNS_POLL_MS = 250;
    private static final long IDLE_LIMIT_MS = 60_000;
    private static final long SWEEP_MS = 15_000;
    private static final int SETUP_TIMEOUT_MS = 10_000;
    private static final int MAX_QUEUED = 64;
    private static final int MAX_DATAGRAM = 65_535;
    private static final byte[] LOOPBACK = {127, 0, 0, 1};
    private static final byte[] TUNNEL_DNS = IpAddress.parse(TunnelNetwork.DNS_SERVER);

    private interface Handler {
        void onReadable();
    }

    private final Router router;
    private final Selector selector = Selector.open();
    private final DatagramChannel hev = DatagramChannel.open();
    private final ByteBuffer buffer = ByteBuffer.allocateDirect(MAX_DATAGRAM + 64);
    private final Map<SessionKey, Session> sessions = new HashMap<>();
    private final List<DnsQuery> queries = new ArrayList<>();
    private final Queue<Runnable> tasks = new ConcurrentLinkedQueue<>();
    private volatile boolean running = true;
    private long nextSweep = now() + SWEEP_MS;

    UdpRelay(Router router) throws IOException {
        this.router = router;
        hev.bind(new InetSocketAddress(InetAddress.getByAddress(LOOPBACK), 0));
        hev.configureBlocking(false);
        hev.register(selector, SelectionKey.OP_READ, (Handler) this::onHevDatagram);
    }

    int port() {
        try {
            return ((InetSocketAddress) hev.getLocalAddress()).getPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void run() {
        while (running) {
            try {
                selector.select(queries.isEmpty() ? SWEEP_MS : DNS_POLL_MS);
            } catch (IOException e) {
                break;
            }
            for (Runnable task = tasks.poll(); task != null; task = tasks.poll()) {
                task.run();
            }
            Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove();
                if (key.isValid()) {
                    ((Handler) key.attachment()).onReadable();
                }
            }
            long now = now();
            expireQueries(now);
            if (now >= nextSweep) {
                closeIdle(now);
                nextSweep = now + SWEEP_MS;
            }
        }
        for (Session session : new ArrayList<>(sessions.values())) {
            session.close();
        }
        for (DnsQuery query : new ArrayList<>(queries)) {
            query.close();
        }
        ProxyConnector.close(hev);
        ProxyConnector.close(selector);
    }

    @Override
    public void close() {
        running = false;
        selector.wakeup();
    }

    private void post(Runnable task) {
        tasks.add(task);
        selector.wakeup();
    }

    // datagrams from hev

    private void onHevDatagram() {
        try {
            while (true) {
                Buffers.clear(buffer);
                SocketAddress source = hev.receive(buffer);
                if (source == null) {
                    return;
                }
                Buffers.flip(buffer);
                Socks5.Datagram datagram = Socks5.parseDatagram(buffer);
                if (datagram != null) {
                    dispatch(source, datagram);
                }
            }
        } catch (IOException e) {
            // a failed receive loses one datagram, UDP callers retry
        }
    }

    private void dispatch(SocketAddress source, Socks5.Datagram datagram) throws IOException {
        if (datagram.port == DNS_PORT) {
            resolve(source, datagram);
            return;
        }
        Route route = router.route(datagram.ip, datagram.port, true);
        if (route.type == Route.Type.BLOCK) {
            return;
        }
        // an HTTP proxy cannot carry UDP, so that traffic goes direct
        if (route.type == Route.Type.PROXY && route.proxy.kind == ProxyKind.SOCKS5) {
            session(source, "proxy:" + route.proxy.id, () -> new ProxySession(source, route.proxy))
                    .send(datagram.ip, datagram.port, buffer);
        } else {
            session(source, "direct:" + IpAddress.format(datagram.ip) + ":" + datagram.port,
                    () -> new DirectSession(source, datagram.ip, datagram.port))
                    .send(datagram.ip, datagram.port, buffer);
        }
    }

    private interface SessionFactory {
        Session create() throws IOException;
    }

    private Session session(SocketAddress source, String target, SessionFactory factory) throws IOException {
        SessionKey key = new SessionKey(source, target);
        Session session = sessions.get(key);
        if (session == null) {
            session = factory.create();
            session.key = key;
            sessions.put(key, session);
        }
        session.lastUsed = now();
        return session;
    }

    private void closeIdle(long now) {
        for (Session session : new ArrayList<>(sessions.values())) {
            if (now - session.lastUsed > IDLE_LIMIT_MS) {
                session.close();
            }
        }
    }

    /** Sends the datagram in the buffer, which already starts with a SOCKS5 UDP header, back to hev. */
    private void replyToHev(SocketAddress source) {
        try {
            Buffers.flip(buffer);
            hev.send(buffer, source);
        } catch (IOException e) {
            // the reply is lost, the caller retries
        }
    }

    private static long now() {
        return System.nanoTime() / 1_000_000;
    }

    private static final class SessionKey {
        private final SocketAddress source;
        private final String target;

        SessionKey(SocketAddress source, String target) {
            this.source = source;
            this.target = target;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof SessionKey && ((SessionKey) other).source.equals(source)
                    && ((SessionKey) other).target.equals(target);
        }

        @Override
        public int hashCode() {
            return Objects.hash(source, target);
        }
    }

    private abstract class Session {
        SessionKey key;
        long lastUsed = now();

        /** Sends the payload remaining in the buffer to the destination. */
        abstract void send(byte[] ip, int port, ByteBuffer payload) throws IOException;

        abstract void closeChannels();

        void close() {
            sessions.remove(key);
            closeChannels();
        }
    }

    /** A UDP flow that leaves directly, from one local socket per destination. */
    private final class DirectSession extends Session implements Handler {
        private final DatagramChannel channel = DatagramChannel.open();
        private final SocketAddress source;
        private final byte[] ip;
        private final int port;

        DirectSession(SocketAddress source, byte[] ip, int port) throws IOException {
            this.source = source;
            this.ip = ip;
            this.port = port;
            try {
                channel.configureBlocking(false);
                channel.connect(new InetSocketAddress(InetAddress.getByAddress(ip), port));
                channel.register(selector, SelectionKey.OP_READ, this);
            } catch (IOException e) {
                closeChannels();
                throw e;
            }
        }

        @Override
        void send(byte[] ip, int port, ByteBuffer payload) throws IOException {
            channel.write(payload);
        }

        @Override
        public void onReadable() {
            try {
                while (true) {
                    Buffers.clear(buffer);
                    Socks5.writeHeader(buffer, ip, port);
                    if (channel.read(buffer) <= 0) {
                        return;
                    }
                    lastUsed = now();
                    replyToHev(source);
                }
            } catch (IOException e) {
                close();
            }
        }

        @Override
        void closeChannels() {
            ProxyConnector.close(channel);
        }
    }

    /** A UDP flow through a SOCKS5 proxy, which relays datagrams for any destination once it has set one up. */
    private final class ProxySession extends Session {
        private final SocketAddress source;
        private final ProxyConfig proxy;
        private final List<byte[]> queued = new ArrayList<>();
        private SocketChannel control;
        private DatagramChannel relay;
        private boolean closed;

        ProxySession(SocketAddress source, ProxyConfig proxy) {
            this.source = source;
            this.proxy = proxy.copy();
            router.executor().execute(this::connect);
        }

        /** Runs on a worker thread: the TCP part of the setup blocks. */
        private void connect() {
            try {
                ProxyConnector.Association association = ProxyConnector.associate(proxy, SETUP_TIMEOUT_MS);
                post(() -> ready(association));
            } catch (IOException | RuntimeException e) {
                post(this::close);
            }
        }

        private void ready(ProxyConnector.Association association) {
            control = association.control;
            if (closed) {
                closeChannels();
                return;
            }
            try {
                relay = DatagramChannel.open();
                relay.configureBlocking(false);
                relay.connect(association.relay);
                relay.register(selector, SelectionKey.OP_READ, (Handler) this::onRelayReadable);
                control.configureBlocking(false);
                control.register(selector, SelectionKey.OP_READ, (Handler) this::onControlReadable);
                for (byte[] packet : queued) {
                    relay.write(ByteBuffer.wrap(packet));
                }
                queued.clear();
            } catch (IOException e) {
                close();
            }
        }

        @Override
        void send(byte[] ip, int port, ByteBuffer payload) throws IOException {
            if (relay != null) {
                ByteBuffer packet = ByteBuffer.allocate(Socks5.headerLength(ip) + payload.remaining());
                Socks5.writeHeader(packet, ip, port);
                packet.put(payload);
                Buffers.flip(packet);
                relay.write(packet);
            } else if (queued.size() < MAX_QUEUED) {
                ByteBuffer packet = ByteBuffer.allocate(Socks5.headerLength(ip) + payload.remaining());
                Socks5.writeHeader(packet, ip, port);
                packet.put(payload);
                queued.add(packet.array());
            }
        }

        /** The proxy frames its replies the way hev expects, so a valid one is passed on as it is. */
        private void onRelayReadable() {
            try {
                while (true) {
                    Buffers.clear(buffer);
                    if (relay.read(buffer) <= 0) {
                        return;
                    }
                    lastUsed = now();
                    ByteBuffer check = buffer.duplicate();
                    Buffers.flip(check);
                    if (Socks5.parseDatagram(check) != null) {
                        replyToHev(source);
                    }
                }
            } catch (IOException e) {
                close();
            }
        }

        /** The association ends when the control connection closes. */
        private void onControlReadable() {
            try {
                Buffers.clear(buffer);
                if (control.read(buffer) < 0) {
                    close();
                }
            } catch (IOException e) {
                close();
            }
        }

        @Override
        void closeChannels() {
            closed = true;
            if (control != null) {
                ProxyConnector.close(control);
            }
            if (relay != null) {
                ProxyConnector.close(relay);
            }
        }
    }

    // DNS

    private void resolve(SocketAddress source, Socks5.Datagram datagram) throws IOException {
        List<InetAddress> servers = Arrays.equals(datagram.ip, TUNNEL_DNS)
                ? router.dnsUpstreams()
                : Collections.singletonList(InetAddress.getByAddress(datagram.ip));
        byte[] query = new byte[buffer.remaining()];
        buffer.get(query);
        DnsQuery dns = new DnsQuery(source, datagram, query, servers);
        queries.add(dns);
        dns.start();
    }

    private void expireQueries(long now) {
        for (DnsQuery query : new ArrayList<>(queries)) {
            if (now >= query.deadline) {
                query.tryNext();
            }
        }
    }

    /** Asks the servers one after the other until one answers, and remembers the names in the answer. */
    private final class DnsQuery implements Handler {
        private final SocketAddress source;
        private final Socks5.Datagram datagram;
        private final byte[] query;
        private final List<InetAddress> servers;
        private DatagramChannel channel;
        private int next;
        long deadline;

        DnsQuery(SocketAddress source, Socks5.Datagram datagram, byte[] query, List<InetAddress> servers) {
            this.source = source;
            this.datagram = datagram;
            this.query = query;
            this.servers = servers;
        }

        void start() {
            tryNext();
        }

        void tryNext() {
            closeChannel();
            while (next < servers.size()) {
                InetAddress server = servers.get(next++);
                try {
                    channel = DatagramChannel.open();
                    channel.configureBlocking(false);
                    channel.connect(new InetSocketAddress(server, DNS_PORT));
                    channel.register(selector, SelectionKey.OP_READ, this);
                    channel.write(ByteBuffer.wrap(query));
                    deadline = now() + DNS_TIMEOUT_MS;
                    return;
                } catch (IOException e) {
                    closeChannel();
                }
            }
            queries.remove(this);
        }

        @Override
        public void onReadable() {
            try {
                Buffers.clear(buffer);
                Socks5.writeHeader(buffer, datagram.ip, datagram.port);
                int start = buffer.position();
                if (channel.read(buffer) <= 0) {
                    return;
                }
                byte[] answer = new byte[buffer.position() - start];
                ByteBuffer copy = buffer.duplicate();
                Buffers.position(copy, start);
                copy.get(answer);
                DnsParser.Answer parsed = DnsParser.parse(answer, answer.length);
                if (parsed != null) {
                    router.dnsMap().record(parsed.domain, parsed.addresses);
                }
                replyToHev(source);
                close();
            } catch (IOException e) {
                tryNext();
            }
        }

        void close() {
            closeChannel();
            queries.remove(this);
        }

        private void closeChannel() {
            if (channel != null) {
                ProxyConnector.close(channel);
                channel = null;
            }
        }
    }
}
