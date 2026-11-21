package com.interceptsuite.proxybridge.router;

import com.interceptsuite.proxybridge.model.ProxyConfig;
import com.interceptsuite.proxybridge.model.ProxyKind;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Opens TCP connections, directly or through a SOCKS5 or HTTP CONNECT proxy. Everything here blocks with a timeout and
 * runs on a worker thread. A returned channel is still in blocking mode.
 */
final class ProxyConnector {
    private static final int HTTP_HEADER_LIMIT = 8192;

    /** A SOCKS5 UDP association: the control connection that keeps it alive and the proxy's UDP address. */
    static final class Association {
        final SocketChannel control;
        final InetSocketAddress relay;

        Association(SocketChannel control, InetSocketAddress relay) {
            this.control = control;
            this.relay = relay;
        }
    }

    private ProxyConnector() {
    }

    static SocketChannel connectDirect(byte[] ip, int port, int timeoutMs) throws IOException {
        return open(new InetSocketAddress(InetAddress.getByAddress(ip), port), timeoutMs);
    }

    /** Connects to {@code host} (an IP literal or a name) through the proxy. */
    static SocketChannel connect(ProxyConfig proxy, String host, int port, int timeoutMs) throws IOException {
        SocketChannel channel = open(proxyAddress(proxy), timeoutMs);
        try {
            Socket socket = channel.socket();
            socket.setSoTimeout(timeoutMs);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();
            if (proxy.kind == ProxyKind.SOCKS5) {
                Socks5.negotiate(in, out, proxy);
                Socks5.request(in, out, Socks5.COMMAND_CONNECT, host, port);
            } else {
                httpConnect(in, out, proxy, host, port);
            }
            socket.setSoTimeout(0);
            return channel;
        } catch (IOException | RuntimeException e) {
            close(channel);
            throw e;
        }
    }

    static Association associate(ProxyConfig proxy, int timeoutMs) throws IOException {
        SocketChannel channel = open(proxyAddress(proxy), timeoutMs);
        try {
            Socket socket = channel.socket();
            socket.setSoTimeout(timeoutMs);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();
            Socks5.negotiate(in, out, proxy);
            Socks5.Endpoint bound = Socks5.request(in, out, Socks5.COMMAND_UDP_ASSOCIATE, "0.0.0.0", 0);
            socket.setSoTimeout(0);
            return new Association(channel, relayAddress(channel, bound));
        } catch (IOException | RuntimeException e) {
            close(channel);
            throw e;
        }
    }

    /** Some proxies answer with 0.0.0.0, which means "the address you reached me on". */
    private static InetSocketAddress relayAddress(SocketChannel control, Socks5.Endpoint bound) throws IOException {
        byte[] ip = IpAddress.parse(bound.host);
        boolean unspecified = ip == null || isZero(ip);
        InetAddress address = unspecified
                ? ((InetSocketAddress) control.getRemoteAddress()).getAddress()
                : InetAddress.getByAddress(ip);
        return new InetSocketAddress(address, bound.port);
    }

    private static boolean isZero(byte[] ip) {
        for (byte b : ip) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static InetSocketAddress proxyAddress(ProxyConfig proxy) throws UnknownHostException {
        InetSocketAddress address = new InetSocketAddress(proxy.host, proxy.port);
        if (address.isUnresolved()) {
            throw new UnknownHostException(proxy.host);
        }
        return address;
    }

    private static SocketChannel open(InetSocketAddress address, int timeoutMs) throws IOException {
        SocketChannel channel = SocketChannel.open();
        try {
            channel.socket().connect(address, timeoutMs);
            channel.socket().setTcpNoDelay(true);
            return channel;
        } catch (IOException | RuntimeException e) {
            close(channel);
            throw e;
        }
    }

    private static void httpConnect(DataInputStream in, OutputStream out, ProxyConfig proxy, String host, int port)
            throws IOException {
        String target = host.indexOf(':') >= 0 ? "[" + host + "]:" + port : host + ":" + port;
        StringBuilder request = new StringBuilder("CONNECT ").append(target).append(" HTTP/1.1\r\nHost: ")
                .append(target).append("\r\n");
        if (proxy.hasCredentials()) {
            String login = proxy.username + ":" + proxy.password;
            request.append("Proxy-Authorization: Basic ")
                    .append(Base64.getEncoder().encodeToString(login.getBytes(StandardCharsets.UTF_8))).append("\r\n");
        }
        out.write(request.append("\r\n").toString().getBytes(StandardCharsets.UTF_8));
        out.flush();

        // One byte at a time, so none of the tunnelled data behind the headers is consumed
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int b = in.read();
            if (b < 0 || head.size() > HTTP_HEADER_LIMIT) {
                throw new IOException("bad reply from proxy");
            }
            head.write(b);
            matched = b == (matched % 2 == 0 ? '\r' : '\n') ? matched + 1 : b == '\r' ? 1 : 0;
        }
        String[] status = head.toString("ISO-8859-1").split(" ", 3);
        if (status.length < 2 || !status[1].equals("200")) {
            throw new IOException("proxy refused the connection");
        }
    }

    static void close(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignored) {
            // nothing more can be done for a connection that is already gone
        }
    }
}
