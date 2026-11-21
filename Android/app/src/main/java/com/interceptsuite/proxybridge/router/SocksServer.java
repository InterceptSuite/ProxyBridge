package com.interceptsuite.proxybridge.router;

import com.interceptsuite.proxybridge.model.ProxyConfig;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.RejectedExecutionException;

/**
 * The SOCKS5 server on the loopback interface that hev connects to. It reads each request, picks a route, opens the
 * upstream connection on a worker thread and hands the two sockets to the relay loop.
 */
final class SocksServer implements Runnable, Closeable {
    private static final int TIMEOUT_MS = 10_000;
    private static final byte[] LOOPBACK = {127, 0, 0, 1};

    private final Router router;
    private final ServerSocketChannel server = ServerSocketChannel.open();

    SocksServer(Router router) throws IOException {
        this.router = router;
        server.bind(new InetSocketAddress(InetAddress.getByAddress(LOOPBACK), 0));
    }

    int port() {
        return ((InetSocketAddress) server.socket().getLocalSocketAddress()).getPort();
    }

    @Override
    public void run() {
        while (server.isOpen()) {
            try {
                SocketChannel client = server.accept();
                try {
                    router.executor().execute(() -> handle(client));
                } catch (RejectedExecutionException e) {
                    ProxyConnector.close(client);
                }
            } catch (ClosedChannelException e) {
                return;
            } catch (IOException e) {
                // a failed accept affects one connection, the next one may succeed
            }
        }
    }

    @Override
    public void close() {
        ProxyConnector.close(server);
    }

    private void handle(SocketChannel client) {
        try {
            Socket socket = client.socket();
            socket.setSoTimeout(TIMEOUT_MS);
            socket.setTcpNoDelay(true);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            OutputStream out = socket.getOutputStream();
            Socks5.readGreeting(in);
            out.write(Socks5.NO_AUTHENTICATION);
            Socks5.Request request = Socks5.readRequest(in);
            switch (request.command) {
                case Socks5.COMMAND_CONNECT:
                    connect(client, out, request);
                    break;
                case Socks5.COMMAND_UDP_ASSOCIATE:
                    associate(client, out);
                    break;
                default:
                    refuse(client, out, Socks5.REPLY_COMMAND_NOT_SUPPORTED);
            }
        } catch (IOException | RuntimeException e) {
            ProxyConnector.close(client);
        }
    }

    private void connect(SocketChannel client, OutputStream out, Socks5.Request request) throws IOException {
        Route route = router.route(request.ip, request.port, false);
        if (route.type == Route.Type.BLOCK) {
            refuse(client, out, Socks5.REPLY_NOT_ALLOWED);
            return;
        }
        SocketChannel upstream;
        try {
            upstream = route.type == Route.Type.DIRECT
                    ? ProxyConnector.connectDirect(request.ip, request.port, TIMEOUT_MS)
                    : ProxyConnector.connect(route.proxy, destination(route.proxy, request), request.port, TIMEOUT_MS);
        } catch (IOException e) {
            refuse(client, out, Socks5.REPLY_FAILURE);
            return;
        }
        client.socket().setSoTimeout(0);
        out.write(Socks5.reply(Socks5.REPLY_SUCCEEDED));
        router.relay().relay(client, upstream);
    }

    /** What to ask the proxy for: the site's name when it is known and the proxy wants it, the address otherwise. */
    private String destination(ProxyConfig proxy, Socks5.Request request) {
        String address = IpAddress.format(request.ip);
        String name = proxy.sendHostname ? router.dnsMap().hostname(address) : null;
        return name != null ? name : address;
    }

    private void associate(SocketChannel client, OutputStream out) throws IOException {
        client.socket().setSoTimeout(0);
        out.write(Socks5.reply(Socks5.REPLY_SUCCEEDED, LOOPBACK, router.udpPort()));
        router.relay().drain(client);
    }

    private static void refuse(SocketChannel client, OutputStream out, int reason) throws IOException {
        out.write(Socks5.reply(reason));
        ProxyConnector.close(client);
    }
}
