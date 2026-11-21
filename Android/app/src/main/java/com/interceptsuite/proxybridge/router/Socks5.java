package com.interceptsuite.proxybridge.router;

import com.interceptsuite.proxybridge.model.ProxyConfig;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** SOCKS5 wire format, shared by the server hev talks to and the client that talks to the upstream proxy. */
final class Socks5 {
    static final int VERSION = 5;
    static final int COMMAND_CONNECT = 1;
    static final int COMMAND_UDP_ASSOCIATE = 3;
    static final int REPLY_SUCCEEDED = 0;
    static final int REPLY_FAILURE = 1;
    static final int REPLY_NOT_ALLOWED = 2;
    static final int REPLY_COMMAND_NOT_SUPPORTED = 7;
    static final byte[] NO_AUTHENTICATION = {VERSION, 0};

    private static final int ADDRESS_IPV4 = 1;
    private static final int ADDRESS_DOMAIN = 3;
    private static final int ADDRESS_IPV6 = 4;
    private static final int MAX_CREDENTIAL = 255;

    /** A request from hev. Its destination is always an IP address. */
    static final class Request {
        final int command;
        final byte[] ip;
        final int port;

        Request(int command, byte[] ip, int port) {
            this.command = command;
            this.ip = ip;
            this.port = port;
        }
    }

    /** The address a proxy reports in its reply, as text. */
    static final class Endpoint {
        final String host;
        final int port;

        Endpoint(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    /** The destination of a UDP datagram. The payload is what remains in the buffer. */
    static final class Datagram {
        final byte[] ip;
        final int port;

        Datagram(byte[] ip, int port) {
            this.ip = ip;
            this.port = port;
        }
    }

    private Socks5() {
    }

    // server side

    static void readGreeting(DataInputStream in) throws IOException {
        if (in.readUnsignedByte() != VERSION) {
            throw new IOException("not a SOCKS5 client");
        }
        in.readFully(new byte[in.readUnsignedByte()]);
    }

    static Request readRequest(DataInputStream in) throws IOException {
        if (in.readUnsignedByte() != VERSION) {
            throw new IOException("not a SOCKS5 request");
        }
        int command = in.readUnsignedByte();
        in.readUnsignedByte();
        int type = in.readUnsignedByte();
        if (type != ADDRESS_IPV4 && type != ADDRESS_IPV6) {
            throw new IOException("unsupported address type " + type);
        }
        byte[] ip = new byte[type == ADDRESS_IPV4 ? 4 : 16];
        in.readFully(ip);
        return new Request(command, ip, in.readUnsignedShort());
    }

    static byte[] reply(int code) {
        return reply(code, new byte[4], 0);
    }

    static byte[] reply(int code, byte[] ip, int port) {
        byte[] out = new byte[3 + 1 + ip.length + 2];
        out[0] = VERSION;
        out[1] = (byte) code;
        out[3] = (byte) (ip.length == 4 ? ADDRESS_IPV4 : ADDRESS_IPV6);
        System.arraycopy(ip, 0, out, 4, ip.length);
        out[out.length - 2] = (byte) (port >> 8);
        out[out.length - 1] = (byte) port;
        return out;
    }

    // client side

    /** The greeting, and the user name and password exchange when the proxy has a login. */
    static void negotiate(DataInputStream in, OutputStream out, ProxyConfig proxy) throws IOException {
        int method = proxy.hasCredentials() ? 2 : 0;
        out.write(new byte[]{VERSION, 1, (byte) method});
        out.flush();
        if (in.readUnsignedByte() != VERSION) {
            throw new IOException("proxy is not SOCKS5");
        }
        int chosen = in.readUnsignedByte();
        if (chosen == 0) {
            return;
        }
        if (chosen != 2 || !proxy.hasCredentials()) {
            throw new IOException("proxy refused the authentication methods");
        }
        byte[] user = limit(proxy.username.getBytes(StandardCharsets.UTF_8));
        byte[] password = limit(proxy.password.getBytes(StandardCharsets.UTF_8));
        byte[] message = new byte[3 + user.length + password.length];
        message[0] = 1;
        message[1] = (byte) user.length;
        System.arraycopy(user, 0, message, 2, user.length);
        message[2 + user.length] = (byte) password.length;
        System.arraycopy(password, 0, message, 3 + user.length, password.length);
        out.write(message);
        out.flush();
        in.readUnsignedByte();
        if (in.readUnsignedByte() != 0) {
            throw new IOException("proxy rejected the login");
        }
    }

    /** Sends a request for a host (an IP literal or a name) and returns the address the proxy reports. */
    static Endpoint request(DataInputStream in, OutputStream out, int command, String host, int port) throws IOException {
        byte[] address = encodeAddress(host, port);
        byte[] message = new byte[3 + address.length];
        message[0] = VERSION;
        message[1] = (byte) command;
        System.arraycopy(address, 0, message, 3, address.length);
        out.write(message);
        out.flush();

        if (in.readUnsignedByte() != VERSION) {
            throw new IOException("bad reply from proxy");
        }
        int code = in.readUnsignedByte();
        in.readUnsignedByte();
        int type = in.readUnsignedByte();
        String bound;
        if (type == ADDRESS_DOMAIN) {
            byte[] name = new byte[in.readUnsignedByte()];
            in.readFully(name);
            bound = new String(name, StandardCharsets.UTF_8);
        } else if (type == ADDRESS_IPV4 || type == ADDRESS_IPV6) {
            byte[] ip = new byte[type == ADDRESS_IPV4 ? 4 : 16];
            in.readFully(ip);
            bound = IpAddress.format(ip);
        } else {
            throw new IOException("bad address type in reply");
        }
        int boundPort = in.readUnsignedShort();
        if (code != REPLY_SUCCEEDED) {
            throw new IOException("proxy refused the request, code " + code);
        }
        return new Endpoint(bound, boundPort);
    }

    private static byte[] encodeAddress(String host, int port) {
        byte[] ip = IpAddress.parse(host);
        byte[] out;
        if (ip != null) {
            out = new byte[1 + ip.length + 2];
            out[0] = (byte) (ip.length == 4 ? ADDRESS_IPV4 : ADDRESS_IPV6);
            System.arraycopy(ip, 0, out, 1, ip.length);
        } else {
            byte[] name = Arrays.copyOf(host.getBytes(StandardCharsets.UTF_8), Math.min(host.length(), 255));
            out = new byte[2 + name.length + 2];
            out[0] = ADDRESS_DOMAIN;
            out[1] = (byte) name.length;
            System.arraycopy(name, 0, out, 2, name.length);
        }
        out[out.length - 2] = (byte) (port >> 8);
        out[out.length - 1] = (byte) port;
        return out;
    }

    private static byte[] limit(byte[] bytes) {
        return bytes.length <= MAX_CREDENTIAL ? bytes : Arrays.copyOf(bytes, MAX_CREDENTIAL);
    }

    // UDP datagrams

    static int headerLength(byte[] ip) {
        return 4 + ip.length + 2;
    }

    static void writeHeader(ByteBuffer out, byte[] ip, int port) {
        out.put((byte) 0).put((byte) 0).put((byte) 0);
        out.put((byte) (ip.length == 4 ? ADDRESS_IPV4 : ADDRESS_IPV6));
        out.put(ip);
        out.putShort((short) port);
    }

    /**
     * Reads the header at the buffer's position and leaves the position at the payload. Returns null for a fragment,
     * a domain address or a packet that is too short.
     */
    static Datagram parseDatagram(ByteBuffer in) {
        if (in.remaining() < 10 || in.get(in.position() + 2) != 0) {
            return null;
        }
        int type = in.get(in.position() + 3);
        int length = type == ADDRESS_IPV4 ? 4 : type == ADDRESS_IPV6 ? 16 : 0;
        if (length == 0 || in.remaining() < 4 + length + 2) {
            return null;
        }
        Buffers.position(in, in.position() + 4);
        byte[] ip = new byte[length];
        in.get(ip);
        return new Datagram(ip, in.getShort() & 0xFFFF);
    }
}
