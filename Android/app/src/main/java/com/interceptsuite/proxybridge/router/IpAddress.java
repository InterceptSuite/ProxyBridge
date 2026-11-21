package com.interceptsuite.proxybridge.router;

import java.util.ArrayList;
import java.util.List;

/** IP literals as raw bytes (4 or 16). Nothing here ever does a DNS lookup. */
final class IpAddress {
    private IpAddress() {
    }

    /** Returns the bytes of an IPv4 or IPv6 literal, or null when the text is not one. */
    static byte[] parse(String text) {
        return text.indexOf(':') >= 0 ? parseV6(text) : parseV4(text);
    }

    static String format(byte[] ip) {
        return ip.length == 4 ? formatV4(ip) : formatV6(ip);
    }

    /** True when the first {@code bits} bits of both addresses are equal. */
    static boolean prefixEqual(byte[] a, byte[] b, int bits) {
        if (a.length != b.length || bits < 0 || bits > a.length * 8) {
            return false;
        }
        int whole = bits / 8;
        for (int i = 0; i < whole; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        int rest = bits % 8;
        if (rest == 0) {
            return true;
        }
        int mask = 0xFF << (8 - rest) & 0xFF;
        return (a[whole] & mask) == (b[whole] & mask);
    }

    private static byte[] parseV4(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            int value = decimal(parts[i]);
            if (value < 0) {
                return null;
            }
            out[i] = (byte) value;
        }
        return out;
    }

    private static int decimal(String part) {
        if (part.isEmpty() || part.length() > 3) {
            return -1;
        }
        int value = 0;
        for (int i = 0; i < part.length(); i++) {
            int digit = part.charAt(i) - '0';
            if (digit < 0 || digit > 9) {
                return -1;
            }
            value = value * 10 + digit;
        }
        return value <= 255 ? value : -1;
    }

    private static byte[] parseV6(String text) {
        int zone = text.indexOf('%');
        if (zone >= 0) {
            text = text.substring(0, zone);
        }
        int compression = text.indexOf("::");
        if (compression != text.lastIndexOf("::")) {
            return null;
        }
        List<Integer> head = groups(compression < 0 ? text : text.substring(0, compression));
        List<Integer> tail = compression < 0 ? new ArrayList<>() : groups(text.substring(compression + 2));
        if (head == null || tail == null) {
            return null;
        }
        int count = head.size() + tail.size();
        if (compression < 0 ? count != 8 : count > 7) {
            return null;
        }
        byte[] out = new byte[16];
        for (int i = 0; i < head.size(); i++) {
            put(out, i, head.get(i));
        }
        for (int i = 0; i < tail.size(); i++) {
            put(out, 8 - tail.size() + i, tail.get(i));
        }
        return out;
    }

    private static void put(byte[] out, int group, int value) {
        out[group * 2] = (byte) (value >> 8);
        out[group * 2 + 1] = (byte) value;
    }

    /** The 16-bit groups of one side of an IPv6 address. A trailing IPv4 part counts as two groups. */
    private static List<Integer> groups(String text) {
        List<Integer> out = new ArrayList<>();
        if (text.isEmpty()) {
            return out;
        }
        String[] parts = text.split(":", -1);
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (part.indexOf('.') >= 0) {
                byte[] v4 = i == parts.length - 1 ? parseV4(part) : null;
                if (v4 == null) {
                    return null;
                }
                out.add((v4[0] & 0xFF) << 8 | v4[1] & 0xFF);
                out.add((v4[2] & 0xFF) << 8 | v4[3] & 0xFF);
            } else {
                if (part.isEmpty() || part.length() > 4) {
                    return null;
                }
                try {
                    out.add(Integer.parseInt(part, 16));
                } catch (NumberFormatException e) {
                    return null;
                }
            }
        }
        return out;
    }

    private static String formatV4(byte[] ip) {
        return (ip[0] & 0xFF) + "." + (ip[1] & 0xFF) + "." + (ip[2] & 0xFF) + "." + (ip[3] & 0xFF);
    }

    /** The compressed form of RFC 5952, so one address always gives one string. */
    private static String formatV6(byte[] ip) {
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = (ip[i * 2] & 0xFF) << 8 | ip[i * 2 + 1] & 0xFF;
        }
        int bestStart = -1;
        int bestLength = 1;
        for (int i = 0; i < 8; ) {
            if (groups[i] != 0) {
                i++;
                continue;
            }
            int end = i;
            while (end < 8 && groups[end] == 0) {
                end++;
            }
            if (end - i > bestLength) {
                bestStart = i;
                bestLength = end - i;
            }
            i = end;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                out.append("::");
                i += bestLength - 1;
                continue;
            }
            if (out.length() > 0 && out.charAt(out.length() - 1) != ':') {
                out.append(':');
            }
            out.append(Integer.toHexString(groups[i]));
        }
        return out.toString();
    }
}
