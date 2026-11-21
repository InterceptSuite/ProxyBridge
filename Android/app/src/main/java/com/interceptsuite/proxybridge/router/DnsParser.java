package com.interceptsuite.proxybridge.router;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Reads the question name and the A and AAAA answers of a DNS response. Every offset is bounds checked. */
final class DnsParser {
    private static final int TYPE_A = 1;
    private static final int TYPE_AAAA = 28;
    private static final int MAX_POINTER_JUMPS = 32;

    static final class Answer {
        final String domain;
        final List<byte[]> addresses;

        Answer(String domain, List<byte[]> addresses) {
            this.domain = domain;
            this.addresses = addresses;
        }
    }

    private DnsParser() {
    }

    /** Returns null when the packet is not a response with a question. */
    static Answer parse(byte[] packet, int length) {
        if (length < 12) {
            return null;
        }
        int questions = u16(packet, 4);
        int answers = u16(packet, 6);
        if (questions < 1) {
            return null;
        }
        int[] end = new int[1];
        String name = readName(packet, length, 12, end);
        if (name == null || name.isEmpty()) {
            return null;
        }
        int i = end[0] + 4;
        for (int q = 1; q < questions; q++) {
            int next = skipName(packet, length, i);
            if (next < 0) {
                return null;
            }
            i = next + 4;
        }
        List<byte[]> addresses = new ArrayList<>();
        for (int a = 0; a < answers; a++) {
            int owner = skipName(packet, length, i);
            if (owner < 0 || owner + 10 > length) {
                break;
            }
            int type = u16(packet, owner);
            int size = u16(packet, owner + 8);
            int start = owner + 10;
            if (start + size > length) {
                break;
            }
            if (type == TYPE_A && size == 4 || type == TYPE_AAAA && size == 16) {
                addresses.add(Arrays.copyOfRange(packet, start, start + size));
            }
            i = start + size;
        }
        return new Answer(name, addresses);
    }

    private static int u16(byte[] b, int at) {
        return (b[at] & 0xFF) << 8 | b[at + 1] & 0xFF;
    }

    /** Reads a possibly compressed name. {@code end[0]} receives the offset right after it. */
    private static String readName(byte[] b, int length, int start, int[] end) {
        StringBuilder name = new StringBuilder();
        int i = start;
        int resume = -1;
        int jumps = 0;
        while (i < length) {
            int size = b[i] & 0xFF;
            if (size == 0) {
                end[0] = resume >= 0 ? resume : i + 1;
                return name.toString();
            }
            if ((size & 0xC0) == 0xC0) {
                if (i + 1 >= length) {
                    return null;
                }
                if (resume < 0) {
                    resume = i + 2;
                }
                i = (size & 0x3F) << 8 | b[i + 1] & 0xFF;
                if (++jumps > MAX_POINTER_JUMPS) {
                    return null;
                }
                continue;
            }
            if (i + 1 + size > length) {
                return null;
            }
            if (name.length() > 0) {
                name.append('.');
            }
            name.append(new String(b, i + 1, size, StandardCharsets.UTF_8));
            i += 1 + size;
        }
        return null;
    }

    /** The offset after a name, without reading it, or -1 when it runs off the packet. */
    private static int skipName(byte[] b, int length, int start) {
        int i = start;
        while (i < length) {
            int size = b[i] & 0xFF;
            if (size == 0) {
                return i + 1;
            }
            if ((size & 0xC0) == 0xC0) {
                return i + 2;
            }
            i += 1 + size;
        }
        return -1;
    }
}
