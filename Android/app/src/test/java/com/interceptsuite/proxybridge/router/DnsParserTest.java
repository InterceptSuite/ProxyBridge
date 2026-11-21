package com.interceptsuite.proxybridge.router;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class DnsParserTest {
    private static final byte[] RESPONSE = {
        0x12, 0x34, (byte) 0x81, (byte) 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
        (byte) 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, (byte) 184, (byte) 216, 34
    };

    @Test
    public void readsNameAndAddress() {
        DnsParser.Answer answer = DnsParser.parse(RESPONSE, RESPONSE.length);
        assertEquals("www.example.com", answer.domain);
        assertEquals(1, answer.addresses.size());
        assertArrayEquals(new byte[] {93, (byte) 184, (byte) 216, 34}, answer.addresses.get(0));
    }

    @Test
    public void truncatedPacketsAreRejectedOrEmpty() {
        for (int length = 0; length < RESPONSE.length; length++) {
            DnsParser.Answer answer = DnsParser.parse(RESPONSE, length);
            if (answer != null) {
                assertEquals(0, answer.addresses.size());
            }
        }
        assertNull(DnsParser.parse(new byte[4], 4));
    }

    @Test
    public void pointerLoopTerminates() {
        byte[] loop = {0, 1, (byte) 0x81, (byte) 0x80, 0, 1, 0, 0, 0, 0, 0, 0, (byte) 0xC0, 12, 0, 1, 0, 1};
        assertNull(DnsParser.parse(loop, loop.length));
    }
}
