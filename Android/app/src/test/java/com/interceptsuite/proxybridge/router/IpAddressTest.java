package com.interceptsuite.proxybridge.router;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class IpAddressTest {
    @Test
    public void parsesAndFormats() {
        assertArrayEquals(new byte[] {10, 0, 0, 1}, IpAddress.parse("10.0.0.1"));
        assertEquals("10.0.0.1", IpAddress.format(IpAddress.parse("10.0.0.1")));
        assertArrayEquals(IpAddress.parse("fd00::2"), IpAddress.parse(IpAddress.format(IpAddress.parse("fd00::2"))));
        assertEquals(16, IpAddress.parse("::1").length);
    }

    @Test
    public void namesAreNotResolved() {
        assertNull(IpAddress.parse("example.com"));
        assertNull(IpAddress.parse("999.1.1.1"));
        assertNull(IpAddress.parse(""));
    }

    @Test
    public void prefixComparison() {
        byte[] a = IpAddress.parse("192.168.1.10");
        assertTrue(IpAddress.prefixEqual(a, IpAddress.parse("192.168.1.99"), 24));
        assertFalse(IpAddress.prefixEqual(a, IpAddress.parse("192.168.2.10"), 24));
        assertTrue(IpAddress.prefixEqual(a, IpAddress.parse("192.168.2.10"), 16));
        assertTrue(IpAddress.prefixEqual(a, IpAddress.parse("8.8.8.8"), 0));
    }
}
