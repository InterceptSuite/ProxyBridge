package com.interceptsuite.proxybridge.router;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

public class DnsMapTest {
    private final DnsMap map = new DnsMap();

    @Test
    public void remembersNewestFirst() {
        List<byte[]> ip = List.of(IpAddress.parse("1.2.3.4"));
        map.record("a.example.com", ip, 0);
        map.record("B.example.com", ip, 1);
        assertEquals(List.of("b.example.com", "a.example.com"), map.domains("1.2.3.4"));
    }

    @Test
    public void hostnameExpires() {
        map.record("a.example.com", List.of(IpAddress.parse("1.2.3.4")), 0);
        assertEquals("a.example.com", map.hostname("1.2.3.4", 299_000));
        assertNull(map.hostname("1.2.3.4", 301_000));
    }

    @Test
    public void unknownAddressHasNoNames() {
        assertTrue(map.domains("9.9.9.9").isEmpty());
        assertNull(map.hostname("9.9.9.9"));
    }

    @Test
    public void onlyPlainHostnamesAreSent() {
        assertTrue(DnsMap.isSafeHostname("api.example.com"));
        assertFalse(DnsMap.isSafeHostname("bad host"));
        assertFalse(DnsMap.isSafeHostname("a\r\nb"));
        assertFalse(DnsMap.isSafeHostname(""));
    }
}
