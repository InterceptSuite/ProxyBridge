package com.interceptsuite.proxybridge.router;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Remembers which names resolved to which IP addresses, so a rule written for a domain can match a connection that
 * only carries an address, and a proxy can be given the name instead of the address.
 */
final class DnsMap {
    private static final int CAPACITY = 2048;
    private static final int NAMES_PER_ADDRESS = 8;
    private static final long NAME_MAX_AGE_MS = 300_000;

    private static final class Entry {
        final String name;
        final long seen;

        Entry(String name, long seen) {
            this.name = name;
            this.seen = seen;
        }
    }

    /** Names for each address, newest last. */
    private final Map<String, ArrayList<Entry>> entries = new HashMap<>();
    private final ArrayDeque<String> insertionOrder = new ArrayDeque<>();

    void record(String domain, List<byte[]> addresses) {
        record(domain, addresses, System.nanoTime() / 1_000_000);
    }

    synchronized void record(String domain, List<byte[]> addresses, long nowMs) {
        String name = domain.toLowerCase(Locale.ROOT);
        for (byte[] address : addresses) {
            String key = IpAddress.format(address);
            ArrayList<Entry> list = entries.get(key);
            if (list == null) {
                list = new ArrayList<>(2);
                entries.put(key, list);
                insertionOrder.add(key);
                if (insertionOrder.size() > CAPACITY) {
                    entries.remove(insertionOrder.poll());
                }
            }
            if (!list.removeIf(entry -> entry.name.equals(name)) && list.size() >= NAMES_PER_ADDRESS) {
                list.remove(0);
            }
            list.add(new Entry(name, nowMs));
        }
    }

    /** Every name that resolved to the address, newest first. */
    synchronized List<String> domains(String address) {
        ArrayList<Entry> list = entries.get(address);
        List<String> out = new ArrayList<>(list == null ? 0 : list.size());
        for (int i = list == null ? -1 : list.size() - 1; i >= 0; i--) {
            out.add(list.get(i).name);
        }
        return out;
    }

    String hostname(String address) {
        return hostname(address, System.nanoTime() / 1_000_000);
    }

    /**
     * The name to give a proxy instead of the address: the newest one, if a DNS answer mentioned it within five
     * minutes and it is safe to put in a proxy request.
     */
    synchronized String hostname(String address, long nowMs) {
        ArrayList<Entry> list = entries.get(address);
        if (list == null || list.isEmpty()) {
            return null;
        }
        Entry newest = list.get(list.size() - 1);
        return nowMs - newest.seen <= NAME_MAX_AGE_MS && isSafeHostname(newest.name) ? newest.name : null;
    }

    /**
     * Names come out of DNS packets and can hold any byte. Only letters, digits, '.', '-' and '_' are passed on,
     * because a space or a line break would end up inside an HTTP CONNECT request.
     */
    static boolean isSafeHostname(String name) {
        if (name.isEmpty() || name.length() > 253 || name.startsWith(".") || name.endsWith(".")) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean allowed = c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
                    || c == '.' || c == '-' || c == '_';
            if (!allowed) {
                return false;
            }
        }
        return IpAddress.parse(name) == null;
    }

    synchronized void clear() {
        entries.clear();
        insertionOrder.clear();
    }
}
