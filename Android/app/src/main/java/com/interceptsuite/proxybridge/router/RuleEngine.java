package com.interceptsuite.proxybridge.router;

import com.interceptsuite.proxybridge.model.AppConfig;
import com.interceptsuite.proxybridge.model.ProxyConfig;
import com.interceptsuite.proxybridge.model.ProxyRule;
import com.interceptsuite.proxybridge.model.RuleAction;
import com.interceptsuite.proxybridge.model.RuleProtocol;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Locale;

/** Picks a route for a flow. Rules are parsed once when the engine is built, the first matching rule wins. */
final class RuleEngine {
    private final List<CompiledRule> rules = new ArrayList<>();
    private final List<ProxyConfig> proxies = new ArrayList<>();
    private final RuleAction defaultAction;

    RuleEngine(AppConfig config) {
        for (ProxyRule rule : config.rules) {
            if (rule.enabled) {
                rules.add(new CompiledRule(rule));
            }
        }
        for (ProxyConfig proxy : config.proxies) {
            proxies.add(proxy.copy());
        }
        defaultAction = config.defaultAction;
    }

    /**
     * @param ip      the destination address as raw bytes
     * @param domains names that resolved to the address, learned from DNS answers
     */
    Route route(byte[] ip, int port, boolean udp, List<String> domains) {
        for (CompiledRule rule : rules) {
            if (rule.matches(ip, port, udp, domains)) {
                return resolve(rule.action, rule.proxyId);
            }
        }
        return resolve(defaultAction, null);
    }

    private Route resolve(RuleAction action, String proxyId) {
        switch (action) {
            case BLOCK:
                return Route.BLOCK;
            case PROXY:
                ProxyConfig chosen = null;
                for (ProxyConfig proxy : proxies) {
                    if (proxy.id.equals(proxyId)) {
                        chosen = proxy;
                    }
                }
                if (chosen == null && !proxies.isEmpty()) {
                    chosen = proxies.get(0);
                }
                return chosen == null ? Route.DIRECT : Route.via(chosen);
            default:
                return Route.DIRECT;
        }
    }

    private static final class CompiledRule {
        final RuleAction action;
        final String proxyId;
        private final RuleProtocol protocol;
        private final List<HostPattern> hosts = new ArrayList<>();
        /** Null matches any port. */
        private final BitSet ports;

        CompiledRule(ProxyRule rule) {
            action = rule.action;
            proxyId = rule.proxyId;
            protocol = rule.protocol;
            for (String item : items(rule.hosts, true)) {
                hosts.add(HostPattern.of(item));
            }
            if (hosts.isEmpty()) {
                hosts.add(HostPattern.ANY);
            }
            ports = parsePorts(items(rule.ports, false));
        }

        boolean matches(byte[] ip, int port, boolean udp, List<String> domains) {
            if (protocol == RuleProtocol.TCP && udp || protocol == RuleProtocol.UDP && !udp) {
                return false;
            }
            if (ports != null && !ports.get(port)) {
                return false;
            }
            for (HostPattern host : hosts) {
                if (host.matches(ip, domains)) {
                    return true;
                }
            }
            return false;
        }

        private static List<String> items(String text, boolean lowercase) {
            List<String> out = new ArrayList<>();
            for (String part : text.split("[;,]")) {
                String item = part.trim();
                if (!item.isEmpty()) {
                    out.add(lowercase ? item.toLowerCase(Locale.ROOT) : item);
                }
            }
            return out;
        }

        private static BitSet parsePorts(List<String> items) {
            if (items.isEmpty() || items.contains("*")) {
                return null;
            }
            BitSet set = new BitSet(65536);
            for (String item : items) {
                int dash = item.indexOf('-');
                int from = number(dash < 0 ? item : item.substring(0, dash));
                int to = dash < 0 ? from : number(item.substring(dash + 1));
                if (from >= 0 && to >= from) {
                    set.set(from, to + 1);
                }
            }
            return set;
        }

        private static int number(String text) {
            try {
                int value = Integer.parseInt(text.trim());
                return value >= 0 && value <= 65535 ? value : -1;
            } catch (NumberFormatException e) {
                return -1;
            }
        }
    }

    private abstract static class HostPattern {
        static final HostPattern ANY = new HostPattern() {
            @Override
            boolean matches(byte[] ip, List<String> domains) {
                return true;
            }
        };

        abstract boolean matches(byte[] ip, List<String> domains);

        static HostPattern of(String text) {
            if (text.equals("*")) {
                return ANY;
            }
            byte[] address = IpAddress.parse(text);
            if (address != null) {
                return new Address(address);
            }
            int slash = text.indexOf('/');
            if (slash > 0) {
                byte[] network = IpAddress.parse(text.substring(0, slash));
                try {
                    if (network != null) {
                        return new Network(network, Integer.parseInt(text.substring(slash + 1)));
                    }
                } catch (NumberFormatException ignored) {
                    // not a prefix length, so it is treated as a name that never matches
                }
            }
            return new Name(text);
        }
    }

    private static final class Address extends HostPattern {
        private final byte[] address;

        Address(byte[] address) {
            this.address = address;
        }

        @Override
        boolean matches(byte[] ip, List<String> domains) {
            return java.util.Arrays.equals(address, ip);
        }
    }

    private static final class Network extends HostPattern {
        private final byte[] network;
        private final int bits;

        Network(byte[] network, int bits) {
            this.network = network;
            this.bits = bits;
        }

        @Override
        boolean matches(byte[] ip, List<String> domains) {
            return IpAddress.prefixEqual(ip, network, bits);
        }
    }

    private static final class Name extends HostPattern {
        private final String pattern;
        /** "*.example.com" also covers example.com itself. */
        private final String apex;

        Name(String pattern) {
            this.pattern = pattern;
            apex = pattern.startsWith("*.") ? pattern.substring(2) : null;
        }

        @Override
        boolean matches(byte[] ip, List<String> domains) {
            for (String domain : domains) {
                if (Glob.matches(pattern, domain) || domain.equals(apex)) {
                    return true;
                }
            }
            return false;
        }
    }
}
