package com.interceptsuite.proxybridge.model;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Reads and writes the config file. A value that is missing or unknown falls back to its default. */
public final class ConfigJson {
    private ConfigJson() {
    }

    public static String toJson(AppConfig config) {
        try {
            JSONObject root = new JSONObject();
            JSONArray proxies = new JSONArray();
            for (ProxyConfig proxy : config.proxies) {
                proxies.put(new JSONObject()
                        .put("id", proxy.id)
                        .put("name", proxy.name)
                        .put("kind", proxy.kind.name())
                        .put("host", proxy.host)
                        .put("port", proxy.port)
                        .put("username", proxy.username)
                        .put("password", proxy.password)
                        .put("sendHostname", proxy.sendHostname));
            }
            JSONArray rules = new JSONArray();
            for (ProxyRule rule : config.rules) {
                rules.put(new JSONObject()
                        .put("id", rule.id)
                        .put("name", rule.name)
                        .put("hosts", rule.hosts)
                        .put("ports", rule.ports)
                        .put("protocol", rule.protocol.name())
                        .put("action", rule.action.name())
                        .put("proxyId", rule.proxyId == null ? JSONObject.NULL : rule.proxyId)
                        .put("enabled", rule.enabled));
            }
            return root.put("proxies", proxies)
                    .put("rules", rules)
                    .put("defaultAction", config.defaultAction.name())
                    .put("appMode", config.appMode.name())
                    .put("packages", new JSONArray(config.packages))
                    .toString();
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    public static AppConfig fromJson(String text) {
        AppConfig config = new AppConfig();
        try {
            JSONObject root = new JSONObject(text);
            JSONArray proxies = root.optJSONArray("proxies");
            for (int i = 0; proxies != null && i < proxies.length(); i++) {
                JSONObject item = proxies.getJSONObject(i);
                ProxyConfig proxy = new ProxyConfig(item.getString("id"));
                proxy.name = item.optString("name", "");
                proxy.kind = parse(ProxyKind.class, item.optString("kind"), ProxyKind.SOCKS5);
                proxy.host = item.optString("host", "");
                proxy.port = item.optInt("port", 1080);
                proxy.username = item.optString("username", "");
                proxy.password = item.optString("password", "");
                proxy.sendHostname = item.optBoolean("sendHostname", true);
                config.proxies.add(proxy);
            }
            JSONArray rules = root.optJSONArray("rules");
            for (int i = 0; rules != null && i < rules.length(); i++) {
                JSONObject item = rules.getJSONObject(i);
                ProxyRule rule = new ProxyRule(item.getString("id"));
                rule.name = item.optString("name", "");
                rule.hosts = item.optString("hosts", "");
                rule.ports = item.optString("ports", "");
                rule.protocol = parse(RuleProtocol.class, item.optString("protocol"), RuleProtocol.ANY);
                rule.action = parse(RuleAction.class, item.optString("action"), RuleAction.PROXY);
                rule.proxyId = item.isNull("proxyId") ? null : item.optString("proxyId", null);
                rule.enabled = item.optBoolean("enabled", true);
                config.rules.add(rule);
            }
            config.defaultAction = parse(RuleAction.class, root.optString("defaultAction"), RuleAction.DIRECT);
            config.appMode = parse(AppMode.class, root.optString("appMode"), AppMode.ALL);
            JSONArray packages = root.optJSONArray("packages");
            for (int i = 0; packages != null && i < packages.length(); i++) {
                config.packages.add(packages.getString(i));
            }
        } catch (JSONException e) {
            return new AppConfig();
        }
        return config;
    }

    private static <T extends Enum<T>> T parse(Class<T> type, String name, T fallback) {
        try {
            return Enum.valueOf(type, name);
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }
}
