# ProxyBridge for Android

Sends the traffic of your Android phone through a SOCKS5 or HTTP proxy. You choose per destination what goes through a proxy, what goes direct and what is blocked. The app has no analytics and collects no data.

## What it does

- Proxies: SOCKS5 and HTTP (CONNECT), with optional user name and password. TCP and UDP work with SOCKS5, HTTP proxies carry TCP only.
- Per proxy, "Send host name to proxy": when the phone looked a site up through the tunnel's DNS, the proxy is given its name instead of its IP address. The name is only used for five minutes after the DNS answer, and only if it is a plain host name.
- Rules: match a destination by domain (wildcards allowed), IP address or CIDR block, plus ports and protocol. The first matching rule wins and its action is proxy, direct or block.
- A default action for traffic that matches no rule. The first proxy in the list is the default proxy.
- Apps: send all apps through the tunnel, only the apps you pick, or all except the apps you pick.
- Changes to rules and proxies apply to a running tunnel without turning it off.

## What it cannot do

Android does not tell a VPN which app sent a packet, so a rule cannot name an app. App selection is done by the system when the tunnel is built, and changing it restarts the tunnel.

A domain rule needs the name to be known. ProxyBridge learns names from DNS answers, so apps that use their own encrypted DNS or connect to a fixed IP address match by IP only.

## How it works

```
apps -> VpnService (TUN) -> hev-socks5-tunnel -> local router -> proxy / direct / block
```

`VpnService` hands the app raw IP packets. [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) (MIT, native library) turns them into TCP connections and UDP flows and sends each one as a SOCKS5 request to a router listening on the loopback address inside the app. The router is the only place where rules are applied. The app excludes itself from the tunnel, so the router's own sockets never loop back.

```
app/src/main/java/.../model    config model and JSON
app/src/main/java/.../router   rule engine, SOCKS5 server, proxy client, TCP and UDP relays, DNS
app/src/main/java/.../vpn      VpnService, native tunnel binding, tunnel state
app/src/main/java/.../data     config storage
app/src/main/java/.../ui       activities and fragments
app/src/main/jni               native build files for hev-socks5-tunnel
fetch-hev.sh                   downloads hev-socks5-tunnel at the pinned commit
```

## Build

Needs Android Studio with the NDK installed (SDK Manager, SDK Tools) and a device or emulator running Android 10 or newer.

```bash
bash fetch-hev.sh
```

Then open this folder in Android Studio, let Gradle sync and run the `app` configuration. The native library is built for `arm64-v8a` and `x86_64`.

## Tests

`app/src/test` holds JVM unit tests for the rule engine, IP handling, DNS parsing and the name map, and the config JSON. Run them from Android Studio or with `./gradlew test`.
