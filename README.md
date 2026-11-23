# ProxyBridge

<p align="center">
  <img src="img/logo.png" alt="ProxyBridge Logo" width="300" />
</p>

<p align="center">
  <a href="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-windows.yml"><img src="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-windows.yml/badge.svg" alt="Build Windows" /></a>
  <a href="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-mac.yml"><img src="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-mac.yml/badge.svg" alt="Build macOS" /></a>
  <a href="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-linux.yml"><img src="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-linux.yml/badge.svg" alt="Build Linux" /></a>
  <a href="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-ios.yml"><img src="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-ios.yml/badge.svg" alt="Build iOS" /></a>
  <a href="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-android.yml"><img src="https://github.com/InterceptSuite/ProxyBridge/actions/workflows/build-android.yml/badge.svg" alt="Build Android" /></a>
  <a href="https://github.com/InterceptSuite/ProxyBridge/releases"><img src="https://img.shields.io/github/downloads/InterceptSuite/ProxyBridge/total?style=flat-square&logo=github&color=blue" alt="Total Downloads" /></a>
  
</p>

<p align="center">
  <a href="https://trendshift.io/repositories/19916?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-19916" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/19916/daily?language=C" alt="InterceptSuite%2FProxyBridge | Trendshift" width="250" height="55"/></a>
  &nbsp;
  <a href="https://trendshift.io/repositories/19916?utm_source=trendshift-badge&amp;utm_medium=badge&amp;utm_campaign=badge-trendshift-19916" target="_blank" rel="noopener noreferrer"><img src="https://trendshift.io/api/badge/trendshift/repositories/19916/monthly?language=C" alt="InterceptSuite%2FProxyBridge | Trendshift" width="250" height="55"/></a>
</p>

ProxyBridge is a free, open-source proxy client (Proxifier alternative) for **Windows**, **macOS**, **Linux**, **iOS** and **Android**. It forces the applications you choose to use a SOCKS5 or HTTP proxy for their TCP and UDP traffic, even apps with no proxy settings or that ignore them, with no changes to the app.

> [!TIP]
> **ProxyBridge routes your traffic - [InterceptSuite](https://interceptsuite.com) lets you see inside it.**
> Full MITM proxy with SSL/TLS inspection, live request editing, scripting, and support for TCP, UDP, StartTLS, DTLS, QUIC and more. Built by the same team. [**Try InterceptSuite →**](https://interceptsuite.com)

## Table of Contents

- [Download](#download)
- [Features](#features)
- [Screenshots](#screenshots)
- [Inspect redirected traffic with InterceptSuite](#inspect-redirected-traffic-with-interceptsuite)
- [License](#license)
- [Author](#author)
- [Credits](#credits)

<p align="center">
  <strong>💖 Support ProxyBridge Development</strong><br/>
  <em>If you find ProxyBridge useful, consider sponsoring to support ongoing development and new features!</em><br/><br/>
  <a href="https://github.com/sponsors/InterceptSuite">
    <img src="https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86" alt="Sponsor InterceptSuite" width="230" height="50">
  </a>
</p>

## Download

<p align="center">
  <a href="https://proxybridge.interceptsuite.com/download/">
    <strong>Download ProxyBridge</strong>
  </a>
  <br/>
  <sub>Windows x64 · macOS (x64 & arm64) · Linux (x64 & ARM64)</sub>
</p>

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.interceptsuite.ProxyBridge">
    <img src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" alt="Get it on Google Play" height="80" />
  </a>
</p>

The iOS app is still in testing, so there is no public release for it yet. You can build it from source, see [iOS](iOS/README.md). The Android app is in [Android](Android/README.md).

<p align="center">
  <a href="https://github.com/InterceptSuite/ProxyBridge/releases">Older versions</a>
</p>


> [!CAUTION]
> **Beware of fake ProxyBridge downloads.** Some unofficial sites distribute malware under the ProxyBridge name. Download only from this repository or [interceptsuite.com/download/proxybridge](https://proxybridge.interceptsuite.com/download/), or build from source. ProxyBridge contacts no server except its update feed (`download.interceptsuite.com/proxybridge.json`), on launch or when you check for updates.

## Features

- **Per-process routing** - send traffic from chosen applications through SOCKS5 or HTTP proxies, or direct, or block it
- **Works with proxy-unaware apps** - system-level interception, no changes to the application
- **TCP and UDP** - HTTP/HTTPS, HTTP/3, SSH, RDP, databases, games, DTLS, DNS and more
- **Flexible rules** - match processes, IPs, ports, protocols and host names, with wildcards and IPv4/IPv6
- **GUI and CLI** on Windows, macOS and Linux, with profiles and rule import/export
- **iOS and Android apps** - route a phone's traffic through a proxy by destination: domain, IP or CIDR, port and protocol

## Screenshots

- [macOS screenshots](MacOS/README.md#overview)
- [Windows screenshots](Windows/README.md#usage)
- [Linux screenshots](Linux/README.md#gui-application)
- [iOS screenshots](iOS/README.md#screenshots)
- [Android app](Android/README.md)


## Inspect redirected traffic with InterceptSuite

**[InterceptSuite](https://interceptsuite.com)** is a cross-platform MITM proxy for inspecting, intercepting, and modifying network traffic. Use ProxyBridge to redirect application or system traffic to InterceptSuite's SOCKS5 proxy and inspect supported protocols in real time.

With InterceptSuite, you can:

- **Intercept TLS/SSL:** Decrypt and inspect encrypted connections using MITM.
- **Inspect multiple protocols:** Work with TCP, UDP, STARTTLS, DTLS, QUIC, and custom protocols.
- **Modify traffic live:** Edit requests and responses before forwarding them.
- **Analyze and replay:** Inspect traffic and replay captured data during testing.
- **Automate workflows:** Use scripting to customize traffic handling and analysis.

**ProxyBridge gets the traffic to the proxy. InterceptSuite gives you the tools to inspect and work with it.**

[**Start your free trial — no credit card required →**](https://interceptsuite.com)

## License

MIT License - See LICENSE file for details

## Author

Sourav Kalal ([X](https://x.com/Ano_F_), [LinkedIn](https://www.linkedin.com/in/sourav-kalal/)) / InterceptSuite ([X](https://x.com/InterceptSuite), [LinkedIn](https://www.linkedin.com/company/interceptsuite/))

## Credits

**Windows Implementation:**
This project is built on top of [WinDivert](https://reqrypt.org/windivert.html) by basil00. WinDivert is a powerful Windows packet capture and manipulation library that makes kernel-level packet interception possible. Special thanks to the WinDivert project for providing such a robust foundation.

Based on the StreamDump example from WinDivert:
https://reqrypt.org/samples/streamdump.html

The Windows GUI and CLI are written in native C using the Win32 API, keeping the footprint small and startup instant.

**macOS Implementation:**
Built using Apple's Network Extension framework for transparent proxy capabilities on macOS.

**Linux Implementation:**
Built on eBPF with a GTK3 GUI. See [Linux/README.md](Linux/README.md).

**iOS Implementation:**
Built on a Network Extension packet tunnel. The packet stack that turns the device's packets into TCP connections and UDP flows is [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) by heiher (MIT licence), which includes lwIP and other open-source libraries. Special thanks to the hev-socks5-tunnel project. See [iOS/README.md](iOS/README.md).

**Android Implementation:**
Built on the Android `VpnService`. The packet stack that turns the device's packets into TCP connections and UDP flows is [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) by heiher (MIT licence), which includes lwIP and other open-source libraries. Special thanks to the hev-socks5-tunnel project. See [Android/README.md](Android/README.md).
