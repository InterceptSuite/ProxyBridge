# ProxyBridge

<p align="center">
  <img src="img/logo.png" alt="ProxyBridge Logo" />
</p>

ProxyBridge is a lightweight, open-source universal proxy client (Proxifier alternative) that provides transparent proxy routing for applications on **Windows** and **macOS**. It redirects TCP and UDP traffic from specific processes through SOCKS5 or HTTP proxies, with the ability to route, block, or allow traffic on a per-application basis. ProxyBridge fully supports both TCP and UDP proxy routing and works at the system level, making it compatible with proxy-unaware applications without requiring any configuration changes.

> 🚀 **Need advanced traffic analysis?** Check out [**InterceptSuite**](https://github.com/InterceptSuite/InterceptSuite) - our comprehensive MITM proxy for analyzing TLS, TCP, UDP, DTLS traffic. Perfect for security testing, network debugging, and system administration!

<p align="center">
  <a href="https://github.com/sponsors/Anof-cyber">
    <img src="https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86" alt="Sponsor Anof-cyber" width="230" height="50">
  </a>
</p>

## Table of Contents

- [Features](#features)
- [Platform Documentation](#platform-documentation)
- [Screenshots](#screenshots)
- [Use Cases](#use-cases)
- [License](#license)
- [Author](#author)
- [Credits](#credits)

## Features

- **Cross-platform** - Available for Windows and macOS
- **Dual interface** - Feature-rich GUI and powerful CLI for all use cases
- **Process-based traffic control** - Route, block, or allow traffic for specific applications
- **Universal compatibility** - Works with proxy-unaware applications
- **Multiple proxy protocols** - Supports SOCKS5 and HTTP proxies
- **System-level interception** - Reliable packet capture at kernel/network extension level
- **No configuration needed** - Applications work without any modifications
- **Protocol agnostic** - Compatible with TCP and UDP protocols (HTTP/HTTPS, HTTP/3, databases, RDP, SSH, games, DTLS, DNS, etc.)
- **Traffic blocking** - Block specific applications from accessing the internet or any network (LAN, localhost, etc.)
- **Flexible rules** - Direct connection, proxy routing, or complete blocking per process
- **Advanced rule configuration** - Target specific processes, IPs, ports, protocols (TCP/UDP), and hostnames with wildcard support
- **Process exclusion** - Prevent proxy loops by excluding proxy applications
- **Import/Export rules** - Share rule configurations across systems with JSON-based import/export

## Platform Documentation

<a href="https://github.com/sponsors/Anof-cyber"><img src="https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86" alt="Sponsor Anof-cyber" width="230" height="50"></a>

## Platform Documentation

ProxyBridge is available for both Windows and macOS, with platform-specific implementations:

### 📘 [Windows Documentation](Windows/README.md)
- **Technology**: WinDivert for kernel-level packet interception
- **Installer**: Available from [Releases](https://github.com/InterceptSuite/ProxyBridge/releases)
- **Requirements**: Windows 10 or later (64-bit), Administrator privileges
- **GUI**: Avalonia-based modern interface
- **CLI**: Full-featured command-line tool with rule file support

### 📗 [macOS Documentation](MacOS/README.md)
- **Technology**: Network Extension framework with transparent proxy
- **Distribution**: Direct download (.pkg installer) from [Releases](https://github.com/InterceptSuite/ProxyBridge/releases)
- **Requirements**: macOS 13.0 (Ventura) or later, Apple Silicon (ARM) or Intel
- **GUI**: Native SwiftUI interface

## Screenshots

### macOS

<p align="center">
  <img src="img/ProxyBridge-mac.png" alt="ProxyBridge macOS Main Interface" width="800"/>
  <br/>
  <em>ProxyBridge GUI - Main Interface</em>
</p>

<p align="center">
  <img src="img/proxy-setting-mac.png" alt="Proxy Settings macOS" width="800"/>
  <br/>
  <em>Proxy Settings Configuration</em>
</p>

<p align="center">
  <img src="img/proxy-rule-mac.png" alt="Proxy Rules macOS" width="800"/>
  <br/>
  <em>Proxy Rules Management</em>
</p>

<p align="center">
  <img src="img/proxy-rule2-mac.png" alt="Add/Edit Rule macOS" width="800"/>
  <br/>
  <em>Add/Edit Proxy Rule</em>
</p>

### Windows

#### GUI

<p align="center">
  <img src="img/ProxyBridge.png" alt="ProxyBridge Windows Main Interface" width="800"/>
  <br/>
  <em>ProxyBridge GUI - Main Interface</em>
</p>

<p align="center">
  <img src="img/proxy-setting.png" alt="Proxy Settings" width="800"/>
  <br/>
  <em>Proxy Settings Configuration</em>
</p>

<p align="center">
  <img src="img/proxy-rule.png" alt="Proxy Rules" width="800"/>
  <br/>
  <em>Proxy Rules Management</em>
</p>

<p align="center">
  <img src="img/proxy-rule2.png" alt="Add/Edit Rule" width="800"/>
  <br/>
  <em>Add/Edit Proxy Rule</em>
</p>

#### CLI

<p align="center">
  <img src="img/ProxyBridge_CLI.png" alt="ProxyBridge CLI" width="800"/>
  <br/>
  <em>ProxyBridge CLI Interface</em>
</p>

## Use Cases

- Redirect proxy-unaware applications (games, desktop apps) through InterceptSuite/Burp Suite for security testing
- Route specific applications through Tor, SOCKS5 or HTTP proxies
- Intercept and analyze traffic from applications that don't support proxy configuration
- Test application behavior under different network conditions
- Analyze protocols and communication patterns

## License

MIT License - See LICENSE file for details

## Author

Sourav Kalal / InterceptSuite

## Credits

**Windows Implementation:**
This project is built on top of [WinDivert](https://reqrypt.org/windivert.html) by basil00. WinDivert is a powerful Windows packet capture and manipulation library that makes kernel-level packet interception possible. Special thanks to the WinDivert project for providing such a robust foundation.

Based on the StreamDump example from WinDivert:
https://reqrypt.org/samples/streamdump.html

The Windows GUI is built using [Avalonia UI](https://avaloniaui.net/) - a cross-platform XAML-based UI framework for .NET, enabling a modern and responsive user interface.

**macOS Implementation:**
Built using Apple's Network Extension framework for transparent proxy capabilities on macOS.
