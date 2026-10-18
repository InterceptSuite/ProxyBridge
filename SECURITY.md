# Security Policy

## Supported Versions

We actively support the following versions of ProxyBridge with security updates. Each platform has its own release line:

| Platform | Supported version | Supported          |
| -------- | ----------------- | ------------------ |
| Windows  | 4.2.x             | :white_check_mark: |
| macOS    | 4.1.x             | :white_check_mark: |
| Linux    | 4.x.x             | :white_check_mark: |

Older releases are **not supported** and do not receive security updates:

| Platform | Not supported            |
| -------- | ------------------------ |
| Windows  | 4.1.x and earlier        |
| macOS    | 4.0.x and earlier        |
| Linux    | earlier than 4.0.0       |

**Note:** Only the latest release line of each platform receives security updates. Please upgrade to the latest version of your platform to ensure you have all security fixes.

## Reporting a Vulnerability

We take the security of ProxyBridge seriously. If you discover a security vulnerability, please follow these steps:

### 🔒 Please DO NOT:

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it has been addressed
- Share the vulnerability with third parties

### ✅ Please DO:

1. **Report privately via GitHub Security Advisories:**
   - Go to: https://github.com/InterceptSuite/ProxyBridge/security/advisories
   - Click "Report a vulnerability"
   - Fill in the details

2. **Or email directly:**
   - Email: security@interceptsuite.com (if available)
   - Subject: `[SECURITY] ProxyBridge Vulnerability Report`

### What to Include

Please provide as much information as possible:

- **Vulnerability type** (e.g., privilege escalation, code injection, etc.)
- **Affected versions** (e.g., 3.1.0, all versions, etc.)
- **Platform** (Windows, macOS, or both)
- **Step-by-step reproduction** instructions
- **Proof of concept** or exploit code (if applicable)
- **Impact assessment** - what can an attacker achieve?
- **Suggested fix** (if you have one)

### What to Expect

- **Initial Response:** Within 48 hours
- **Assessment:** Within 7 days we'll confirm the issue and severity
- **Fix Timeline:**
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: Next release cycle
- **Disclosure:** We'll coordinate with you on public disclosure timing
- **Credit:** We'll acknowledge your contribution (unless you prefer to remain anonymous)

## Security Considerations

### ProxyBridge Security Model

ProxyBridge is an **open-source project** and does not provide monetary rewards or bug bounty programs for vulnerability reports. Some vulnerabilities may be applicable for CVE assignments through standard disclosure processes.

ProxyBridge operates with the following security considerations:

#### Windows Architecture
- **Three Components:**
  - **ProxyBridgeCore.dll** - Native C library for packet interception (WinDivert-based)
  - **ProxyBridge.exe** - Native C (Win32) GUI application
  - **ProxyBridge_CLI.exe** - Native C command-line interface application
- **Requires Administrator privileges** to install and run WinDivert kernel driver
- **Kernel-level packet interception** via WinDivert.sys driver
- **Local TCP relay server** runs on port 34010 (127.0.0.1 only)
- **Local UDP relay server** runs on port 34011 (127.0.0.1 only)
- **No remote access** - relay servers bind to localhost only, not exposed to network
- **Credential storage** - proxy credentials (username/password) stored in **plaintext** in `%APPDATA%\ProxyBridge\config.json`
- **Configuration storage** - all rules and settings in JSON format at `%APPDATA%\ProxyBridge\config.json`

#### macOS Architecture
- **Two Components:**
  - **ProxyBridge.app** - SwiftUI-based GUI application (sandboxed)
  - **ProxyBridge Extension** - Network Extension (System Extension, runs with elevated privileges)
- **Requires System Extension approval** via System Settings
- **Network Extension runs as system daemon** - operates at network layer with elevated privileges
- **App Sandbox** for main GUI application with limited permissions
- **Two providers in one extension process:**
  - an **app proxy provider** (transparent proxy) that redirects matching TCP and UDP flows to the configured proxy
  - a **DNS proxy provider** that forwards the system's UDP DNS queries unchanged to the real resolver and records which domain names resolved to which IP addresses, so domain rules and the "Let proxy resolve DNS (send hostname)" option work. This table is kept **in memory only** (it is not written to disk) and is cleared when the extension starts and stops
- **Network Extension Entitlements:**
  - `com.apple.developer.networking.networkextension` - the app and extension are signed with the full set of Network Extension capabilities that Apple's provisioning grants. ProxyBridge itself only uses the app proxy provider and the DNS proxy provider (`app-proxy-provider-systemextension`, `dns-proxy-systemextension`)
  - `com.apple.developer.system-extension.install` (app) to install the System Extension
  - `com.apple.security.network.client` and `com.apple.security.network.server`
  - `com.apple.security.application-groups`
- **Hardened runtime** is enabled for both the app and the extension
- **Command line mode** - the app's own executable also runs without a window when started with options (`proxybridge --profile ...`). It is not a separate program, so it has the same signature, entitlements and sandbox. Profiles are read by name or from standard input and are not accepted as command line arguments, so proxy credentials do not appear in the process list. The `proxybridge` command is a short shell launcher installed by the package
- **Credential storage** - proxy credentials and configuration stored in **UserDefaults** (not Keychain)
  - UserDefaults stored at: `~/Library/Containers/com.interceptsuite.ProxyBridge/Data/Library/Preferences/`
  - **Not encrypted** - stored in plaintext plist format
- **No remote access** - all configuration is local via IPC to System Extension

### Known Limitations

1. **Proxy Credentials - PLAINTEXT STORAGE:**
   - **Windows:** Stored in **plaintext** in `%APPDATA%\ProxyBridge\config.json`
     - Username and password visible to anyone with file access
     - Readable by all processes running under the same user
   - **macOS:** Stored in **plaintext** in UserDefaults plist files
     - Located at: `~/Library/Containers/com.interceptsuite.ProxyBridge/Data/Library/Preferences/`
     - Not using Keychain - credentials stored unencrypted

2. **Local Relay Server (Windows):**
   - **TCP relay on 127.0.0.1:34010** - handles proxied connections
   - **UDP relay on 127.0.0.1:34011** - handles SOCKS5 UDP ASSOCIATE
   - Only binds to localhost (not exposed to network)
   - **Risk:** Local processes could potentially interact with relay servers

3. **Process Privilege:**
   - **Windows:** Requires Administrator to install/run WinDivert driver
     - Core DLL runs with administrator privileges
     - GUI/CLI apps run as administrator
   - **macOS:** Network Extension runs as system daemon with elevated privileges
     - Has broad network interception capabilities
     - GUI app runs sandboxed with limited privileges
   - **Impact:** Vulnerabilities in core components could lead to privilege escalation or system compromise
4. **Local File Access:**
   - Configuration files readable by all local administrators
   - **Windows:** `%APPDATA%\ProxyBridge\` accessible to user and admins
   - **macOS:** App Container accessible to user and admins

5. **Third-party Dependencies:**
   - **Windows:**
     - WinDivert 2.x (kernel driver + userspace library) - trusted, open-source
   - **macOS:**
     - Apple NetworkExtension framework (system component)
     - Swift standard library
   - **Monitoring:** We track security advisories for all dependencies
   - **Update Policy:** Dependencies are updated when security issues are published

### Accepted Risks

These are known and have been reviewed. We have decided to accept them, usually because the alternative would break a feature or the platform does not allow a better option. Please take them into account when deciding where to use ProxyBridge.

1. **Proxy credentials are stored in plaintext** (see Known Limitations above). We do not plan to move them to the Keychain or Credential Manager at this time.
2. **Exported profiles contain proxy credentials.** Exporting a profile (`.pbprofile`) on macOS and Windows writes each proxy's username and password into the file in plaintext, and the Linux profile format has the same fields. Treat an exported profile like a password file: do not post it in issues, chat or repositories.
3. **Updates are not verified beyond HTTPS.** The built-in update check and download use HTTPS to `download.interceptsuite.com`. The macOS app does not additionally verify a signature or hash of the downloaded installer before opening it (the installer itself is code-signed and notarized). If the update server were compromised, a manifest and its hash could be changed together, so an extra hash would not change that. If you want stronger assurance, skip the built-in update and download the installer from the official sources listed below.
4. **macOS requests the full Network Extension entitlement set.** See "macOS Architecture". Only the app proxy and DNS proxy providers are used.
5. **Imported rules and profiles are not strictly validated** (macOS). Only import rule and profile files from sources you trust.
6. **No heartbeat between the macOS app and its extension.** If the app crashes or is force-quit, the System Extension keeps its rules and proxy settings until the app is started again or the extension is stopped. Traffic that matches a proxy rule keeps being sent to the configured proxy. Quitting the app normally clears the rules and settings.
7. **A proxy that is down is not bypassed.** If a rule sends traffic to a proxy that cannot be reached or returns an error, the application's connection fails and the error is logged. ProxyBridge does not silently send that traffic direct. Remove the rule to let the application connect directly.

### Known Issues

#### All platforms
- **UDP only works through SOCKS5 proxies.** HTTP proxies cannot carry UDP. UDP traffic that matches a rule pointing to an HTTP proxy is sent direct (macOS logs a one-time error for this). If you need UDP to be proxied, use a SOCKS5 proxy that supports UDP ASSOCIATE.
- **Hostnames are sent to proxies by default.** The "Let proxy resolve DNS (send hostname)" option (on by default for new proxies) makes ProxyBridge hand the proxy the host name an application looked up instead of the IP address. Turn it off for a proxy that should only receive IP addresses or that cannot resolve the names your computer can.

#### macOS
- **UDP rules match on the process only.** macOS does not tell the extension where a UDP flow is going when it is created, so the target host and port of a UDP rule are not used for matching. A UDP rule applies to all UDP traffic of the matched process. This is a macOS limitation.
- **Clients that half-close cannot receive a reply.** A client that sends data, closes only its sending side and then waits for a reply (for example `nc` with piped input) does not get the reply through a transparent proxy flow, because macOS closes the flow itself. Clients that keep the connection open are not affected.
- **The legacy Network Extension connection API is deprecated by Apple** (macOS 15) but is still used by the extension. It works on all supported macOS versions. Migration depends on the minimum macOS version we support.
- **Fixed in 4.1.x (not in 4.0.x and earlier):**
  - UDP flows could keep their proxy connections open after the application closed them, using memory and file descriptors, and could cause high CPU use (#239, #226)
  - the installer asked Apple silicon Macs to install Rosetta
  - the app quit when the menu bar icon's menu was dismissed (#233)
  - the About page showed an old version number (#231)

## Security Best Practices for Users

### Installation

1. **Download from official sources only:**
   - ✅ GitHub Releases: https://github.com/InterceptSuite/ProxyBridge/releases
   - ✅ Official website https://interceptsuite.com
   - ❌ Third-party download sites

2. **Verify signatures** (when available):
   - Windows: Check code signing certificate
   - macOS: Check notarization status



## Vulnerability Disclosure Policy

### Timeline

1. **Day 0:** Vulnerability reported
2. **Day 2:** Initial response and acknowledgment
3. **Day 7:** Severity assessment completed
4. **Day 14-60:** Fix developed and tested (depending on severity)
5. **Release:** Security update published
6. **+7 days:** Public disclosure (coordinated with reporter)

### Credit Policy

We believe in giving credit where it's due:

- Security researchers will be credited in:
  - Security advisory
  - Release notes
  - CHANGELOG.md
  - GitHub Security Advisories

- You may choose to:
  - Be credited by name/handle
  - Remain anonymous
  - Include company/affiliation

### Severity Levels

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Remote code execution, privilege escalation, credential theft | Arbitrary code execution via crafted packet, kernel driver exploit, credential extraction from memory |
| **High** | Authentication bypass, sensitive data exposure, DoS | Bypass process rules, config file exposure, relay server abuse, crash with system impact |
| **Medium** | Information disclosure, local DoS, logic errors | Connection log information leak, application crash, rule matching bypass |
| **Low** | Minor issues with limited security impact | UI rendering issue, non-security configuration bug, cosmetic issues |

**Note:** This is an open-source project. We do not offer monetary rewards or bug bounty payments. However:
- Security researchers will receive public credit (if desired)
- Some vulnerabilities may qualify for CVE assignment
- We coordinate responsible disclosure with reporters
- Contributions that fix vulnerabilities are highly valued

## Security Updates

Security updates are distributed via:

1. **GitHub Releases** - Primary distribution
2. **GitHub Security Advisories** - Notification system
3. **CHANGELOG.md** - Documented in release notes

### How to Stay Updated

- ⭐ **Star** the repository for notifications
- 👁️ **Watch** releases on GitHub
- 📧 Subscribe to GitHub Security Advisories
- 🔔 Enable update checks in ProxyBridge settings

## Past Security Advisories

Currently no published security advisories.

When vulnerabilities are discovered and fixed, they will be listed here with:
- CVE identifier (if applicable)
- Severity rating
- Affected versions
- Fix version
- Brief description

## Contact

For security concerns:
- **Private:** GitHub Security Advisories
- **General:** GitHub Issues (non-security bugs only)
- **Project:** https://github.com/InterceptSuite/ProxyBridge

## Acknowledgments

We thank the security research community for helping keep ProxyBridge secure. Special thanks to:

- *(Security researchers who responsibly disclose vulnerabilities will be listed here)*

---

**Last Updated:** October 2026

Thank you for helping keep ProxyBridge and our users safe! 🛡️
