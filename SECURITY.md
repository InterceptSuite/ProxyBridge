# Security Policy

## Supported Versions

We actively support the following versions of ProxyBridge with security updates:

| Version | Supported          | Platform |
| ------- | ------------------ | -------- |
| 3.1.x   | :white_check_mark: | Windows, macOS |
| 3.0.x   | :x:                | Windows, macOS |
| < 3.0   | :x:                | All      |

**Note:** Only the latest minor version (3.1.x) receives security updates. Please upgrade to the latest version to ensure you have all security fixes.

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
  - **ProxyBridge.exe** - Avalonia-based GUI application (.NET 10.0)
  - **ProxyBridge_CLI.exe** - Command-line interface application (.NET 10.0)
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
- **Network Extension Entitlements:**
  - `com.apple.developer.networking.networkextension` (app-proxy-provider-systemextension)
  - `com.apple.security.network.client` and `com.apple.security.network.server`
  - `com.apple.security.application-groups` for inter-process communication
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
     - Avalonia UI 11.x framework
     - .NET 10.0 runtime
   - **macOS:**
     - Apple NetworkExtension framework (system component)
     - Swift standard library
   - **Monitoring:** We track security advisories for all dependencies
   - **Update Policy:** Dependencies are updated when security issues are published

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

**Last Updated:** January 2026

Thank you for helping keep ProxyBridge and our users safe! 🛡️
