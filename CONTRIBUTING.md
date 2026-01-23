# Contributing to ProxyBridge

Thank you for your interest in contributing to ProxyBridge! We welcome contributions from the community to help make this project better.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to fostering an open and welcoming environment. We pledge to make participation in our project a harassment-free experience for everyone.

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs **actual behavior**
- **Screenshots** if applicable
- **Environment details**:
  - OS version (Windows 10/11, macOS version)
  - ProxyBridge version
  - Proxy server type (SOCKS5/HTTP)

### Suggesting Features

Feature suggestions are welcome! Please provide:

- **Clear use case** - explain the problem you're trying to solve
- **Proposed solution** - describe how the feature would work
- **Alternatives considered** - what other solutions did you think about?
- **Additional context** - mockups, examples, etc.

### Pull Requests

**IMPORTANT: Before Creating a Pull Request**

1. **Create a GitHub Issue First**
   - If you want to fix a bug or add a new feature, **create a GitHub issue first**
   - This allows us to track and confirm whether:
     - The feature is already implemented in our development branch
     - We plan to include that feature (some features may not align with project goals)
     - Your pull request will be accepted before you invest time coding
   - If a GitHub issue already exists for the bug/feature you want to work on:
     - Comment on the existing issue mentioning you plan to fix it
     - **Do NOT create a duplicate issue**

2. **Fork the `dev` Branch**
   - **Always fork and create pull requests against the `dev` branch**
   - **NEVER create pull requests against the `master` branch**
   - The `master` branch is only updated with new releases
   - All development work happens in the `dev` branch
   - Pull requests to `master` will be **automatically rejected**

3. **macOS Code Changes - Apple Developer Account Required**
   - If you are making changes to macOS code, you **MUST**:
     - Have a valid Apple Developer account ($99/year)
     - Have tested your code changes and verified they work as expected
     - Have proper code signing configured (see Apple Signing section below)
   - **Pull requests with untested macOS code will NOT be merged**
   - If you don't have an Apple Developer account and cannot test your changes, your PR will be rejected

**Standard Pull Request Process:**

1. Fork the repository (`dev` branch)
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request to the `dev` branch

## Development Setup

### Windows

**Prerequisites:**
- Visual Studio 2022 or later (with C++ tools)
- .NET 10.0 SDK
- PowerShell 5.1 or later
- Git
- **WinDivert 2.2.2-A** - Download from: https://www.reqrypt.org/windivert.html
- **NSIS** (optional, for building installer) - Download from: https://nsis.sourceforge.io/
  - **EnVar Plugin** (required for NSIS) - Download from: https://nsis.sourceforge.io/EnVar_plug-in
  - Install EnVar plugin to: `C:\Program Files (x86)\NSIS\Plugins\`
  - The installer uses EnVar to add ProxyBridge to system PATH

**WinDivert Setup:**
1. Download WinDivert 2.2.2-A from the official website
2. Extract to `C:\WinDivert-2.2.2-A\` (default path used by compile script)
3. Or extract to a different location and update the path in `compile.ps1`:
   ```powershell
   $WinDivertPath = "C:\Your\Custom\Path\WinDivert-2.2.2-A"
   ```

**Required WinDivert Files:**
- `WinDivert-2.2.2-A\include\windivert.h` (header file)
- `WinDivert-2.2.2-A\x64\WinDivert.lib` (import library)
- `WinDivert-2.2.2-A\x64\WinDivert.dll` (runtime library)
- `WinDivert-2.2.2-A\x64\WinDivert64.sys` (kernel driver)
- `WinDivert-2.2.2-A\x64\WinDivert32.sys` (32-bit driver)

**Setup:**
```powershell
# Clone the repository (dev branch)
git clone -b dev https://github.com/InterceptSuite/ProxyBridge.git
cd ProxyBridge/Windows

# Verify WinDivert is installed
Test-Path C:\WinDivert-2.2.2-A\include\windivert.h

# Build the project (auto-detects MSVC or GCC)
.\compile.ps1

# Or specify compiler explicitly
.\compile.ps1 -Compiler msvc    # Recommended
.\compile.ps1 -Compiler gcc     # Use MinGW-w64

# Build without code signing
.\compile.ps1 -NoSign
```

**What compile.ps1 Does:**
1. Compiles `ProxyBridgeCore.dll` from C source code (using MSVC or GCC)
2. Copies WinDivert runtime files (`WinDivert.dll`, `WinDivert64.sys`, `WinDivert32.sys`)
3. Publishes GUI app (`ProxyBridge.exe`) with .NET single-file deployment
4. Publishes CLI app (`ProxyBridge_CLI.exe`) as single executable
5. Optionally signs all binaries (requires code signing certificate)
6. Builds NSIS installer (`ProxyBridge-Setup-3.1.0.exe`) if NSIS is installed

**Output:**
All compiled files are placed in `Windows/output/` directory:
- `ProxyBridgeCore.dll` - Native C library
- `ProxyBridge.exe` - GUI application
- `ProxyBridge_CLI.exe` - CLI application
- `WinDivert.dll`, `WinDivert64.sys` - WinDivert files
- `ProxyBridge-Setup-3.1.0.exe` - Installer (if NSIS installed)
- Additional .NET runtime DLLs

**Project Structure:**
- `Windows/src/` - C library core (ProxyBridge.c, ProxyBridge.h)
  - `ProxyBridge.c` - Main packet interception logic
  - Uses WinDivert for kernel-level packet capture
- `Windows/gui/` - Avalonia GUI (.NET 10.0)
  - GUI application using Avalonia UI framework
- `Windows/cli/` - Command-line interface (.NET 10.0)
  - CLI application for headless operation
- `Windows/installer/` - NSIS installer script
  - `ProxyBridge.nsi` - Installer configuration
- `Windows/compile.ps1` - Build script
- `Windows/output/` - Compiled binaries (created by compile.ps1)

### macOS

**Prerequisites:**
- Xcode 15.0 or later
- macOS 13.0 (Ventura) or later
- Swift 5.9+
- Git
- **Valid Apple Developer Account** (required for code signing)
- **Provisioning Profiles** installed on your system

**Apple Developer Account & Code Signing:**

macOS development requires a valid Apple Developer account with proper signing configuration:

1. **Apple Developer Account:**
   - Sign up at: https://developer.apple.com/programs/
   - Cost: $99/year (required for System Extension development)
   - You need this to create Provisioning Profiles and sign the app

2. **Create Provisioning Profiles:**
   - Log in to Apple Developer Portal: https://developer.apple.com/account
   - Create two Provisioning Profiles:
     - **ProxyBridge Prod** - for the main GUI app
     - **ProxyBridge Extension Prod** - for the Network Extension
   - Download and install both profiles on your system (double-click to install)

3. **Configure Code Signing:**

   The project uses configuration files to manage signing credentials securely.

   **Step 1: Create config folder**
   ```bash
   cd MacOS/ProxyBridge
   mkdir config
   ```

   **Step 2: Copy template config files**
   ```bash
   # Copy template files from project root to config folder
   cp proxybridge-app.xcconfig config/Signing-Config-app.xcconfig
   cp proxybridge-ext.xcconfig config/Signing-Config-ext.xcconfig
   ```

   **Step 3: Edit config files with YOUR credentials**

   Edit `config/Signing-Config-app.xcconfig`:
   ```plaintext
   // MARK: - Team Configuration
   DEVELOPMENT_TEAM = YOUR_TEAM_ID              // Replace with your Team ID (e.g., L4HJT32Z59)

   // MARK: - Main App Signing (ProxyBridge)
   CODE_SIGN_STYLE = Manual
   CODE_SIGN_IDENTITY = Developer ID Application
   CODE_SIGN_ENTITLEMENTS = ProxyBridge/ProxyBridgeRelease.entitlements
   PRODUCT_BUNDLE_IDENTIFIER = com.interceptsuite.ProxyBridge
   PRODUCT_MODULE_NAME = ProxyBridge
   PRODUCT_NAME = ProxyBridge
   PROVISIONING_PROFILE_SPECIFIER = ProxyBridge Prod  // Your provisioning profile name

   // MARK: - Additional Signing Settings
   CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO
   ENABLE_HARDENED_RUNTIME = YES
   ```

   Edit `config/Signing-Config-ext.xcconfig`:
   ```plaintext
   // MARK: - Team Configuration
   DEVELOPMENT_TEAM = YOUR_TEAM_ID              // Replace with your Team ID

   // MARK: - Extension Signing
   CODE_SIGN_STYLE = Manual
   CODE_SIGN_IDENTITY = Developer ID Application
   CODE_SIGN_ENTITLEMENTS = extension/extensionRelease.entitlements
   PRODUCT_BUNDLE_IDENTIFIER = com.interceptsuite.ProxyBridge.extension
   PRODUCT_MODULE_NAME = com_interceptsuite_ProxyBridge_extension
   PROVISIONING_PROFILE_SPECIFIER = ProxyBridge Extension Prod  // Your extension profile name

   // MARK: - Additional Signing Settings
   CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO
   ENABLE_HARDENED_RUNTIME = YES
   ```

   **How to find your DEVELOPMENT_TEAM ID:**
   - Open Xcode → Settings → Accounts
   - Select your Apple ID → Click "Manage Certificates"
   - Your Team ID is shown next to your team name

   **Note:** The `config/` folder is in `.gitignore` to keep your credentials private.

**Setup:**
```bash
# Clone the repository (dev branch)
git clone -b dev https://github.com/InterceptSuite/ProxyBridge.git
cd ProxyBridge/MacOS/ProxyBridge

# Edit signing configuration files with your Apple Developer details
# proxybridge-app.xcconfig - for main app
# proxybridge-ext.xcconfig - for network extension

# Open in Xcode and configure signing (see steps above)
open ProxyBridge.xcodeproj
```

**Building the Application:**

**⚠️ IMPORTANT: Network Extension will NOT work with Debug builds!**

You **MUST** create a **Release build** for the Network Extension to function properly.

**Step-by-Step Build Process:**

1. **Configure Signing** (see "Apply Configuration Files in Xcode" above)

2. **Create Archive (Release Build):**
   ```
   In Xcode:
   - Select "ProxyBridge" scheme
   - Go to: Product → Archive
   - Wait for archive to complete
   ```

3. **Export the App:**
   ```
   After archive completes:
   - Xcode Organizer window will open automatically
   - Select your archive
   - Click "Distribute App"
   - Choose "Developer ID" (for distribution outside App Store)
   - Select "Export"
   - Choose export location: MacOS/ProxyBridge/output/
   - Click "Export"
   ```

   This will create a **signed and notarized** `ProxyBridge.app` in the output folder.

4. **Create PKG Installer (Optional):**
   ```bash
   # The build.sh script creates a PKG installer from the .app
   # It does NOT build the .app - you must export it from Xcode first

   cd MacOS/ProxyBridge

   # Verify ProxyBridge.app exists in output/
   ls -la output/ProxyBridge.app

   # Create PKG installer
   ./build.sh
   ```

   **What build.sh does:**
   - Checks for `output/ProxyBridge.app` (exits if not found)
   - Creates PKG installer: `output/ProxyBridge-v3.1-Universal-Installer.pkg`
   - Optionally signs and notarizes the PKG (requires .env file with credentials)

**Output:**
- `MacOS/ProxyBridge/output/ProxyBridge.app` - Release build (from Xcode Archive)
- `MacOS/ProxyBridge/output/ProxyBridge-v3.1-Universal-Installer.pkg` - PKG installer (from build.sh)

**Project Structure:**
- `MacOS/ProxyBridge/ProxyBridge/` - SwiftUI main app
- `MacOS/ProxyBridge/extension/` - Network Extension provider
- `MacOS/ProxyBridge/config/` - Your signing configuration (NOT in git)
- `MacOS/ProxyBridge/build.sh` - PKG installer creation script
- `MacOS/ProxyBridge/output/` - Exported .app and PKG installer
- `proxybridge-app.xcconfig` - Template config (in project root)
- `proxybridge-ext.xcconfig` - Template config (in project root)

## Pull Request Process

1. **Update documentation** - if your changes affect user-facing features
2. **Add tests** - for new functionality when applicable
3. **Follow coding standards** - see below
4. **Update CHANGELOG** - add a note about your changes
5. **One feature per PR** - keep pull requests focused
6. **Sign your commits** - use `git commit -s`

### PR Checklist

- [ ] Code builds without errors
- [ ] All tests pass
- [ ] Documentation updated
- [ ] No merge conflicts
- [ ] Commit messages are clear
- [ ] Code follows project style

## Coding Standards

All code submissions must follow these standards and optimization principles.

### AI-Generated Code

We **accept and welcome** code written with AI assistance (such as Claude, GitHub Copilot, or other AI coding tools), provided it meets our quality and optimization standards.

**Requirements for AI-Generated Code:**

1. **Code Quality Standards**
   - Code must be well-written, optimized, and follow project coding standards
   - Follow the same review process as manually written code
   - Must be thoroughly tested and verified before submission

2. **Optimization is Critical**
   - We take code optimization **very seriously**
   - All code must be optimized for performance and clarity
   - Contributors are responsible for understanding and optimizing AI-generated code

3. **Contributor Responsibility**
   - **Understand what the code does** - Don't blindly submit AI-generated code
   - **Review and optimize** - If code seems verbose or inefficient, refactor it
   - **Question verbosity** - If you feel the code is too large or can be written better, optimize it
   - **Benchmark when needed** - For performance-critical code, verify optimization claims

**Our Two Optimization Priorities:**

1. **Performance First**
   - Code must be optimized for best performance
   - Choose algorithms and data structures wisely
   - Minimize memory allocations, CPU cycles, and I/O operations
   - Profile performance-critical sections

2. **Simplicity and Brevity**
   - Prefer clear, concise code over verbose implementations
   - **If 10 lines can do what 20-30 lines do, use 10 lines**
   - Even without performance difference, we prefer shorter, clearer code
   - Avoid unnecessary abstractions, boilerplate, or redundant code
   - Write code that is easy to read, understand, and maintain

**Examples:**

✅ **Good - Optimized and concise:**
```c
// Fast hash lookup, minimal code
if (connection_table[hash] && connection_table[hash]->port == port) {
    return connection_table[hash];
}
```

❌ **Bad - Verbose, unnecessary:**
```c
// Same functionality but unnecessarily verbose
ConnectionInfo* info = connection_table[hash];
if (info != NULL) {
    if (info->port == port) {
        return info;
    }
}
return NULL;
```

**Before Submitting AI-Generated Code:**

- [ ] I understand what this code does and how it works
- [ ] I have reviewed it for optimization opportunities
- [ ] I have removed unnecessary code, variables, or abstractions
- [ ] I have verified it follows project coding standards
- [ ] I have tested it thoroughly
- [ ] Performance-critical code has been profiled/benchmarked
- [ ] Code is as simple and concise as possible while remaining clear

**Remember:** Using AI tools is encouraged, but you are responsible for the quality and optimization of the code you submit. AI-generated code that is verbose, inefficient, or poorly optimized will be rejected.

### C/C++ (Windows Core)

```c
// Use clear, descriptive names
static bool check_proxy_rules(const char *process, uint32_t dest_ip,
                               uint16_t dest_port, uint8_t proto)
{
    // Comments for complex logic
    if (!process || !dest_ip) return false;

    // Use consistent formatting
    for (int i = 0; i < rule_count; i++) {
        if (match_rule(&rules[i], process, dest_ip, dest_port, proto)) {
            return rules[i].action;
        }
    }

    return ACTION_DIRECT;
}
```

**Standards:**
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Always use braces for if/while/for blocks
- Declare variables close to usage
- Check for NULL/error conditions
- Free allocated memory
- Use meaningful variable names

### C# (Windows GUI/CLI)

```csharp
// Follow .NET naming conventions
public class ProxySettingsViewModel : ViewModelBase
{
    private string _proxyHost = "127.0.0.1";

    // Properties use PascalCase
    public string ProxyHost
    {
        get => _proxyHost;
        set => this.RaiseAndSetIfChanged(ref _proxyHost, value);
    }

    // Methods use PascalCase
    public async Task SaveSettingsAsync()
    {
        // Use meaningful names
        var settings = new ProxySettings
        {
            ProxyHost = ProxyHost,
            ProxyPort = ProxyPort
        };

        await _configManager.SaveAsync(settings);
    }
}
```

**Standards:**
- Use 4 spaces for indentation
- Follow C# naming conventions (PascalCase for public, camelCase for private)
- Use `async/await` for asynchronous operations
- Handle exceptions appropriately
- Use `using` statements for IDisposable
- Add XML documentation comments for public APIs

### Swift (macOS)

```swift
// Use Swift naming conventions
class ProxyBridgeViewModel: ObservableObject {
    @Published var proxyHost: String = "127.0.0.1"
    @Published var proxyPort: String = "1080"

    // Use descriptive parameter names
    func saveProxySettings(host: String, port: UInt16) async throws {
        // Guard for early returns
        guard !host.isEmpty else {
            throw ProxyError.invalidHost
        }

        // Use clear, self-documenting code
        let settings = ProxySettings(host: host, port: port)
        try await configManager.save(settings)
    }
}
```

**Standards:**
- Use 4 spaces for indentation
- Follow Swift naming conventions (camelCase)
- Use `guard` for early returns
- Prefer `let` over `var` when possible
- Use optionals appropriately
- Add documentation comments for public APIs


### Manual Testing Checklist

- [ ] Proxy connection works (SOCKS5)
- [ ] Proxy connection works (HTTP)
- [ ] Rules are applied correctly
- [ ] Direct connections bypass proxy
- [ ] Blocked connections are denied
- [ ] TCP traffic routes correctly
- [ ] UDP traffic routes correctly
- [ ] GUI updates reflect changes
- [ ] Settings persist after restart
- [ ] No memory leaks
- [ ] Clean shutdown/cleanup

## Commit Messages

Use clear, descriptive commit messages:

```
Good:
✅ Fix memory leak in connection table cleanup
✅ Add support for wildcard IP matching
✅ Update GUI to show connection count

Bad:
❌ fix bug
❌ update
❌ wip
```

### Format:
```
<type>: <subject>

<body (optional)>

<footer (optional)>
```

**Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code formatting (no functional changes)
- `refactor:` - Code restructuring
- `test:` - Adding/updating tests
- `chore:` - Maintenance tasks

## Questions?

- Open an issue for discussion
- Check existing issues and discussions
- Contact: [GitHub Issues](https://github.com/InterceptSuite/ProxyBridge/issues)

## License

By contributing to ProxyBridge, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to ProxyBridge! 🎉
