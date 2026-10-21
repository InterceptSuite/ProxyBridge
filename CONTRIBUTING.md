# Contributing to ProxyBridge

Thank you for your interest in contributing to ProxyBridge! We welcome contributions from the community to help make this project better.

## Table of Contents

- [Read This Before You Open a Pull Request](#read-this-before-you-open-a-pull-request)
- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## Read This Before You Open a Pull Request

> [!IMPORTANT]
> **Thank you for wanting to contribute!** Please take a couple of minutes to read this short guide before you start.
> Pull requests that don't follow it are hard for us to review, so they are usually closed straight away, sometimes without a detailed reply. It is nothing personal. We simply want to protect your time and ours.

### Why we ask for this

We would love to receive your work, and a pull request that follows this guide is warmly welcome. Here is why we ask for a little preparation up front:

- **It looks like one small project, but it is a bigger one.** ProxyBridge is a single repository, but it holds **three different applications with three different code bases**: Windows, macOS and Linux. They share a goal, not code, and they use different languages, drivers, APIs, builds and tests. **One person maintains all of them**, and more platforms (such as Android and iOS) are planned. If you use ProxyBridge on one platform, it is natural to see it as one app. From our side it is three, with more to come.
- **We want the full picture from the pull request itself.** With this much code on this many platforms, we cannot always tell from a bare pull request what it is for, how it was tested, or whether we already know about it. The template, the linked issue and your test details give us that before we start reviewing.
- **We keep open the work we have already talked about.** Those are pull requests for a bug or feature we already know about, where someone said on the issue that they would fix it and how, and where the testing is shown. That is why we ask you to comment on the issue first.
- **The goal is to save effort, yours and ours.** We want to avoid pull requests that don't fit the project's goals, fix something that is already fixed on another branch, or add a bug fix or feature we didn't know about. Those take a lot of time to review and nobody benefits.

If you are unsure about anything, just ask on the issue. That is exactly what it is there for.

### The five things to know

**1. Please open your pull request against `dev`.**
- Fork the `dev` branch, create your branch from it, and open the pull request against `dev`.
- `master` only changes when we publish a release. A pull request opened against any other branch is closed right away, usually without a comment, so please double-check the target branch before you create it.

**2. Please fill in the pull request template.**
- The template tells us **what** you changed, **how**, **why**, **which platform** and **how you tested it**. We need those details to review your work.
- Use the template for your platform (see [Pull request templates](#pull-request-templates-and-the-automatic-check)). It also asks what tests you ran locally and what the result was, even though the checks on GitHub run too.
- An **automatic check** looks at every pull request. If something is missing it adds a `needs-details` label and a friendly comment that lists exactly what to add. If the template is removed, if sections are deleted, or if the requested details stay empty, we are not able to review the pull request and it will be closed.

**3. Please link an issue, and comment on it before you start.**

A link to an issue on its own is not enough. Before you write the code, please:

1. **comment on the issue**, saying you would like to fix the bug or add the feature, and
2. **wait for a maintainer to reply.**

Why: many features and fixes are already done on `dev`, on another branch, or locally on our side, and unreleased work is not visible to you. Some issues are not valid or are not part of the project's goals. A quick comment first saves **you** from building something we cannot use. The automatic check looks at the linked issue: it should exist, show a comment from you before the pull request was opened, and show a reply from someone else. A pull request with no linked issue, or for an issue that was not discussed first, cannot be accepted. Opening a new issue and a pull request at the same time does not count as asking first. If an issue already exists, please comment on it instead of opening a duplicate.

**4. macOS: please sign and test it yourself.**
- The macOS app needs Apple signing to run its system extension, so we can only accept macOS changes that **you** were able to build, sign and test on a real Mac. See [macOS](#macos) and [Testing](#testing).
- We are not able to sign, build or test macOS changes on your behalf.
- macOS has its own test suite in [`MacOS/tests`](MacOS/tests). It runs **locally**, not in GitHub Actions, because a person has to approve the system extension on the Mac. Please tell us in your pull request what you tested and what the results were (macOS version, chip, how you signed, which tests you ran, the output).
- If you can't sign the app, that is completely fine. Describe the bug or idea on the issue instead, and we will take care of it in a future release.

**5. Please make sure the existing tests pass on every platform.**
- Pull requests for **all** platforms need to pass the existing tests and checks. See [Testing](#testing) for what runs on each platform.
- When you fix a bug or change behavior and the platform has a test suite (Linux and macOS do), a new test for it is very welcome.

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

Read [Read This Before You Open a Pull Request](#read-this-before-you-open-a-pull-request) first. In short: pull request to **`dev`** only, **complete template**, a **linked issue you commented on first**, **signed macOS testing** for macOS changes, and **all existing tests passing**.

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
- Visual Studio 2022 or later (with the "Desktop development with C++" workload) - the core DLL, CLI and GUI are all native C built with `cl.exe`
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
3. Builds the native C GUI (`ProxyBridge.exe`) with `cl.exe`
4. Builds the native C CLI (`ProxyBridge_CLI.exe`) as a single executable
5. Optionally signs all binaries (requires code signing certificate)
6. Builds NSIS installer (`ProxyBridge-Setup-4.3.0.exe`) if NSIS is installed

**Output:**
All compiled files are placed in `Windows/output/` directory:
- `ProxyBridgeCore.dll` - Native C library
- `ProxyBridge.exe` - Native C GUI application
- `ProxyBridge_CLI.exe` - Native C CLI application
- `WinDivert.dll`, `WinDivert64.sys` - WinDivert files
- `ProxyBridge-Setup-4.3.0.exe` - Installer (if NSIS installed)

**Running the tests:**
```powershell
cd ProxyBridge/Windows
.\tests\run_tests.ps1                 # build and run everything (exit code 0 = all passed)
.\tests\run_tests.ps1 -SkipUi         # without the two GUI tests (no desktop session)
.\tests\run_tests.ps1 -Only test_engine,test_cli
```
The tests are small console programs in `Windows/tests/` compiled from the real source files; they never load the
WinDivert driver or reach the internet (only the WinDivert headers and import library are needed; a few tests use
loopback sockets or private named pipes). They cover rule matching, profiles and the JSON parser, the DNS reply parser,
the SOCKS5/HTTP handshakes against a fake proxy, the service's request handler and pipe permissions, the connection
table, the CLI helpers, and the GUI windows (created for real, with a stubbed engine). A set of static checks also
verifies that the version number agrees everywhere and that the installer script keeps its safety properties. The `Build Windows` workflow runs the same script on every push and pull
request, before the build. **Please add or update a test when you change behavior**, for example a new rule-matching
case in `test_engine.c`, a profile-format change in `test_profile.c`, or a new window feature in `test_rules_ui.c` /
`test_main_ui.c`.

**Real-traffic end-to-end test:** `Windows/tests/e2e/run_e2e.ps1` is the opposite of the unit tests: it runs the real engine and WinDivert driver (through `ProxyBridge_CLI.exe`) with a real SOCKS5 proxy (Nexus Proxy), a small HTTP proxy and real requests to real servers, and checks that traffic goes where the rules say (SOCKS5, HTTP proxy, login, Direct, Block, domain and CIDR rules, UDP, an HTTPS download with a checksum). Because it loads a kernel driver and redirects the machine's traffic, it runs only on the CI runner (the `Build Windows` workflow, best effort, logs in the `ProxyBridge-E2E-Logs` artifact) and refuses to run anywhere else unless you pass `-IKnowThisLoadsTheKernelDriver` on a throw-away VM.

**Project Structure:**
- `Windows/src/` - C library core (ProxyBridge.c, ProxyBridge.h)
  - `ProxyBridge.c` - Main packet interception logic
  - Uses WinDivert for kernel-level packet capture
- `Windows/gui/` - Native C (Win32) GUI application
  - `main.c` - entry point and main window; `ui/`, `api/`, `loc/`, `profile/`, `res/` subfolders
- `Windows/cli/` - Native C command-line interface
  - `main.c` - CLI application for headless operation
- `Windows/installer/` - NSIS installer script
  - `ProxyBridge.nsi` - Installer configuration
- `Windows/tests/` - Test programs and `run_tests.ps1` (run by the Windows workflow)
- `Windows/compile.ps1` - Build script
- `Windows/output/` - Compiled binaries (created by compile.ps1)

### macOS

**Prerequisites:**
- A Mac with a recent macOS and **Xcode 16 or later** (the project uses file-system synchronized groups, which need Xcode 16+; we build with the latest stable Xcode)
- The app supports **macOS 13.0 (Ventura) or later** (that is the project's deployment target) and builds universal (`arm64` and `x86_64`)
- Swift language mode 5 (`SWIFT_VERSION = 5.0`). **No third-party libraries**: the app uses only Apple frameworks (SwiftUI, AppKit, NetworkExtension, SystemExtensions, ServiceManagement)
- Git
- **Valid Apple Developer Account** (required for code signing and for the System Extension)
- **Provisioning Profiles** installed on your system
- For the macOS tests: **Python 3** and a **C compiler** (both come with the Xcode command line tools)

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

   **Bundle identifiers:** the identifiers and the app group used by the project (`com.interceptsuite.ProxyBridge`, `com.interceptsuite.ProxyBridge.extension`, `group.com.interceptsuite.ProxyBridge`) belong to InterceptSuite's Apple team, so your team cannot sign with them. Use **your own identifiers** for local signing and testing. Set them in your `config/Signing-Config-*.xcconfig` files and update every place that refers to them. Find all of them with:

   ```bash
   cd MacOS/ProxyBridge
   grep -rn "com.interceptsuite" . --exclude-dir=output --exclude-dir=build
   ```

   The places that matter are `ProxyBridge.xcodeproj/project.pbxproj`, the two `*Release.entitlements` files, `extension/AppProxyProvider.swift` (the extension skips its own traffic by bundle ID), `ProxyBridge/ProxyBridgeViewModel.swift` (the app activates the extension by ID) and `extension/DNSMapStore.swift` (app group). **Do not include your identifier or signing changes in your pull request.**

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
   - Checks that the app and the extension are **universal** (`arm64` and `x86_64`)
   - Checks that `VERSION` at the top of `build.sh` matches `MARKETING_VERSION` in the Xcode project (it fails if they differ, so bump both together when the version changes)
   - Creates the PKG installer `output/ProxyBridge-v<VERSION>-Universal-Installer.pkg`. Its `distribution.xml` declares `hostArchitectures="x86_64,arm64"`, so Apple silicon Macs do not ask to install Rosetta. Keep that attribute
   - Optionally signs and notarizes the PKG (requires a `.env` file with credentials). Without it you get an unsigned PKG, which is fine for local testing

**Output:**
- `MacOS/ProxyBridge/output/ProxyBridge.app` - Release build (from Xcode Archive)
- `MacOS/ProxyBridge/output/ProxyBridge-v<VERSION>-Universal-Installer.pkg` - PKG installer (from build.sh)

**Re-installing a rebuilt extension:** macOS only replaces an installed system extension when its version changes. When you rebuild the same version for testing, raise `CURRENT_PROJECT_VERSION` of the **extension** target (in the Xcode project) so the new build replaces the old one. Do not include that bump in your pull request.

**Project Structure:**
- `MacOS/ProxyBridge/ProxyBridge/` - SwiftUI main app
- `MacOS/ProxyBridge/extension/` - Network Extension provider
- `MacOS/ProxyBridge/config/` - Your signing configuration (NOT in git)
- `MacOS/ProxyBridge/build.sh` - PKG installer creation script
- `MacOS/ProxyBridge/output/` - Exported .app and PKG installer
- `proxybridge-app.xcconfig` - Template config (in project root)
- `proxybridge-ext.xcconfig` - Template config (in project root)

### Linux

**Prerequisites** (Debian/Ubuntu package names, the same ones the CI uses):
`build-essential gcc make clang curl linux-tools-common linux-tools-generic libbpf-dev libelf-dev zlib1g-dev libgtk-3-dev pkg-config`

On Ubuntu `bpftool` is installed with `linux-tools-*` and is not on `PATH`. Point `BPFTOOL` at it (for example `/usr/lib/linux-tools/<kernel>/bpftool`) if the build cannot find it.

```bash
git clone -b dev https://github.com/InterceptSuite/ProxyBridge.git
cd ProxyBridge/Linux
WERROR=1 ./build.sh        # builds the library, the CLI and the GUI, results land in Linux/output/
```

The CI builds with `WERROR=1`, so your change must compile warning-free. See [`Linux/README.md`](Linux/README.md) for usage and the full list of tests.

## Testing

Every pull request must pass the existing tests and checks for the platform it touches. The checks that run automatically on pull requests are in [`.github/workflows`](.github/workflows); the tests that need a real machine are run by you, locally.

| Platform | Runs automatically (GitHub Actions) | You run locally |
|----------|--------------------------------------|-----------------|
| **Windows** | `Build Windows` (`compile.ps1 -NoSign`), the Windows tests and `CodeQL` | Test your change on a real Windows machine and describe it in the pull request |
| **Linux** | `Build Linux` (unit tests, then the build with `WERROR=1`) and `CodeQL` | The root-only end-to-end tests in `Linux/tests` when your change touches the kernel hooks, relay, rules or DNS (see `Linux/README.md`) |
| **macOS** | `CodeQL`. The signed `Build macOS` workflow uses our signing secrets, which GitHub does not give to pull requests from forks, so its signing steps cannot run for them | **The whole macOS test suite (below). Required.** |

**Linux tests that run in CI** (you can run them too, no root needed):

```bash
Linux/profile/tests/run_tests.sh                       # .pbprofile reader/writer, including fuzzing under ASan/UBSan
cd Linux/src && make test-rules BUILD_DIR=/tmp/pbt     # rule engine and DNS parser tests
cd tests && ./run_relay_test.sh plain                  # relay tests
```

### macOS tests

The macOS tests are in [`MacOS/tests`](MacOS/tests) (see its `README.md` for details). They are **not** run in GitHub Actions: the system extension has to be approved by a person on the Mac, which CI cannot do. **You run them on your own signed build and report the results in your pull request.**

1. **Logic tests** - no installed extension needed, they take seconds:

   ```bash
   MacOS/tests/logic/run.sh
   ```

   They compile the matcher, DNS-map and command line tests (option parsing, profile loading) against the real sources and run them.

2. **End-to-end tests** - run against your **signed** app with the system extension approved:
   1. Install your signed build, start it and approve the system extension and the network configuration when macOS asks.
   2. In the app, create a new profile and import `MacOS/tests/pbtest.pbprofile` (it adds five local test proxies and ten rules). Make it the active profile. The test rules redirect `curl`, `nc`, `openssl` and `pbudp` traffic, so switch back to your normal profile afterwards.
   3. Run:

      ```bash
      sudo -v                              # lets the leaks check run without a prompt
      python3 MacOS/tests/pbtest.py        # about 5 minutes
      python3 MacOS/tests/pbtest.py --slow # also the 2.5 minute idle-UDP test
      ```

   The suites cover routing (SOCKS5, HTTP, auth, DIRECT, BLOCK, UDP), proxy reply parsing, per-proxy hostnames, 300 parallel TCP connections and UDP flows (memory must stay flat), DNS, and a `leaks` check on the extension.

   If you change the **command line mode** (`CLIArguments.swift`, `CLIProfile.swift`, `CLIRunner.swift`), also run `python3 MacOS/tests/pbtest.py cli` with the ProxyBridge app **quit**.

3. **Add a test** when you fix a bug or change behavior in the extension or the CLI: extend `MacOS/tests/pbtest.py` / `servers.py`, or add a logic test in `MacOS/tests/logic`.

**What your macOS pull request must show:** macOS version and chip (Apple silicon or Intel), Xcode version, how you signed the build, which test suites you ran and their result (paste the summary lines), and screenshots or logs for any GUI change.

## Pull Request Process

1. **Update documentation** - if your changes affect user-facing features
2. **Add tests** - for new functionality when applicable
3. **Follow coding standards** - see below
4. **Update CHANGELOG** - add a note about your changes
5. **One feature per PR** - keep pull requests focused
6. **Sign your commits** - use `git commit -s`

### Pull request templates and the automatic check

Pull request descriptions are plain Markdown (GitHub does not support forms for pull requests the way it does for issues), so we kept the template short: type your answer after each question. There is **no checkbox to tick by hand**.

**Pick the template for your platform.** The default template opens automatically. For a platform template, add `?template=<name>.md` to the address of the "Open a pull request" page:

| Platform | Template | Address ending |
|----------|----------|----------------|
| Any / cross-platform | the default | (nothing to add) |
| Windows | `.github/PULL_REQUEST_TEMPLATE/windows.md` | `?template=windows.md` |
| macOS | `.github/PULL_REQUEST_TEMPLATE/macos.md` | `?template=macos.md` |
| Linux | `.github/PULL_REQUEST_TEMPLATE/linux.md` | `?template=linux.md` |

**Every template asks about your local tests**, because the GitHub checks do not replace them:
- Did you run the tests locally (which ones, on which system)?
- What was the result or output?
- Did anything fail, and why?
- Did you add any new tests?
- Did you remove or change any tests?

The **macOS template** also asks for your macOS version and chip, your Xcode version, how you signed the app, and whether the signed app ran correctly with your change. If your pull request changes anything under `MacOS/`, this part is required whichever template you started from.

**What the automatic check does** (workflow `PR Check`):

| Situation | What happens |
|-----------|--------------|
| The pull request targets a branch other than `dev` | It is **closed with a short comment** asking you to open a new one against `dev` |
| No linked issue, or the issue was not discussed first | `needs-details` label and a friendly comment |
| Template removed, or required details missing or left empty | `needs-details` label and a friendly comment listing what to add |
| Everything is there | Nothing. The comment updates and the label is removed once you fix your description |

Maintainers, branches pushed to this repository, and bots are not checked.

### PR Checklist

- [ ] The pull request targets **`dev`**
- [ ] The **pull request template is fully filled in** (nothing removed, nothing left empty)
- [ ] It links a GitHub issue, and I **commented on that issue and heard back from a maintainer before I started**
- [ ] Code builds without errors (and without warnings on Linux, `WERROR=1`)
- [ ] **All existing tests and checks pass** for the platforms I changed
- [ ] **macOS changes only:** I signed the app myself, tested it on a real Mac, ran the macOS tests, and described the results in the pull request
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

### C (Windows GUI/CLI)

The Windows GUI and CLI are native C built against the Win32 API - the same standards as the core apply.

**Standards:**
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Always use braces for if/while/for blocks
- Use the **secure CRT** variants (`_snwprintf_s`, `strcpy_s`, `strncpy_s`, ...) - the banned unbounded functions are rejected in review
- Free every allocation; guard against double-free and leaks (the GUI is long-running)
- Keep the build warning-clean under `/W4`

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
