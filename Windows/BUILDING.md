# Windows build entry points

Compile unsigned user-mode components from 64-bit PowerShell:

```powershell
.\Windows\compile.ps1 -NoSign -UserModeOnly -OutputDirectory C:\build\ProxyBridge-new
```

Requires MSVC, MSBuild and Windows SDK. Defaults for CI are v143 and
10.0.26100.0; an existing VS2026 lab can explicitly pass `-PlatformToolset v145
-WindowsSdkVersion 10.0.28000.0`. Omit `-UserModeOnly` only with the matching
WDK installed to also compile the unsigned driver. No tool is installed.

The destination must be new. Compilation uses a source snapshot under its
`intermediate` directory, preserves old artifacts and running applications,
and writes build-result.json only after all requested components succeed.
This is not an installable driver package; intermediate files are not shipped.
The five application outputs are Core, GUI, CLI, driver helper and launcher.

Signed packaging is a separate entry point:
`Windows/installer/build-signed-package.ps1`. Supply its explicit manifest,
launcher and publisher hashes, versions, verified signed payload, SignTool,
MakeNSIS, timestamp service and a new destination. Existing verification must
succeed; compile.ps1 never signs or creates certificates. The transaction
installer remains rehearsal-only pending physical/release gates.

The normal Windows CI job builds user mode only, including PRs to Driver.
GitHub-hosted execution is not yet verified by the local build.
Runner inventory: https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md
Release workflow intentionally stops before compilation/upload until a production
release invocation is configured. It cannot publish the unsigned CI outputs.

## Reuse a separately signed driver in one installer

First sign the five application outputs with the intended publisher certificate.
Keep a complete Microsoft-returned driver directory (INF, CAT, SYS), and record
its approved catalog and SYS SHA256 values. Do not rebuild or edit its contents.
Application-only releases can reuse that driver when the protocol and version
contract remains compatible.

```powershell
$inputArgs = @{
    ApplicationDirectory = 'C:\release\signed-app'
    DriverDirectory = 'C:\release\microsoft-driver'
    ExpectedDriverCatalogHash = $approvedCatalogSha256
    ExpectedDriverBinaryHash = $approvedSysSha256
    Protocol = 4
    DriverVersion = 65537
    AppVersion = $appVersion
    Destination = 'C:\release\new-prepared'
}
$prepared = & .\Windows\installer\prepare-package-inputs.ps1 @inputArgs
```

Preparation preserves all original inputs, checks the declared contract against
this checkout's header, pins driver hashes before and after copying, and creates
a manifest. It does not certify signatures or independently infer binary ABI;
use application binaries built from the matching checkout.

Pass `$prepared.ManifestHash`, `$prepared.LauncherHash`, the new payload folder
and launcher to `installer/build-signed-package.ps1`, together with its required
publisher certificate/tool/version/timestamp arguments. Keep its default
`DriverSignaturePolicy=KernelPolicy` for the production driver route. That step
verifies publisher signatures, kernel catalog policy, INF/SYS membership and all
manifest bytes before NSIS. It signs generated uninstaller and final setup.

The result is one ProxyBridge-Setup.exe containing app and driver. The current
NSIS gate still marks it as a rehearsal; do not publish as a production release
until the recorded release gates are completed. There is no automatic Microsoft
submission/download step and no dependency on signing private keys in ordinary CI.
# Installed layout (current rehearsal implementation)

Native registration creates `ProxyBridge.lnk` in the common Start menu folder
and on the common desktop, targeting the verified bootstrap launcher with its
embedded icon. Updates retarget owned links; uninstall removes matching links.
A link changed to a foreign target is preserved and reported as a registration
error. The shared desktop must not grant effective write access to ordinary users;
the installer checks this but does not change its Windows ACL.

New application payloads use `%ProgramFiles%\InterceptSuite\ProxyBridge\versions\{transaction-guid}`.
Version directories support transactional update and rollback. Bootstrap/recovery
executables remain under `%ProgramData%\InterceptSuite.ProxyBridge\bootstrap`.
Existing receipts for the former ProgramData `versions` directory remain readable
and eligible for validated cleanup; installation does not relocate old files in place.
Legacy fallback is limited to that fixed protected directory. Access-denied or
invalid-security errors at the new root are not treated as a missing installation.

This layout is being replaced. It does not meet the product requirement of a
single conventional Program Files installation and has outstanding PB-SUT
uninstall/reinstall regressions. See
[`installer/KNOWN-ISSUES.md`](installer/KNOWN-ISSUES.md) before using a
rehearsal installer for product validation.

