# HLK: CHAOS discovery and Static Tools Logo

This branch is limited to issue #228 (WDTF/CHAOS device discovery) and the
separate Static Tools Logo DVL preparation issue. It is based on `Driver`
commit `63be0eb`. It does not include the GUI, network refactoring, installer
replacement, benchmarks, or test suites from the full Windows development branch.

## CHAOS: a started PnP device

The original driver created a legacy control device. WDTF could not find a
started PnP device associated with `ProxyBridgeDrv.sys`. The INF now describes
one root-enumerated KMDF device in the System setup class, with hardware ID
`ROOT\InterceptSuite_ProxyBridge` and an associated service installed by PnP.

KMDF owns device creation, power transitions, removal and file cleanup. WFP
activation remains explicit: a started devnode does not depend on the Base
Filtering Engine already being available. Closing the controller or taking
the device out of D0 disables filtering and drains session state. A second
device cannot share the driver's singleton WFP state.

The existing `\\.\ProxyBridgeDrv` open path and all existing IOCTL layouts are
retained. The application no longer creates a legacy service: install the PnP
package first. Configuration/activation errors are propagated instead of
reporting a successful start. After a device removal/restart, stop and restart
the application to open a new session; automatic reconnection is out of scope.

## Build and install on an isolated HLK client

Build `ProxyBridgeDrv.vcxproj` as Release/x64 with the matching Visual Studio,
SDK/WDK (the project pins SDK 10.0.28000.0) and KMDF 1.31 libraries. Build the
application core from this branch too. Sign the generated driver package using
your lab's test-signing procedure before installing it on a test-signing client.
Do not reuse a catalog or DVL generated for a different binary/source revision.

The existing application installer has not been adapted to PnP installation.
For this focused HLK change, use the signed INF/CAT/SYS directly in the lab.
On a clean client with no existing ProxyBridge device or legacy service, use
the WDK's DevCon from an elevated terminal, in the signed package directory:

```powershell
devcon.exe install .\ProxyBridgeDrv.inf 'ROOT\InterceptSuite_ProxyBridge'
Get-PnpDevice | Where-Object InstanceId -Like 'ROOT\INTERCEPTSUITE_PROXYBRIDGE\*'
sc.exe query ProxyBridgeDrv
```

DevCon `install` creates a new root device every time: do not repeat it for an
already installed device. For an existing lab device use `devcon.exe update`
with the INF and hardware ID instead. Investigate duplicates or an old legacy
service before proceeding; do not delete DriverStore files manually.

Select this device in HLK and run both CHAOS variants. Record the final parent
test results, including cleanup; a green `Run Test` substep alone is insufficient.
Also check ordinary application start/stop and device disable/enable on the lab
client. No new automated test harness is included in this branch.

## Static Tools Logo: preserve genuine CodeQL evidence

Run the required Windows driver CodeQL suite against this exact source/build.
Then pass its SARIF to `create-dvl.ps1` with the installed Microsoft DVL tool:

```powershell
.\create-dvl.ps1 -DvlTool $dvlTool -Sarif $sarif -OutputDirectory $newDirectory
```

The script saves the generator log, SHA-256 hashes and assessment summary. It
rejects missing/old ruleset metadata and blocking required-query outcomes.
It does not edit the generated XML or establish that SARIF matches the source;
retain the CodeQL database/build provenance alongside the output.

Microsoft documents a DVL version mismatch for Windows 11 25H2 with the May
2026 HLK. For that specific combination, `-Prepare25H2Waiver320241` supports
evidence preparation with generator 10.0.28000.1761. The applicable Microsoft
filter/waiver must still be verified on the HLK controller. This is a filtered
assessment route, not a driver-code fix or an unconditional Static Tools pass.

## Validation status of this reduced branch

- Release x64 driver compilation/linking with warnings treated as errors: passed.
- Catalog generation and standalone x64 `InfVerif /w /v`: passed.
- Core DLL compilation/linking: passed.
- DVL script PowerShell syntax validation: passed.

The local WDK's integrated verifier cannot load its x86 `InfVerif.dll`; the
build used `SkipPackageVerification=true` and ran the installed x64 verifier
separately against the generated INF. No source-level verification bypass was
added to the project.

This reduced branch has not been installed or run through HLK yet. Historical
CHAOS passes and filtered Static Tools results from the full branch do not
certify this new binary. A fresh CodeQL/DVL run and physical HLK validation are
required before claiming either blocker resolved for this revision. No
production signature or certification is claimed.

References:

- [DevCon Install](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/devcon-install)
- [Creating a DVL and the 25H2 known issue](https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/creating-a-driver-verification-log)
