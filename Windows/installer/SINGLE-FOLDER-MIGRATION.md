# Single-folder installer, increment 93 (2026-09-25)

The default `ProxyBridge-transaction.nsi` now calls `install-flat` and
`uninstall-flat`. It extracts its helper to private temporary input, installs
one application in `%ProgramFiles%\InterceptSuite\ProxyBridge` and overwrites
that directory on update. No previous application version or rollback copy is
retained. Windows manages the installed driver through PnP/Driver Store.

The fixed folder holds the application, driver input, launcher, helper and
uninstaller. InstallLocation, Start/Desktop shortcuts and the startup task point
to the fixed folder. The wizard has Welcome, License, destination, progress and
Finish pages; the destination is displayed read-only because the coordinator
uses a single native Program Files location. Launch is hidden when reboot is
required. Helper output and process-launch errors reach the installation log.

The journal has separate single-folder phases (16-21); committed phase 6 remains
compatible with the existing launcher/Core. Overwrite starts only after durable
launch blocking. Re-running Setup completes replacement after failure; there is
no application rollback. Exact previously recorded unbound PnP instances can be
resumed/removed after interruption. Stale uninstallers cannot remove a package
with a different manifest hash.

An absent PnP device no longer automatically implies code 183 if its kernel
service remains. Adoption requires matching service type/start configuration,
a canonical Windows driver image and byte equality with the signed input SYS.
A marked-for-deletion service or missing image requires reboot; unrelated or
mismatched services are refused. This is not proof that every PB-SUT service
state is repaired; the physical regression gate is still pending.

Legacy cleanup accepts only canonical GUID/hash leaves beneath protected old
product roots, fixed file inventories, and non-reparse objects. It refuses
unknown files and hardlinks, opens the complete leaf inventory before deleting,
and removes empty version/bootstrap directories. Owned old recovery links are
removed after checking their exact target/arguments. User profiles and vendor
roots are not recursively erased.

## Verified

- Helper Release x64 v145/SDK28000 built with `/W4 /WX` configured in the project.
- `single-folder-93-tests/verify.cmd`: coordinator phase retries, source failure,
  durable journal flush failure, copy/driver/registration/cleanup errors,
  reboot install/remove, stale uninstall, orphan refusal, unbound instance
  resume/removal, migration from a legacy pending record and journal CAS.
- `tests/run-overwrite-tests.ps1 -OutputDirectory .../single-folder-93-files`:
  real-file overwrite/retry at every file, locks, ACL/hardlink refusal,
  old versions/bootstrap cleanup, foreign-file refusal, removal and reinstall.
- `single-folder-93-registration/verify.cmd`: real COM shortcut files, old and
  fixed registration, migration without an old uninstall key, desktop/icon
  targets, removal of owned recovery links, foreign action refusal and retry.
- `single-folder-93-service/verify.cmd`: real file comparison with adapted SCM
  and Windows root; matching image, SystemRoot syntax, mismatch/type/start/path
  refusal, absence and missing/deletion-pending service images.
- Native API/known-folder/security/registry/task adapters were used. These are
  isolated tests, not a real elevated installation or actual PnP device test.
- Package builder validated payload/catalog membership and test signatures,
  signed/timestamped helper/setup/uninstaller, and verified the final package.

All artifact directories above are under `C:/build/ProxyBridgeDrv-228/63be0eb`.
The new helper is in `single-folder-93-helper`. The signed package is
`candidate-20260925-93-test-package/ProxyBridge-Setup.exe`; verified desktop copy:
`C:/Users/LabAdmin/Desktop/ProxyBridge-Setup-93.exe`.

Installer SHA256: BB74E462E059660D7EF2BA4EA95BFAC76455BBFB04D1F19E319EFEC5679C1779
Manifest: 044E417C0796967EC8C1B421B86E1A56E16459CEA0EFDB17AFAEA10DFD563B15
Uninstaller SHA256: 095094223AB2AB830597D47FA75397B8AE4ECF2E41C9ED6FDA9EBE726D0B976A
Test signer: 4544323109A45FC4761819E079BBDBD5E0BFE8D6
Unchanged driver SYS: 067B8EDA68576F1F265B9FFC4F092BCE643310A6EECDB0B7AF10BC20BF13C78E
Unchanged driver CAT: FCD59A439C6BBBB9D61D61F22E6DC83050004273E6F9599781A7236A4FA64B68

## Next physical gate

On PB-SUT close ProxyBridge, run Setup 93 over its existing state without manual
file cleanup. If it requests reboot, restart then rerun the same Setup. Verify
traffic, fixed InstallLocation, shortcuts, absence of old application copies,
then uninstall/reinstall. Any failure must be diagnosed from `SetupStep`,
`SetupFile`, `ServiceImage` and `CleanupBlocked`, not just the final number.
No live installation/uninstallation/UAC was performed on the development host;
no commit/push or driver rebuild was performed. This remains a test-signed
rehearsal package, not a Microsoft-signed production release.

## Increment 94: uninstall waits for stale SCM service cleanup

The flat uninstall path now probes `ProxyBridgeDrv` in SCM after PnP removal.
If the service still exists or is marked for deletion, it returns 3010 before
removing the application registration/files. NSIS marks reboot required and
asks to rerun uninstall after restart. This covers PB-SUT's confirmed sequence:
uninstall then immediate reinstall fails at `check-orphan-service` with 1306,
while reboot removes the stale service and allows reinstall.

Verification: `install-flat-service-test` and `install-flat-test` compiled
with MSVC `/W4 /WX` and passed. The helper Release x64 build also passed with
zero warnings/errors. The setup and uninstaller were signed/timestamped using
the existing lab test signer; package verification passed with `TestTrusted`.
The unchanged HLK driver CAT/SYS and existing signed application binaries were
reused; only the helper and payload manifest changed. No live PB-SUT install,
uninstall, or reboot was performed.

Package: `C:/build/ProxyBridgeDrv-228/63be0eb/candidate-20260925-94-test-package/ProxyBridge-Setup.exe`
Desktop copy: `C:/Users/LabAdmin/Desktop/ProxyBridge-Setup-94.exe`
SHA-256: `396B6C4727E2FF9A919AFDD5C5F4438ED18E54AE23495303E3186236BC29B879`
Manifest: `4556C4150DEDC947544D824A1C40E6810E82CECA039E7703B8B15924B356F749`
Helper SHA-256: `6008237E0BD174C56BEFFDB853FAEFEF6A2C1C3A6E8306A112B670564982624F`
Uninstaller SHA-256: `13492BCE51E4456D0078714822B5D197AF142C43F9E64EBAC4F1261431713D2D`
Test signer: `4544323109A45FC4761819E079BBDBD5E0BFE8D6`; driver policy: `TestTrusted`.

Next physical check: install/upgrade with Setup94, uninstall, honor any restart
prompt and rerun uninstall, then reinstall and verify runtime traffic.

## Increment 95: complete application removal before restart

PB-SUT showed that Setup94's 3010 prompt left the application installed and
launch-blocked after reboot because Windows does not rerun an interactive
uninstaller automatically. The revised path now removes the verified PnP
package, application registration, shortcuts and payload during the first
uninstall pass when only the SCM service record is awaiting reboot. It returns
3010 only after the app removal journal is committed; reinstall remains gated
while the stale service exists. The message tells the user to rerun uninstall
only if the app still appears after restart.

Source-linked `install-flat-test` and `install-flat-service-test` pass with
MSVC `/W4 /WX`. The helper Release x64 build passed with zero warnings/errors.
The signed/timestamped rehearsal installer and uninstaller passed publisher
signature verification; package validation passed with `TestTrusted`. The
existing signed application binaries, launcher and HLK driver CAT/SYS were
reused without changes. No PB-SUT action has been performed by this change.

Package: `C:/build/ProxyBridgeDrv-228/63be0eb/candidate-20260925-95-test-package/ProxyBridge-Setup.exe`
Desktop copy: `C:/Users/LabAdmin/Desktop/ProxyBridge-Setup-95.exe`
SHA-256: `CA39834E0CF131F14FA6C8D1A9B1B059523BA23E3A338BE3CE81AF461E4151D8`
Manifest: `E7150AD0F436F09584B33B8C1E921EC6C023C017D78DF7600789ED434EC49F1D`
Helper SHA-256: `47C85E4AE2422F68ED9C18A3E8C1D45351DEA9539A0B81CFC806075A87FBE3E8`
Uninstaller SHA-256: `3E5DA8862E5DB1C550004AECB7D961853A7A9BFAD01AA289E818CABB41DECF20`
Test signer: `4544323109A45FC4761819E079BBDBD5E0BFE8D6`; driver policy: `TestTrusted`.

Next physical check: use Setup95 to recover/upgrade the PB-SUT app, then
uninstall and confirm the app files/entry disappear on the first pass. If it
requests restart, reboot before reinstalling; the app should not require a
second uninstall pass unless it still appears in Programs.
