# Installer regression record

Increment93 implements a distinct single-folder lifecycle and passes isolated
coordinator, filesystem, registration and orphan-service tests. The default
Setup uses it. PB-SUT verification is still pending: the observations below
are retained as regression gates, not declared physically fixed. See
`SINGLE-FOLDER-MIGRATION.md` for the tested package and exact evidence.

## PB-SUT reinstall after increment93 (2026-09-25)

Observed sequence after uninstall succeeded and increment93 install failed:

1. Setup log reached `check-orphan-service` and returned 1306, before payload
   copy. There was no `ServiceImage=` line. `sc qc ProxyBridgeDrv` showed a
   kernel service with `StartType=4 DISABLED`; its DriverStore SYS path did not
   exist. `sc queryex` showed STOPPED / Win32 exit 31.
2. `pnputil /enum-drivers` showed the remaining ProxyBridge package was
   `oem14.inf`, class `WFPCALLOUTS`, version 1.0.0.0 / 2026-01-01. The current
   installer input INF is class `System`, version 1.0.0.1 / 2026-09-08. The
   user's INF contents confirm `oem14.inf` is the old non-PnP package.
3. User removed only `oem14.inf` with `pnputil /delete-driver oem14.inf`.
   The disabled service still appeared in SCM, proving that old package removal
   alone did not clear this service record.
4. After Windows reboot, `sc qc` and `sc queryex` both returned 1060
   (`ERROR_SERVICE_DOES_NOT_EXIST`). Thus reboot completed removal of the
   stale service. No installer code was changed during diagnosis.
5. In a follow-up cycle, install -> uninstall -> reboot -> install succeeded;
   repeating install -> uninstall -> install without reboot reproduced 1306 at
   `check-orphan-service`. This confirms the uninstall path must detect
   lingering `ProxyBridgeDrv` state before allowing an immediate reinstall.

Increment94 exposed a bad uninstall experience: when SCM retained the driver
service, it returned 3010 before removing the application, so reboot alone did
not resume uninstall and the launch-blocked app remained. Increment95 changes
this: after PnP/package removal, a stale SCM entry records reboot-required but
does not prevent removal of app registration/files. The install path continues
to reject a stale service until reboot. Reboot messaging now asks to rerun
uninstall only if the app still appears afterwards. Source-linked tests cover
this completion path and SCM present/marked/absent/access-denied results.

Next physical gate: use `C:\Users\LabAdmin\Desktop\ProxyBridge-Setup-95.exe`
on PB-SUT. Install/upgrade, uninstall, and observe whether stale SCM state
causes an explicit 3010 restart prompt. The app should be removed immediately;
restart before reinstalling. If it remains in Programs after restart, rerun
uninstall and capture `SetupStep` output. Do not claim the physical reinstall
regression fixed until that cycle passes without manual service/package cleanup.

## Blocker: removal followed by reinstall can strand the PnP service

Observed on PB-SUT during the 2026-09-25 rehearsal packages.

1. An earlier transaction is removed or interrupted while the PnP service
   `ProxyBridgeDrv` remains visible to Service Control Manager.
2. A subsequent `update-package` run can fail with `183` (`ERROR_ALREADY_EXISTS`)
   in more than one lifecycle stage. In the latest observed state the journal
   reached `PB_INSTALL_ROLLING_BACK` (phase 7) with `LastError=183`.
3. If obsolete bootstrap files are deleted manually while the journal is in
   `PB_INSTALL_CLEANED` (phase 15), the old registration cleanup returns `2`
   (`ERROR_FILE_NOT_FOUND`).
4. Reinstall also returned `170` (`ERROR_BUSY`). There are several possible
   sources: a pending journal, the installer mutex and the runtime guard. The
   supplied UI log does not identify which one returned it. Do not attribute
   this occurrence to a running application without the failing step's log.

The previous per-transaction layout accumulates payload folders under
`%ProgramFiles%\InterceptSuite\ProxyBridge\versions\{GUID}` and recovery
bootstrap folders under `%ProgramData%\InterceptSuite.ProxyBridge\bootstrap\{hash}`.
It is unsuitable for the requested product layout and makes recovery difficult
to validate after manual intervention.

## Required replacement acceptance criteria

* One installed payload only: `%ProgramFiles%\InterceptSuite\ProxyBridge`.
* No application payload, launcher, helper, recovery link, or retained version
  directory under `%ProgramData%`.
* Update closes or reports the running application before replacing files; it
  never creates a second payload directory.
* Updates overwrite the one installed version. No previous-version backups,
  `.setup/rollback`, `incoming` version directories or automatic application
  rollback. Interrupted copying remains launch-blocked; running Setup again
  completes replacement from its embedded payload.
* Uninstall removes the owned PnP device/package, product registration and
  owned shortcuts, then removes the single payload directory.
* Reinstall after uninstall succeeds on the same boot or explicitly requests a
  reboot when Windows reports that the driver removal is pending.
* The UI restores the conventional installer flow from `ProxyBridge.nsi`:
  Welcome, License, Directory, progress, Finish, and equivalent uninstall
  confirmation/progress pages.

No release may be claimed until clean install, update, uninstall and reinstall
have passed on PB-SUT without manually deleting any product files.
