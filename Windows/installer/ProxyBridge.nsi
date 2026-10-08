!define PRODUCT_NAME "ProxyBridge"
!define PRODUCT_VERSION "4.0.13-Beta"
!define PRODUCT_PUBLISHER "InterceptSuite"
!define PRODUCT_WEB_SITE "https://github.com/InterceptSuite/ProxyBridge"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

Unicode True

; Version Information
VIProductVersion "4.0.13.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 ${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT_NAME} Setup"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "Comments" "Network Proxy Bridge Application"

!include "MUI2.nsh"

SetCompressor /SOLID lzma
SetCompressorDictSize 64

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "ProxyBridge-Setup-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
InstallDirRegKey HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation"
RequestExecutionLevel admin

!define MUI_ABORTWARNING
!define MUI_ICON "..\gui\res\logo.ico"
!define MUI_UNICON "..\gui\res\logo.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; Finish page offers to launch ProxyBridge - checkbox is checked by default.
!define MUI_FINISHPAGE_RUN "$INSTDIR\ProxyBridge.exe"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchInstalled
!define MUI_FINISHPAGE_RUN_TEXT "Run ProxyBridge now"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Function LaunchInstalled
  IfRebootFlag launch_done
  Exec '"$INSTDIR\ProxyBridge.exe"'
  launch_done:
FunctionEnd

Section "MainSection" SEC01
  ; A running ProxyBridge locks the files we need to overwrite. Detect it and ask
  ; the user before closing it, instead of killing it silently.
  nsExec::ExecToStack 'cmd /c tasklist /FI "IMAGENAME eq ProxyBridge.exe" /NH | findstr /I "ProxyBridge.exe"'
  Pop $0   ; findstr exit code: 0 = a matching process is running
  Pop $1   ; captured output (unused)
  StrCmp $0 "0" 0 install_proceed
    MessageBox MB_YESNO|MB_ICONQUESTION "ProxyBridge is currently running and must be closed to continue the installation.$\n$\nClose ProxyBridge now and continue?$\n$\nYes  -  close ProxyBridge and install$\nNo   -  cancel and close the installer" IDYES install_kill IDNO install_abort
    install_abort:
      Quit
    install_kill:
      nsExec::ExecToLog 'taskkill /F /IM ProxyBridge.exe'
      nsExec::ExecToLog 'taskkill /F /IM ProxyBridge_CLI.exe'
      Sleep 1500
  install_proceed:

  ; Also clean up any legacy WinDivert driver from older installs.
  nsExec::ExecToLog 'sc stop WinDivert'
  nsExec::ExecToLog 'sc delete WinDivert'
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\WinDivert"
  Delete "$INSTDIR\WinDivert.dll"
  Delete "$INSTDIR\WinDivert64.sys"
  ; Legacy: remove the old "pbwfp"-named driver from before the ProxyBridgeDrv rename.
  nsExec::ExecToLog 'sc stop pbwfp'
  nsExec::ExecToLog 'sc delete pbwfp'
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\pbwfp"
  Delete "$INSTDIR\pbwfp.sys"

  ; Brief pause to let the OS release all file handles.
  Sleep 1000

  SetOutPath "$INSTDIR"
  SetOverwrite on

  File "..\output\ProxyBridge.exe"
  File "..\output\ProxyBridge_CLI.exe"
  File "..\output\ProxyBridgeCore.dll"
  SetOutPath "$INSTDIR\driver"
  File "..\output\driver\ProxyBridgeDrv.inf"
  File "..\output\driver\ProxyBridgeDrv.cat"
  File "..\output\driver\ProxyBridgeDrv.sys"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "..\output\ProxyBridgeDriverSetup.exe"
  nsExec::ExecToLog '"$PLUGINSDIR\ProxyBridgeDriverSetup.exe" install "$INSTDIR\driver\ProxyBridgeDrv.inf"'
  Pop $0
  StrCmp $0 "0" driver_installed
  StrCmp $0 "3010" driver_reboot
  StrCmp $0 "1072" driver_pending
    SetErrorLevel 1
    MessageBox MB_OK|MB_ICONSTOP "Driver installation failed (code $0). See installation details and Windows\INF\setupapi.dev.log."
    Abort
  driver_pending:
    SetRebootFlag true
    SetErrorLevel 3010
    MessageBox MB_OK|MB_ICONINFORMATION "Restart Windows, then run Setup again to replace the old driver service."
    Abort
  driver_reboot:
    SetRebootFlag true
    SetErrorLevel 3010
  driver_installed:
  SetOutPath "$INSTDIR"
  Delete /REBOOTOK "$INSTDIR\ProxyBridgeDrv.sys"

  ; Remove leftover native libraries from the old C#/Avalonia GUI. The native C GUI
  ; does not use them; without this an upgrade would keep these stale DLLs behind.
  Delete "$INSTDIR\av_libglesv2.dll"
  Delete "$INSTDIR\libHarfBuzzSharp.dll"
  Delete "$INSTDIR\libSkiaSharp.dll"

  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\ProxyBridge.exe"
  CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\ProxyBridge.exe"

  ; Add to PATH using EnVar plugin
  EnVar::SetHKLM
  EnVar::AddValue "PATH" "$INSTDIR"
  Pop $0

  ; Broadcast environment change
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\ProxyBridge.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation" "$INSTDIR"
SectionEnd

Section Uninstall
  ; If ProxyBridge is running, its files stay locked and can only be removed after a
  ; reboot. Detect it and offer to close it so the uninstall can complete now.
  nsExec::ExecToStack 'cmd /c tasklist /FI "IMAGENAME eq ProxyBridge.exe" /NH | findstr /I "ProxyBridge.exe"'
  Pop $0   ; findstr exit code: 0 = a matching process is running
  Pop $1   ; captured output (unused)
  StrCmp $0 "0" 0 uninst_proceed
    MessageBox MB_YESNO|MB_ICONQUESTION "ProxyBridge is currently running.$\n$\nClose it and continue the uninstall?$\n$\nYes  -  close ProxyBridge and remove all files now$\nNo   -  continue without closing (some files may be removed only after a reboot)" IDYES uninst_kill IDNO uninst_proceed
    uninst_kill:
      nsExec::ExecToLog 'taskkill /F /IM ProxyBridge.exe'
      nsExec::ExecToLog 'taskkill /F /IM ProxyBridge_CLI.exe'
      Sleep 1500
  uninst_proceed:

  ; Remove the "Run at Startup" logon task the GUI may have created.
  nsExec::ExecToLog 'schtasks /Delete /F /TN "ProxyBridge"'

  ; Remove the PnP device and its package before removing uninstall metadata.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "..\output\ProxyBridgeDriverSetup.exe"
  nsExec::ExecToLog '"$PLUGINSDIR\ProxyBridgeDriverSetup.exe" remove "$INSTDIR\driver\ProxyBridgeDrv.inf"'
  Pop $0
  StrCmp $0 "0" driver_removed
  StrCmp $0 "3010" uninst_reboot
    SetErrorLevel 1
    MessageBox MB_OK|MB_ICONSTOP "Driver removal failed (code $0). See removal details and Windows\INF\setupapi.dev.log."
    Abort
  uninst_reboot:
    SetRebootFlag true
    SetErrorLevel 3010
  driver_removed:
  SetOutPath "$TEMP"
  ; Legacy WinDivert cleanup for upgrades from older versions.
  nsExec::ExecToLog 'sc stop WinDivert'
  nsExec::ExecToLog 'sc delete WinDivert'
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\WinDivert"
  ; Legacy pbwfp (pre-rename) cleanup.
  nsExec::ExecToLog 'sc stop pbwfp'
  nsExec::ExecToLog 'sc delete pbwfp'
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\pbwfp"
  Delete "$INSTDIR\pbwfp.sys"
  Sleep 500

  Delete /REBOOTOK "$INSTDIR\ProxyBridge.exe"
  Delete /REBOOTOK "$INSTDIR\ProxyBridge_CLI.exe"
  Delete /REBOOTOK "$INSTDIR\ProxyBridgeCore.dll"
  Delete /REBOOTOK "$INSTDIR\ProxyBridgeDrv.sys"
  Delete /REBOOTOK "$INSTDIR\driver\ProxyBridgeDrv.inf"
  Delete /REBOOTOK "$INSTDIR\driver\ProxyBridgeDrv.cat"
  Delete /REBOOTOK "$INSTDIR\driver\ProxyBridgeDrv.sys"
  RMDir /REBOOTOK "$INSTDIR\driver"
  Delete "$INSTDIR\WinDivert.dll"
  Delete "$INSTDIR\WinDivert64.sys"
  Delete /REBOOTOK "$INSTDIR\uninst.exe"

  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  RMDir /REBOOTOK "$INSTDIR"

  ; Remove from PATH using EnVar plugin
  EnVar::SetHKLM
  EnVar::DeleteValue "PATH" "$INSTDIR"
  Pop $0

  ; Broadcast environment change
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  SetAutoClose true
SectionEnd
