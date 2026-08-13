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
!insertmacro MUI_PAGE_LICENSE "..\..\\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; Finish page offers to launch ProxyBridge - checkbox is checked by default.
!define MUI_FINISHPAGE_RUN "$INSTDIR\ProxyBridge.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Run ProxyBridge now"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

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

  ; Stop and unload the WinDivert driver so WinDivert64.sys can be replaced.
  nsExec::ExecToLog 'sc stop WinDivert'
  nsExec::ExecToLog 'sc delete WinDivert'
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\WinDivert"

  ; Brief pause to let the OS release all file handles.
  Sleep 1000

  SetOutPath "$INSTDIR"
  SetOverwrite on

  File "..\output\ProxyBridge.exe"
  File "..\output\ProxyBridge_CLI.exe"
  File "..\output\ProxyBridgeCore.dll"
  File "..\output\WinDivert.dll"
  File "..\output\WinDivert64.sys"

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

  ; Stop the WinDivert driver first so WinDivert64.sys isn't held open.
  nsExec::ExecToLog 'sc stop WinDivert'
  nsExec::ExecToLog 'sc delete WinDivert'
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\WinDivert"
  Sleep 500

  Delete "$INSTDIR\ProxyBridge.exe"
  Delete "$INSTDIR\ProxyBridge_CLI.exe"
  Delete "$INSTDIR\ProxyBridgeCore.dll"
  Delete "$INSTDIR\WinDivert.dll"
  Delete "$INSTDIR\WinDivert64.sys"
  Delete "$INSTDIR\uninst.exe"

  Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  RMDir "$INSTDIR"

  ; Remove from PATH using EnVar plugin
  EnVar::SetHKLM
  EnVar::DeleteValue "PATH" "$INSTDIR"
  Pop $0

  ; Broadcast environment change
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  SetAutoClose true
SectionEnd
