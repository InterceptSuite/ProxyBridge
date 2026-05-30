!define PRODUCT_NAME "ProxyBridge"
!define PRODUCT_VERSION "3.2.0"
!define PRODUCT_PUBLISHER "InterceptSuite"
!define PRODUCT_WEB_SITE "https://github.com/InterceptSuite/ProxyBridge"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

Unicode True

; Version Information
VIProductVersion "3.2.0.0"
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
!define MUI_ICON "..\gui\Assets\logo.ico"
!define MUI_UNICON "..\gui\Assets\logo.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "MainSection" SEC01
  ; Kill any running ProxyBridge instance before overwriting files.
  ; This prevents "file in use" errors on update/reinstall.
  nsExec::ExecToLog 'taskkill /F /IM ProxyBridge.exe'
  nsExec::ExecToLog 'taskkill /F /IM ProxyBridge_CLI.exe'

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
  File "..\output\av_libglesv2.dll"
  File "..\output\libHarfBuzzSharp.dll"
  File "..\output\libSkiaSharp.dll"

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
  Delete "$INSTDIR\ProxyBridge.exe"
  Delete "$INSTDIR\ProxyBridge_CLI.exe"
  Delete "$INSTDIR\ProxyBridgeCore.dll"
  Delete "$INSTDIR\WinDivert.dll"
  Delete "$INSTDIR\WinDivert64.sys"
  Delete "$INSTDIR\av_libglesv2.dll"
  Delete "$INSTDIR\libHarfBuzzSharp.dll"
  Delete "$INSTDIR\libSkiaSharp.dll"
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

  ; Stop and remove the WinDivert kernel driver service so a future reinstall
  ; doesn't inherit a stale/disabled entry (error 1058).
  nsExec::ExecToLog 'sc stop WinDivert'
  nsExec::ExecToLog 'sc delete WinDivert'
  DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\WinDivert"

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  SetAutoClose true
SectionEnd
