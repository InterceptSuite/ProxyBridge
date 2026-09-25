; Single-folder integration rehearsal. The signed installer supplies temporary
; input; the native coordinator overwrites one protected Program Files root.
!ifndef TRANSACTION_REHEARSAL
!error "Transaction installer is not release-ready. Explicit rehearsal build required."
!endif
!ifndef PAYLOAD_DIR
!error "PAYLOAD_DIR required"
!endif
!ifndef MANIFEST_SHA256
!error "MANIFEST_SHA256 required (bind after payload signing)"
!endif
!ifndef LAUNCHER_FILE
!error "LAUNCHER_FILE required"
!endif
!ifndef SETUP_OUTPUT
!error "SETUP_OUTPUT required"
!endif
; Supplied by build-signed-package.ps1. Rehearsal-only builds may omit these.
!ifdef PACKAGE_FINALIZER
!ifndef PACKAGE_SIGNING_CONFIG
!error "PACKAGE_SIGNING_CONFIG required with PACKAGE_FINALIZER"
!endif
!uninstfinalize '"${PACKAGE_POWERSHELL}" -NoProfile -NonInteractive -File "${PACKAGE_FINALIZER}" -Configuration "${PACKAGE_SIGNING_CONFIG}" -Kind Uninstaller -Artifact "%1"' = 0
!finalize '"${PACKAGE_POWERSHELL}" -NoProfile -NonInteractive -File "${PACKAGE_FINALIZER}" -Configuration "${PACKAGE_SIGNING_CONFIG}" -Kind Installer -Artifact "%1"' = 0
!endif
Unicode true
RequestExecutionLevel admin
!ifndef PRODUCT_VERSION
!define PRODUCT_VERSION "1.0.0.0"
!endif
Name "ProxyBridge"
OutFile "${SETUP_OUTPUT}"
VIProductVersion "${PRODUCT_VERSION}"
VIAddVersionKey "ProductName" "ProxyBridge"
VIAddVersionKey "CompanyName" "InterceptSuite"
VIAddVersionKey "FileDescription" "ProxyBridge Setup"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 InterceptSuite"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
SetCompressor /SOLID lzma
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\InterceptSuite.ProxyBridge"
!define MUI_ICON "${__FILEDIR__}\..\gui\res\logo.ico"
!define MUI_UNICON "${__FILEDIR__}\..\gui\res\logo.ico"
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${__FILEDIR__}\..\..\LICENSE"
!define MUI_DIRECTORYPAGE_TEXT_TOP "ProxyBridge installs one copy here. Updates replace the existing files."
!define MUI_PAGE_CUSTOMFUNCTION_SHOW DirectoryShow
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchInstalled
!define MUI_FINISHPAGE_RUN_TEXT "Open ProxyBridge"
!define MUI_PAGE_CUSTOMFUNCTION_SHOW FinishShow
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "English"
Var Result
!macro NormalizeResult
  ${If} $Result == "error"
    StrCpy $Result 1603
  ${ElseIf} $Result == "timeout"
    StrCpy $Result 1460
  ${EndIf}
!macroend
Function DirectoryShow
  EnableWindow $mui.DirectoryPage.Directory 0
  EnableWindow $mui.DirectoryPage.BrowseButton 0
FunctionEnd
Function FinishShow
  ${If} $Result != 0
    ShowWindow $mui.FinishPage.Run ${SW_HIDE}
  ${EndIf}
FunctionEnd
Function LaunchInstalled
  ${If} $Result == 0
    Exec '"$INSTDIR\ProxyBridgeLauncher.exe"'
  ${EndIf}
FunctionEnd
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "ProxyBridge requires x64 Windows."
    SetErrorLevel 1633
    Quit
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    SetErrorLevel 1633
    Quit
  ${EndIf}
  SetRegView 64
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
  ${If} $0 < 19041
    MessageBox MB_ICONSTOP "Windows 10 build 19041 or newer is required."
    SetErrorLevel 1633
    Quit
  ${EndIf}
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\InterceptSuite\ProxyBridge"
FunctionEnd
Function un.onInit
  SetRegView 64
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\InterceptSuite\ProxyBridge"
FunctionEnd
Section
  InitPluginsDir
  ClearErrors
  SetOutPath "$PLUGINSDIR\support"
  File /oname=ProxyBridgeLauncher.exe "${LAUNCHER_FILE}"
  WriteUninstaller "$PLUGINSDIR\support\uninstall.exe"
  SetOutPath "$PLUGINSDIR\payload"
  File "${PAYLOAD_DIR}\ProxyBridge.exe"
  File "${PAYLOAD_DIR}\ProxyBridge_CLI.exe"
  File "${PAYLOAD_DIR}\ProxyBridgeCore.dll"
  File "${PAYLOAD_DIR}\ProxyBridgeDriverSetup.exe"
  File "${PAYLOAD_DIR}\payload.manifest"
  SetOutPath "$PLUGINSDIR\payload\driver"
  File "${PAYLOAD_DIR}\driver\ProxyBridgeDrv.inf"
  File "${PAYLOAD_DIR}\driver\ProxyBridgeDrv.cat"
  File "${PAYLOAD_DIR}\driver\ProxyBridgeDrv.sys"
  ${If} ${Errors}
    SetErrorLevel 1603
    Abort
  ${EndIf}
  ; The embedded helper runs from temporary input, never the file being replaced.
  nsExec::ExecToLog '"$PLUGINSDIR\payload\ProxyBridgeDriverSetup.exe" install-flat "$PLUGINSDIR\payload" ${MANIFEST_SHA256} "$PLUGINSDIR\support"'
  Pop $Result
  !insertmacro NormalizeResult
  ${If} $Result == 3010
    SetRebootFlag true
    MessageBox MB_ICONINFORMATION "Restart Windows, then run this Setup again to finish installation."
  ${ElseIf} $Result == 170
  ${OrIf} $Result == 32
    MessageBox MB_ICONEXCLAMATION "Close ProxyBridge and any other setup windows, then run Setup again. If the error repeats, copy the installation details."
    SetErrorLevel $Result
    Abort
  ${ElseIf} $Result != 0
    MessageBox MB_ICONSTOP "Installation did not complete (code $Result). Copy the installation details. Run Setup again to finish installation."
    SetErrorLevel $Result
    Abort
  ${EndIf}
  SetErrorLevel $Result
SectionEnd
Section Uninstall
  InitPluginsDir
  ClearErrors
  SetOutPath "$PLUGINSDIR"
  File /oname=ProxyBridgeDriverSetup.exe "${PAYLOAD_DIR}\ProxyBridgeDriverSetup.exe"
  ${If} ${Errors}
    SetErrorLevel 1603
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$PLUGINSDIR\ProxyBridgeDriverSetup.exe" uninstall-flat ${MANIFEST_SHA256}'
  Pop $Result
  !insertmacro NormalizeResult
  ${If} $Result == 3010
    SetRebootFlag true
  ${ElseIf} $Result == 170
  ${OrIf} $Result == 32
    MessageBox MB_ICONEXCLAMATION "Close ProxyBridge and any other setup windows, then run this uninstaller again."
    SetErrorLevel $Result
    Abort
  ${ElseIf} $Result != 0
    MessageBox MB_ICONSTOP "Removal did not complete (code $Result). Copy the removal details, then run this uninstaller again."
    SetErrorLevel $Result
    Abort
  ${EndIf}
  SetErrorLevel $Result
SectionEnd
