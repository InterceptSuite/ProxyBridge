<#
.SYNOPSIS
  Builds and runs the ProxyBridge Windows tests. Exit code 0 = everything passed.

.DESCRIPTION
  Each test is a small console program (tests\test_*.c) compiled with MSVC from the real source files, so the
  tests exercise the shipping code. Nothing loads the WinDivert driver and nothing talks to the internet; some
  tests use loopback sockets or private named pipes, the GUI tests create real windows (they need a desktop
  session) and replace the engine API with recording stubs. A few static checks (PowerShell) guard release hygiene.

    test_hosts          Target Hosts list helpers (clean-up, IP/domain split and merge)
    test_profile        profile files: old-format migration, save format, long lists, hostile input
    test_json           the JSON parser/writer: escapes, malformed input, nesting limit, round trips
    test_proto          the app <-> service wire protocol reader/writer
    test_service        the service's request handler and the named-pipe permission list
    test_engine         rule matching: IP or domain, IPv4/IPv6, ports, localhost flag, main switch
    test_rules_match    individual matchers (IP, port, process, domain patterns) and rule ordering/API
    test_conntrack      connection table (#209) and the Connections-log rules (Log Every Connection)
    test_dns            the DNS reply parser behind domain rules (guard-page hardened)
    test_proxy_protocols SOCKS5 and HTTP CONNECT handshakes against a scripted fake proxy
    test_cli            the command-line client's host-list helpers
    test_gui_misc       updater version logic, EN/ZH string table, log filters, log store, conversions
    test_rules_ui       the Proxy Rules window (search, row mapping, keyboard)           [needs a desktop]
    test_main_ui        the main window (main switch menu, Log Every Connection)         [needs a desktop]
    test_dialogs_ui     rule editor, servers list, filters list, About box               [needs a desktop]
    static_checks       version numbers agree everywhere, installer script safety, workflow wiring

.PARAMETER WinDivertPath  WinDivert SDK folder (headers + import library only; the driver is never loaded).
.PARAMETER SkipUi         Do not run the GUI tests (for a session without a desktop).
.PARAMETER Only           Run only the named tests, for example: -Only test_engine,static_checks
#>
param(
    [string]$WinDivertPath = "C:\WinDivert-2.2.2-A",
    [switch]$SkipUi,
    [string[]]$Only
)

$ErrorActionPreference = 'Stop'
$WinRoot = Split-Path -Parent $PSScriptRoot            # ...\Windows
$RepoRoot = Split-Path -Parent $WinRoot
$Out     = Join-Path $PSScriptRoot 'out'
$Arch    = 'x64'

if (-not (Test-Path (Join-Path $WinDivertPath 'include\windivert.h'))) {
    Write-Host "ERROR: WinDivert SDK not found at $WinDivertPath (pass -WinDivertPath)" -ForegroundColor Red
    exit 2
}

# --- locate the MSVC environment the same way compile.ps1 does -----------------------------------------------------
$vcvars = $null
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsPath) {
        $cand = Join-Path $vsPath 'VC\Auxiliary\Build\vcvarsall.bat'
        if (Test-Path $cand) { $vcvars = $cand }
    }
}
if (-not $vcvars -and -not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Visual Studio C++ tools not found (run from a Developer prompt or install the C++ workload)" -ForegroundColor Red
    exit 2
}

if (Test-Path $Out) { [IO.Directory]::Delete($Out, $true) }
New-Item -ItemType Directory -Path $Out | Out-Null

$core = 'ProxyBridge.c','pb_util.c','pb_process.c','pb_rules.c','pb_proxy.c','pb_dns.c','pb_socks5.c','pb_http.c','pb_conntrack.c','pb_relay.c','pb_sockmap.c' | ForEach-Object { "src\$_" }
$warn = '/W3 /wd4100 /wd4189 /wd4267 /wd4244 /wd4996'
$wdInc = "/I`"$WinDivertPath\include`""
$wdLib = "/LIBPATH:`"$WinDivertPath\$Arch`""

$clPlain = "/D_CRT_SECURE_NO_WARNINGS"
$clUni   = "/utf-8 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS"
$clCore  = "/Isrc $wdInc /DPROXYBRIDGE_EXPORTS /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS"
$lnCore  = "$wdLib WinDivert.lib ws2_32.lib iphlpapi.lib advapi32.lib"
$lnProf  = 'user32.lib advapi32.lib shell32.lib'
$lnGui   = '/SUBSYSTEM:CONSOLE /ENTRY:wWinMainCRTStartup user32.lib gdi32.lib comctl32.lib shell32.lib comdlg32.lib winhttp.lib advapi32.lib dwmapi.lib uxtheme.lib ole32.lib uuid.lib'
$prof    = 'gui\profile\profile.c'
$res     = "$Out\app.res"

# n = name, src = sources, cl = compiler flags, link = linker arguments, ui = needs a desktop session
$tests = @(
    @{ n='test_hosts';           src=@('tests\test_hosts.c', $prof);                        cl=$clUni;   link=$lnProf; ui=$false },
    @{ n='test_profile';         src=@('tests\test_profile.c', $prof);                      cl=$clUni;   link=$lnProf; ui=$false },
    @{ n='test_json';            src=@('tests\test_json.c');                                cl=$clPlain; link='';      ui=$false },
    @{ n='test_proto';           src=@('tests\test_proto.c');                               cl=$clPlain; link='';      ui=$false },
    @{ n='test_service';         src=@('tests\test_service.c');                             cl="$clPlain /DUNICODE /D_UNICODE"; link='user32.lib advapi32.lib'; ui=$false },
    @{ n='test_engine';          src=@('tests\test_engine.c') + $core;                      cl=$clCore;  link=$lnCore; ui=$false },
    @{ n='test_rules_match';     src=@('tests\test_rules_match.c') + $core;                 cl=$clCore;  link=$lnCore; ui=$false },
    @{ n='test_conntrack';       src=@('tests\test_conntrack.c') + $core;                   cl=$clCore;  link=$lnCore; ui=$false },
    @{ n='test_flows';           src=@('tests\test_flows.c') + $core;                       cl=$clCore;  link=$lnCore; ui=$false },
    @{ n='test_dns';             src=@('tests\test_dns.c') + $core;                         cl=$clCore;  link=$lnCore; ui=$false },
    @{ n='test_proxy_protocols'; src=@('tests\test_proxy_protocols.c') + $core;             cl=$clCore;  link=$lnCore; ui=$false },
    @{ n='test_cli';             src=@('tests\test_cli.c');                                 cl="$clPlain /D_WINSOCK_DEPRECATED_NO_WARNINGS /D_WIN32_WINNT=0x0601"; link='winhttp.lib shell32.lib advapi32.lib'; ui=$false },
    @{ n='test_gui_misc';        src=@('tests\test_gui_misc.c', $prof);                     cl=$clUni;   link=$lnGui;  ui=$false },
    @{ n='test_rules_ui';        src=@('tests\test_rules_ui.c', $prof, $res);               cl=$clUni;   link=$lnGui;  ui=$true },
    @{ n='test_main_ui';         src=@('tests\test_main_ui.c', $prof, $res);                cl=$clUni;   link=$lnGui;  ui=$true },
    @{ n='test_dialogs_ui';      src=@('tests\test_dialogs_ui.c', $prof, $res);             cl=$clUni;   link=$lnGui;  ui=$true }
)
$runStatic = $true
if ($Only) { $tests = $tests | Where-Object { $Only -contains $_.n }; $runStatic = ($Only -contains 'static_checks') }
if ($SkipUi) { $tests = $tests | Where-Object { -not $_.ui } }

function Invoke-Msvc([string]$name, [string]$body) {
    $bat = Join-Path $Out "$name.bat"
    $lines = @('@echo off')
    if ($vcvars) { $lines += "call `"$vcvars`" $Arch >nul" }
    $lines += "cd /d `"$WinRoot`""
    $lines += $body
    Set-Content -Path $bat -Value $lines -Encoding ASCII
    $log = & cmd /c "`"$bat`" 2>&1"
    return @{ code = $LASTEXITCODE; log = $log }
}

# resources for the GUI tests (menus, dialogs, icon, manifest) come from the real app.rc
if ($tests | Where-Object { $_.src -contains $res }) {
    $r = Invoke-Msvc 'rc' "cd /d `"$WinRoot\gui\res`" && rc /nologo /fo `"$Out\app.res`" app.rc"
    if ($r.code -ne 0) { Write-Host "Resource compile failed:`n$($r.log -join "`n")" -ForegroundColor Red; exit 2 }
}

$results = @()
foreach ($t in $tests) {
    $name = $t.n
    Write-Host "`n=== $name" -ForegroundColor Cyan
    $objDir = Join-Path $Out $name; New-Item -ItemType Directory -Path $objDir | Out-Null
    $srcs = ($t.src | ForEach-Object { if ($_ -like '*:*') { "`"$_`"" } else { $_ } }) -join ' '
    $cmd = "cl /nologo $warn $($t.cl) /Fo:`"$objDir\\`" $srcs /Fe:`"$Out\$name.exe`" /link $($t.link)"
    $b = Invoke-Msvc "build_$name" $cmd
    if ($b.code -ne 0 -or -not (Test-Path "$Out\$name.exe")) {
        Write-Host "BUILD FAILED" -ForegroundColor Red
        $b.log | Where-Object { $_ -match 'error|fatal|LNK' } | Select-Object -First 12 | ForEach-Object { Write-Host "  $_" }
        $results += [pscustomobject]@{ Test = $name; Result = 'BUILD FAILED' }
        continue
    }
    $outTxt = Join-Path $Out "$name.out.txt"
    $p = Start-Process -FilePath "$Out\$name.exe" -NoNewWindow -PassThru -RedirectStandardOutput $outTxt
    if (-not $p.WaitForExit(240000)) { $p.Kill(); Write-Host "TIMEOUT (240 s)" -ForegroundColor Red; $results += [pscustomobject]@{ Test = $name; Result = 'TIMEOUT' }; continue }
    Get-Content $outTxt | ForEach-Object { Write-Host "  $_" }
    $res1 = if ($p.ExitCode -eq 0) { 'PASS' } else { "FAIL (exit $($p.ExitCode))" }
    $results += [pscustomobject]@{ Test = $name; Result = $res1 }
}

# ------------------------------------------------------------------------------------------------------------------
# static checks: things that must stay consistent but that no compiler checks
# ------------------------------------------------------------------------------------------------------------------
if ($runStatic) {
    Write-Host "`n=== static_checks" -ForegroundColor Cyan
    $fails = New-Object System.Collections.Generic.List[string]; $n = 0
    function Check([bool]$ok, [string]$what) { $script:n++; if (-not $ok) { $script:fails.Add($what); Write-Host "  FAIL $what" } }
    function Read-Text([string]$rel) { [IO.File]::ReadAllText((Join-Path $WinRoot $rel)) }

    # 1. the version number is the same everywhere it is written
    $resH = Read-Text 'gui\res\resource.h'
    $maj = [regex]::Match($resH, 'PB_VER_MAJOR\s+(\d+)').Groups[1].Value; $min = [regex]::Match($resH, 'PB_VER_MINOR\s+(\d+)').Groups[1].Value
    $pat = [regex]::Match($resH, 'PB_VER_PATCH\s+(\d+)').Groups[1].Value
    $ver = "$maj.$min.$pat"
    Check ($maj -ne '' -and $min -ne '' -and $pat -ne '') 'resource.h has PB_VER_MAJOR/MINOR/PATCH'
    Check ([regex]::Match($resH, 'PB_VER_STR\s+"([^"]+)"').Groups[1].Value -eq $ver)  "resource.h PB_VER_STR is $ver"
    Check ([regex]::Match($resH, 'PB_VER_STRW\s+L"([^"]+)"').Groups[1].Value -eq $ver) "resource.h PB_VER_STRW is $ver"
    $nsi = Read-Text 'installer\ProxyBridge.nsi'
    Check ([regex]::Match($nsi, '!define PRODUCT_VERSION "([^"]+)"').Groups[1].Value -eq $ver) "installer PRODUCT_VERSION is $ver"
    Check ([regex]::Match($nsi, 'VIProductVersion "([^"]+)"').Groups[1].Value -eq "$ver.0")   "installer VIProductVersion is $ver.0"
    Check ([regex]::Match((Read-Text 'cli\main.c'), '#define VERSION "([^"]+)"').Groups[1].Value -eq $ver)       "cli VERSION is $ver"
    Check ([regex]::Match((Read-Text 'src\pb_internal.h'), '#define VERSION "([^"]+)"').Groups[1].Value -eq $ver) "engine VERSION is $ver"
    Check ([regex]::Match((Read-Text 'gui\res\app.manifest'), 'assemblyIdentity version="([^"]+)"').Groups[1].Value -eq "$ver.0") "app.manifest version is $ver.0"
    Check ((Read-Text '..\CONTRIBUTING.md').Contains("ProxyBridge-Setup-$ver.exe")) "CONTRIBUTING.md names ProxyBridge-Setup-$ver.exe"

    # 2. the installer: elevated, locked-down install folder, service ACL, normal-user launch, clean uninstall
    Check ($nsi -match 'RequestExecutionLevel admin') 'installer runs elevated'
    $ic = [regex]::Match($nsi, 'icacls "\$INSTDIR"[^\r\n]*').Value
    Check ($ic -match '/inheritance:r') 'install folder: inheritance removed'
    Check ($ic -match '\*S-1-5-18:\(OI\)\(CI\)F' -and $ic -match '\*S-1-5-32-544:\(OI\)\(CI\)F') 'install folder: SYSTEM and Administrators full control'
    Check ($ic -match '\*S-1-5-32-545:\(OI\)\(CI\)RX' -and $ic -notmatch '\*S-1-5-32-545:[^ ]*(M|F|W)\b') 'install folder: Users read/execute only'
    Check ($nsi -match '--setup-users') 'installer creates the ProxyBridge Users group (--setup-users)'
    Check ($nsi -match 'MUI_FINISHPAGE_RUN_FUNCTION\s+LaunchAppAsUser' -and $nsi -match 'explorer\.exe') 'finish page launches the app through Explorer (normal user)'
    Check ($nsi -notmatch 'MUI_FINISHPAGE_RUN\s+"') 'finish page does not start the exe directly from the elevated installer'
    $sd = [regex]::Match($nsi, "sc sdset ProxyBridgeSvc `"([^`"]+)`"").Groups[1].Value
    Check ($sd -ne '') 'service permission list (sc sdset) is set'
    Check ($sd -notmatch ';;;(WD|AU|BU|AN|NU)\)') 'service permissions never grant Everyone / Authenticated / Users / Anonymous'
    $iu = [regex]::Match($sd, '\(A;;([A-Z]+);;;IU\)').Groups[1].Value
    if ($iu) { $rights = for ($i = 0; $i -lt $iu.Length; $i += 2) { $iu.Substring($i, 2) }; Check (-not ($rights | Where-Object { 'WP','DT','WD','WO','DC','SD' -contains $_ })) 'interactive users may start the service but not stop/reconfigure/delete it' }
    Check ($nsi -match "sc delete ProxyBridgeSvc" -and $nsi -match 'localgroup "ProxyBridge Users" /delete' -and $nsi -match 'AllowedSids') 'uninstaller removes the service, the group and the saved SIDs'
    Check ($nsi -match 'netsh advfirewall firewall delete rule') 'uninstaller/installer clean up firewall rules'

    # 3. the pipe names and protocol version agree between the app and the service (one header, but make sure it is sane)
    $proto = Read-Text 'src\service\pb_proto.h'
    Check ([int][regex]::Match($proto, 'PB_PROTO_VERSION\s+(\d+)').Groups[1].Value -ge 5) 'service protocol version is at least 5'

    # 3b. the string enum and the EN/ZH table in loc.h list the same names in the same order (a shifted table shows the
    #     wrong text everywhere after the mistake)
    $loc = Read-Text 'gui\loc\loc.h'
    $enumBody = [regex]::Match($loc, 'enum\s*\{(.*?)\bS_COUNT\b', 'Singleline').Groups[1].Value
    $enumNames = [regex]::Matches($enumBody, '\bS_[A-Z0-9_]+\b') | ForEach-Object { $_.Value }
    $tableNames = [regex]::Matches($loc, '/\*\s*(S_[A-Z0-9_]+)\s*\*/\s*\{') | ForEach-Object { $_.Groups[1].Value }
    Check ($enumNames.Count -gt 100 -and $enumNames.Count -eq $tableNames.Count) 'loc.h: the string enum and the translation table have the same number of entries'
    $badAt = -1; for ($i = 0; $i -lt [Math]::Min($enumNames.Count, $tableNames.Count); $i++) { if ($enumNames[$i] -ne $tableNames[$i]) { $badAt = $i; break } }
    Check ($badAt -lt 0) ("loc.h: the translation table is in the same order as the enum" + $(if ($badAt -ge 0) { " (first difference: enum " + $enumNames[$badAt] + " vs table " + $tableNames[$badAt] + ")" } else { "" }))

    # 4. wiring: every test source is run by this script, and the workflow runs this script
    $self = [IO.File]::ReadAllText($PSCommandPath)
    foreach ($f in Get-ChildItem $PSScriptRoot -Filter 'test_*.c') { Check ($self.Contains("n='$($f.BaseName)'")) "tests\$($f.Name) is registered in run_tests.ps1" }
    $wf = [IO.File]::ReadAllText((Join-Path $RepoRoot '.github\workflows\build-windows.yml'))
    Check ($wf -match 'tests\\run_tests\.ps1') 'build-windows.yml runs tests\run_tests.ps1'

    $ok = ($fails.Count -eq 0)
    Write-Host ("  static_checks: " + $(if ($ok) { "OK ($n checks)" } else { "FAILED ($($fails.Count) of $n checks failed)" }))
    $results += [pscustomobject]@{ Test = 'static_checks'; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }) }
}

# the tests use private %APPDATA% folders under %TEMP%; remove what they left
Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -Filter 'pbtest_*' -ErrorAction SilentlyContinue | ForEach-Object { try { [IO.Directory]::Delete($_.FullName, $true) } catch {} }

Write-Host "`n================ summary ================" -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host
$bad = @($results | Where-Object { $_.Result -ne 'PASS' })
if ($bad.Count -gt 0 -or $results.Count -eq 0) { Write-Host "$($bad.Count) of $($results.Count) test program(s) did not pass" -ForegroundColor Red; exit 1 }
Write-Host "All $($results.Count) test programs passed" -ForegroundColor Green
exit 0
