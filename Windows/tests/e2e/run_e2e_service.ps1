<#
.SYNOPSIS
  Real end-to-end test of the way people actually use ProxyBridge for Windows: the real installer, the ProxyBridge Service
  (LocalSystem, named pipe), the same client library the app uses, the Live Connections data, the permissions around the
  service, the real app (ProxyBridge.exe) applying a profile, and the real uninstaller.

.DESCRIPTION
  run_e2e.ps1 tests the engine through the CLI. This one tests everything around it that the CLI never touches:

    installer      silent install: files, service (auto start), "ProxyBridge Users" group, folder permissions, PATH, shortcuts
    permissions    a user outside the group is DENIED, a member can connect (needs a temporary local user; SKIP if not possible)
    service path   proxies, rules, start/stop, pause, Log Every Connection, traffic logging, rule enable/disable/move/delete,
                   a second client (BUSY), a client that dies (the engine is released), with real traffic
    live data      Live Connections: process, proxy, rule, destination, and sent/received compared with the real transfer
    the app        ProxyBridge.exe started with a profile applies it to the service and the traffic follows
    uninstaller    service, group, driver, files and PATH are really gone

  It INSTALLS SOFTWARE, LOADS THE KERNEL DRIVER and creates a local user. It is meant for a disposable CI runner (the
  "Real-traffic end-to-end tests, installer and service" step of build-windows.yml) and refuses to run elsewhere unless
  -IKnowThisLoadsTheKernelDriver is given.

.PARAMETER PbDir  Folder with the compile.ps1 output (ProxyBridge-Setup-*.exe).
.PARAMETER Out    Where logs and test files go.
#>
param(
    [string]$PbDir = (Join-Path $PSScriptRoot '..\..\output'),
    [string]$Out   = (Join-Path $PSScriptRoot 'out_service'),
    [switch]$IKnowThisLoadsTheKernelDriver
)
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -and -not $IKnowThisLoadsTheKernelDriver) {
    Write-Host "This test installs ProxyBridge, loads the WinDivert kernel driver and creates a local user. It is for a CI runner." -ForegroundColor Yellow
    Write-Host "Run it on a throw-away VM with -IKnowThisLoadsTheKernelDriver if you really mean to." -ForegroundColor Yellow
    exit 2
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator rights are required (installer, service, driver)." -ForegroundColor Red; exit 2
}

$PbDir = (Resolve-Path $PbDir).Path
$setup = Get-ChildItem -Path $PbDir -Filter 'ProxyBridge-Setup-*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $setup) { Write-Host "No ProxyBridge-Setup-*.exe in $PbDir" -ForegroundColor Red; exit 2 }
if (Get-Service ProxyBridgeSvc -ErrorAction SilentlyContinue) { Write-Host "ProxyBridge is already installed here; this test needs a clean machine." -ForegroundColor Red; exit 2 }

if (Test-Path $Out) { [IO.Directory]::Delete($Out, $true) }
New-Item -ItemType Directory -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$bin = Join-Path $Out 'bin'; New-Item -ItemType Directory -Path $bin | Out-Null

. (Join-Path $PSScriptRoot 'e2e_common.ps1')

$PORT_OPEN = 31080; $PORT_HTTP = 33128
$logOpen = Join-Path $Out 'nexus-open.log'; $logHttp = Join-Path $Out 'http-proxy.log'
$inst = Join-Path $env:ProgramFiles 'ProxyBridge'
$testUser = 'pbe_user'
$publicDir = 'C:\Users\Public\pbe'
$driver = $null; $gui = $null; $uninstalled = $false

# ---- the helper that talks to the service like the app does (built from the app's own client code)
Write-Host "`n=== building the service test client" -ForegroundColor Cyan
$vcvars = $null
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsPath) { $c = Join-Path $vsPath 'VC\Auxiliary\Build\vcvarsall.bat'; if (Test-Path $c) { $vcvars = $c } }
}
$svcClient = Join-Path $bin 'svc_client.exe'
$bat = Join-Path $Out 'build_client.bat'
$lines = @('@echo off'); if ($vcvars) { $lines += "call `"$vcvars`" x64 >nul" }
$lines += "cd /d `"$PSScriptRoot`""
$lines += "cl /nologo /W3 /wd4996 /D_CRT_SECURE_NO_WARNINGS svc_client.c /Fo:`"$bin\\`" /Fe:`"$svcClient`" /link user32.lib advapi32.lib"
Set-Content -Path $bat -Value $lines -Encoding ASCII
$buildLog = & cmd /c "`"$bat`" 2>&1"
if (-not (Test-Path $svcClient)) { Write-Host ($buildLog -join "`n"); Write-Host "svc_client.exe did not build" -ForegroundColor Red; exit 2 }
Write-Host "svc_client.exe built"

# ---- a small driver for the helper: send a line, read the answer; events are kept on the side
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
public class SvcDrv {
    Process p; readonly object L = new object();
    List<string> replies = new List<string>(); List<string> events = new List<string>(); int ri = 0;
    public SvcDrv(string exe) {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, CreateNoWindow = true };
        p = Process.Start(psi);
        p.OutputDataReceived += (s, e) => { if (e.Data == null) return; lock (L) { if (e.Data.StartsWith("EVT\t")) events.Add(e.Data); else replies.Add(e.Data); } };
        p.BeginOutputReadLine();
    }
    string Next(int ms) {
        var end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end) {
            lock (L) { if (ri < replies.Count) return replies[ri++]; }
            if (p.HasExited) { lock (L) { if (ri < replies.Count) return replies[ri++]; } return null; }
            Thread.Sleep(20);
        }
        return null;
    }
    public string First(int ms) { return Next(ms); }
    public string[] Cmd(string c, int ms) {
        p.StandardInput.WriteLine(c); p.StandardInput.Flush();
        var o = new List<string>(); string l;
        while ((l = Next(ms)) != null) { o.Add(l); if (!c.StartsWith("flows") || l.StartsWith("END\t")) break; }
        return o.ToArray();
    }
    public string[] Events() { lock (L) { return events.ToArray(); } }
    public bool Exited { get { return p.HasExited; } }
    public int Pid { get { return p.Id; } }
    public void Kill() { try { p.Kill(); } catch { } }
    public void Quit() { try { p.StandardInput.WriteLine("quit"); p.StandardInput.Flush(); p.WaitForExit(5000); } catch { } }
}
'@

function Svc([string]$cmd, [int]$ms = 20000) { $r = $script:driver.Cmd($cmd, $ms); return ,$r }   # the comma keeps a one-line answer an array
function Svc-Id([string]$cmd) { $r = Svc $cmd; if ($r.Count -ge 1 -and $r[0] -match "^OK`t(\d+)$") { return [int]$Matches[1] }; return 0 }
function Svc-Ok([string]$cmd) { $r = Svc $cmd; return ($r.Count -ge 1 -and $r[0] -like 'OK*') }
function Get-Flows {
    $out = @()
    foreach ($l in (Svc 'flows')) {
        $f = $l -split "`t"
        if ($f[0] -eq 'FLOW' -and $f.Count -ge 13) {
            $out += [pscustomobject]@{ Id = [uint64]$f[1]; Pid = [int]$f[2]; Udp = $f[3] -eq '1'; V6 = $f[4] -eq '1'; Host = $f[5]; Port = [int]$f[6]
                                       Sent = [uint64]$f[7]; Received = [uint64]$f[8]; Name = $f[9]; Rule = [int]$f[10]; Proxy = [int]$f[11]; AgeMs = [uint64]$f[12] }
        }
    }
    return $out
}
function Conn-Text([string]$proc) { (@($script:driver.Events() | Where-Object { $_ -match "^EVT`tCONN`t[^`t]*$([regex]::Escape($proc))`t" }) -join ' | ') -replace "`t", ' ' }
function Conn-Events([string]$proc) { @($script:driver.Events() | Where-Object { $_ -match "^EVT`tCONN`t[^`t]*$([regex]::Escape($proc))`t" }).Count }
function Probe([string]$exe = $svcClient) { ((& $exe --probe 2>&1 | Out-String).Trim() -split "`n")[0].Trim() }

function Via-Open([string]$label, [string]$client, [string]$url = 'http://example.com/') {
    $before = Count $logOpen '[CONNECT]'
    $r = Get-Ok $client $url 'Example Domain'
    Check $label ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain') -and (Count $logOpen '[CONNECT]') -gt $before) "exit $($r.Exit) status $($r.Status)"
}
function Direct-Open([string]$label, [string]$client, [string]$url = 'http://example.com/') {
    $before = Count $logOpen '[CONNECT]'
    $r = Get-Ok $client $url 'Example Domain'
    Check $label ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain') -and (Count $logOpen '[CONNECT]') -eq $before) "exit $($r.Exit) status $($r.Status)"
}

try {
    # ======================= installer =======================
    Write-Host "`n=== silent install" -ForegroundColor Cyan
    $p = Start-Process -FilePath $setup.FullName -ArgumentList '/S' -PassThru -Wait
    Check 'Installer finishes silently' ($p.ExitCode -eq 0) "exit code $($p.ExitCode)"
    $svc = Get-Service ProxyBridgeSvc -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 30 -and $svc -and $svc.Status -ne 'Running'; $i++) { Start-Sleep -Seconds 1; $svc.Refresh() }
    Check 'Installed files: app, CLI, engine, service, driver, uninstaller' (@('ProxyBridge.exe', 'ProxyBridge_CLI.exe', 'ProxyBridgeCore.dll', 'ProxyBridgeSvc.exe', 'WinDivert.dll', 'WinDivert64.sys', 'uninst.exe' |
        Where-Object { -not (Test-Path (Join-Path $inst $_)) }).Count -eq 0) "folder $inst"
    Check 'The ProxyBridge Service exists and is running' ($svc -and $svc.Status -eq 'Running') "status $(if ($svc) { $svc.Status } else { 'missing' })"
    Check 'The service starts with Windows (automatic)' ((& sc.exe qc ProxyBridgeSvc | Out-String) -match 'AUTO_START')
    Check 'The "ProxyBridge Users" group exists' ((& net.exe localgroup 'ProxyBridge Users' 2>&1 | Out-String) -match 'ProxyBridge Users')
    $usersLine = @(& icacls.exe $inst) | Where-Object { $_ -match 'BUILTIN\\Users:' } | Select-Object -First 1
    Check 'Install folder: ordinary users can read and run, not modify' ($usersLine -match '\(RX\)' -and $usersLine -notmatch '\((F|M|W)\)') "$usersLine"
    Check 'The install folder is on the machine PATH' (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -contains $inst)
    $lnk = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\ProxyBridge\ProxyBridge.lnk", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\ProxyBridge\ProxyBridge.lnk") | Where-Object { Test-Path $_ }
    Check 'Start Menu shortcut exists' ([bool]$lnk)
    Check 'The installed CLI starts (--help)' ((& (Join-Path $inst 'ProxyBridge_CLI.exe') --help 2>&1 | Out-String) -match 'ProxyBridge')

    # ======================= proxies and clients =======================
    Write-Host "`n=== starting proxies" -ForegroundColor Cyan
    Start-Bg $node @($nexusJs, '--port', "$PORT_OPEN", '--verbose') $logOpen | Out-Null
    Start-Bg $python @((Join-Path $PSScriptRoot 'http_proxy.py'), '--port', "$PORT_HTTP", '--log', $logHttp) "$Out\http-proxy.out" | Out-Null
    foreach ($pt in $PORT_OPEN, $PORT_HTTP) { if (-not (Wait-Port $pt 20)) { Write-Host "proxy on port $pt did not start" -ForegroundColor Red; exit 2 } }
    $names = 'svc', 'http', 'block', 'flow', 'order', 'nomatch', 'gui', 'after'
    $exe = @{}; foreach ($n in $names) { $exe[$n] = New-Client "pbe_$n" }
    $bigUrl = 'https://speed.cloudflare.com/__down?bytes=26214400'; $bigSize = 26214400

    # ======================= who may use the service =======================
    Write-Host "`n=== permissions" -ForegroundColor Cyan
    $userReady = $false
    try {
        $pw = 'Pbe-' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '!aA1'
        New-LocalUser -Name $testUser -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -AccountNeverExpires | Out-Null
        New-Item -ItemType Directory -Path $publicDir -Force | Out-Null
        Copy-Item $svcClient (Join-Path $publicDir 'svc_client.exe')
        $cred = New-Object Management.Automation.PSCredential(".\$testUser", (ConvertTo-SecureString $pw -AsPlainText -Force))
        $userReady = $true
    } catch { Skip 'Permissions: a user outside the group is refused' "could not create a local test user: $($_.Exception.Message)" }
    if ($userReady) {
        function Probe-As {
            $o = Join-Path $publicDir 'probe.txt'; if (Test-Path $o) { Remove-Item $o -Force }
            Start-Process -FilePath (Join-Path $publicDir 'svc_client.exe') -ArgumentList '--probe' -Credential $cred -WorkingDirectory $publicDir `
                -RedirectStandardOutput $o -NoNewWindow -Wait -ErrorAction Stop
            if (Test-Path $o) { return ((Get-Content $o -Raw).Trim() -split "`n")[0].Trim() }; return ''
        }
        try {
            $a = Probe-As
            Check 'A normal user who is not in "ProxyBridge Users" is refused (DENIED)' ($a -match 'DENIED') "answer: $a"
            Add-LocalGroupMember -Group 'ProxyBridge Users' -Member $testUser
            $a = Probe-As
            Check 'The same user can connect once added to "ProxyBridge Users"' ($a -eq 'CONNECTED') "answer: $a"
        } catch { Skip 'Permissions: refused outside the group, allowed inside' "could not start a process as the test user: $($_.Exception.Message)" }
    }
    Check 'An administrator can connect' ((Probe) -eq 'CONNECTED')

    # ======================= the service path with real traffic =======================
    Write-Host "`n=== connect, add proxies and rules, start" -ForegroundColor Cyan
    $driver = New-Object SvcDrv($svcClient)
    $first = $driver.First(20000)
    Check 'The client connects to the service' ($first -eq 'CONNECTED') "answer: $first"
    if ($first -ne 'CONNECTED') { throw 'cannot continue without a connection to the service' }
    $pA = Svc-Id "proxy`tsocks5`t127.0.0.1`t$PORT_OPEN`t-`t-`t1"
    $pB = Svc-Id "proxy`thttp`t127.0.0.1`t$PORT_HTTP`t-`t-`t1"
    Check 'Two proxy servers are added through the service' ($pA -gt 0 -and $pB -gt 0 -and $pA -ne $pB) "ids $pA, $pB"
    $rS = Svc-Id "rule`tpbe_svc.exe`t*`t*`t*`ttcp`tproxy`t$pA`t0"
    $rH = Svc-Id "rule`tpbe_http.exe`t*`t*`t*`ttcp`tproxy`t$pB`t0"
    $rB = Svc-Id "rule`tpbe_block.exe`t*`t*`t*`ttcp`tblock`t0`t0"
    $rF = Svc-Id "rule`tpbe_flow.exe`t*`t*`t*`ttcp`tproxy`t$pA`t0"
    $rO1 = Svc-Id "rule`tpbe_order.exe`t*`t*`t*`ttcp`tproxy`t$pA`t0"
    $rO2 = Svc-Id "rule`tpbe_order.exe`t*`t*`t*`ttcp`tdirect`t0`t0"
    Check 'Rules are added through the service' (($rS, $rH, $rB, $rF, $rO1, $rO2 | Where-Object { $_ -le 0 }).Count -eq 0) "ids $rS $rH $rB $rF $rO1 $rO2"
    Check 'Rules keep the order they were added in' ((Svc-Id "rulepos`t$rO1") -lt (Svc-Id "rulepos`t$rO2"))
    Check 'The engine starts' (Svc-Ok 'start')
    $null = Svc-Ok "logall`t0"
    if (-not (Wait-Port 34010 30)) { throw 'the relay did not come up' }
    Start-Sleep -Seconds 2

    Write-Host "`n=== real traffic through the service-driven engine" -ForegroundColor Cyan
    Via-Open 'Proxy rule: the page comes back through the SOCKS5 proxy' $exe.svc
    $bh = Count $logHttp '[CONNECT]'
    $r = Get-Ok $exe.http 'http://example.com/' 'Example Domain'
    Check 'A second rule sends another program through the HTTP proxy' ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain') -and (Count $logHttp '[CONNECT]') -gt $bh)
    $r = Invoke-Curl $exe.block 'http://example.com/' @() 10
    Check 'Block rule: the connection fails' ($r.Exit -ne 0 -and -not (Has-Body $r 'Example Domain'))

    # ---- Live Connections: who, which proxy, which rule, and real byte counts
    Write-Host "`n=== Live Connections against a real, rate-limited transfer" -ForegroundColor Cyan
    $flowFile = Join-Path $Out 'flow.bin'; $httpFile = Join-Path $Out 'flow_http.bin'
    $cf = Start-Process -FilePath $exe.flow -ArgumentList @('-s', '-S', '-o', $flowFile, '--limit-rate', '1M', '--max-time', '100', '--connect-timeout', '15', $bigUrl) -PassThru -WindowStyle Hidden
    $ch = Start-Process -FilePath $exe.http -ArgumentList @('-s', '-S', '-o', $httpFile, '--limit-rate', '300k', '--max-time', '60', '--connect-timeout', '15', $bigUrl) -PassThru -WindowStyle Hidden
    $mine = $null; $other = $null
    for ($i = 0; $i -lt 40 -and (-not $mine -or -not $other); $i++) {
        Start-Sleep -Milliseconds 500
        $fl = Get-Flows
        $mine = $fl | Where-Object { $_.Pid -eq $cf.Id -and -not $_.Udp } | Select-Object -First 1
        $other = $fl | Where-Object { $_.Pid -eq $ch.Id -and -not $_.Udp } | Select-Object -First 1
    }
    if ($mine) {
        Check 'Live Connections lists the program with its real name and process id' ($mine.Name -eq 'pbe_flow.exe') "name '$($mine.Name)' pid $($mine.Pid)"
        Check 'Live Connections shows the destination (host and port)' ($mine.Port -eq 443 -and $mine.Host -match 'cloudflare|\d+\.\d+\.\d+\.\d+') "$($mine.Host):$($mine.Port)"
        Check 'Live Connections shows which proxy server this connection goes to' ($mine.Proxy -eq $pA) "proxy id $($mine.Proxy), expected $pA"
        Check 'Live Connections shows which rule matched' ($mine.Rule -eq $rF) "rule id $($mine.Rule), expected $rF"
    } else { foreach ($t in 'name and process id', 'destination', 'proxy server', 'matching rule') { Check "Live Connections shows the $t" $false 'the transfer never appeared in the list' } }
    if ($other) {
        Check 'A program on another rule shows the other proxy and rule at the same time' ($other.Proxy -eq $pB -and $other.Rule -eq $rH -and $other.Name -eq 'pbe_http.exe') "proxy $($other.Proxy)/$pB rule $($other.Rule)/$rH name $($other.Name)"
    } else { Check 'A program on another rule shows the other proxy and rule at the same time' $false 'the second transfer never appeared in the list' }

    # sample the counters while the transfer runs at about 1 MB/s
    $lastRecv = 0; $lastSent = 0; $s1 = $null; $s2 = $null
    if ($mine) {
        Start-Sleep -Seconds 2
        $s1 = Get-Flows | Where-Object { $_.Id -eq $mine.Id } | Select-Object -First 1; $t1 = Get-Date
        Start-Sleep -Seconds 4
        $s2 = Get-Flows | Where-Object { $_.Id -eq $mine.Id } | Select-Object -First 1; $t2 = Get-Date
        if ($s1 -and $s2) {
            $rate = ($s2.Received - $s1.Received) / ($t2 - $t1).TotalSeconds
            Check 'Received bytes grow while the transfer runs' ($s2.Received -gt $s1.Received) "$($s1.Received) -> $($s2.Received)"
            Check 'The received rate matches the real rate limit (about 1 MB/s)' ($rate -gt 600000 -and $rate -lt 1900000) ("{0:N0} bytes/s" -f $rate)
            Check 'Sent bytes are only the request (a download sends very little)' ($s2.Sent -gt 0 -and $s2.Sent -lt 100000) "sent $($s2.Sent)"
        } else { foreach ($t in 'Received bytes grow while the transfer runs', 'The received rate matches the real rate limit (about 1 MB/s)', 'Sent bytes are only the request (a download sends very little)') { Check $t $false 'the flow disappeared while sampling' } }
        # keep sampling until it ends, remember the last values
        $end = (Get-Date).AddSeconds(80)
        while (-not $cf.HasExited -and (Get-Date) -lt $end) {
            $x = Get-Flows | Where-Object { $_.Id -eq $mine.Id } | Select-Object -First 1
            if ($x) { $lastRecv = $x.Received; $lastSent = $x.Sent }
            Start-Sleep -Milliseconds 700
        }
    }
    $null = $cf.WaitForExit(15000)
    $len = if (Test-Path $flowFile) { (Get-Item $flowFile).Length } else { 0 }
    Check 'The rate-limited download itself arrived complete' ($cf.HasExited -and $cf.ExitCode -eq 0 -and $len -eq $bigSize) "exit $(if ($cf.HasExited) { $cf.ExitCode }), $len bytes"
    if ($mine -and $len -eq $bigSize) {
        Check 'At the end the received counter equals the real transfer size (within a second of data and TLS overhead)' ($lastRecv -ge ($bigSize * 0.9) -and $lastRecv -le ($bigSize * 1.05 + 100000)) "counter $lastRecv, file $bigSize"
    }
    Start-Sleep -Seconds 6
    Check 'A finished connection leaves the list' (-not (Get-Flows | Where-Object { $_.Pid -eq $cf.Id }))
    if (-not $ch.HasExited) { Stop-Process -Id $ch.Id -Force }

    # ---- pause, logging switches
    Write-Host "`n=== pause, Log Every Connection, traffic logging" -ForegroundColor Cyan
    $null = Svc-Ok "enabled`t0"; Start-Sleep -Seconds 1
    Direct-Open 'Paused: a Proxy rule is not applied (traffic goes direct)' $exe.svc
    $r = Get-Ok $exe.block 'http://example.com/' 'Example Domain'
    Check 'Paused: a Block rule is not applied either' ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain'))
    $null = Svc-Ok "enabled`t1"; Start-Sleep -Seconds 1
    Via-Open 'Resumed: the Proxy rule applies again' $exe.svc

    $null = Svc-Ok 'clearlogs'; $null = Svc-Ok "logall`t0"
    # One program opens the same connection twice (the log remembers per process, so it has to be one process).
    function Twice($client) { & $client -s -o NUL -H "Connection: close" --max-time 20 http://example.com/ --next -s -o NUL -H "Connection: close" --max-time 20 http://example.com/ 2>&1 | Out-Null; Start-Sleep -Seconds 2 }
    function Web-Events([string]$proc) { @($script:driver.Events() | Where-Object { $_ -match "^EVT`tCONN`t[^`t]*$([regex]::Escape($proc))`t\d+`t[^`t]+`t80`t" }).Count }
    Twice $exe.nomatch
    # default: a connection is logged once per program, destination, port and action; "every connection" logs each one
    Check 'Log Every Connection off: the same connection twice is logged once' ((Web-Events 'pbe_nomatch.exe') -eq 1) (Conn-Text 'pbe_nomatch.exe')
    $before = Web-Events 'pbe_nomatch.exe'
    $null = Svc-Ok "logall`t1"
    Twice $exe.nomatch
    Check 'Log Every Connection on: each of the two connections is logged' ((Web-Events 'pbe_nomatch.exe') -ge ($before + 2)) "$before -> $(Web-Events 'pbe_nomatch.exe') events"
    $null = Svc-Ok "logall`t0"

    $before = Conn-Events 'pbe_svc.exe'
    $r = Get-Ok $exe.svc 'http://example.com/' 'Example Domain'; Start-Sleep -Seconds 2
    Check 'A proxied connection is logged with its process and the proxy it used' ((Conn-Events 'pbe_svc.exe') -gt $before -and (Conn-Text 'pbe_svc.exe') -match "Proxy SOCKS5://127.0.0.1:$PORT_OPEN") (Conn-Text 'pbe_svc.exe')
    $null = Svc-Ok "traffic`t0"; Start-Sleep -Seconds 1
    $bo = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.svc 'http://example.com/' 'Example Domain'
    Check 'Switching traffic logging off does not change where the traffic goes' ($r.Exit -eq 0 -and (Count $logOpen '[CONNECT]') -gt $bo)
    $null = Svc-Ok "traffic`t1"

    # ---- editing rules while running
    Write-Host "`n=== rules changed while the engine runs" -ForegroundColor Cyan
    Via-Open 'Order: the first rule (Proxy) wins' $exe.order
    $null = Svc-Ok "disable_rule`t$rO1"; Start-Sleep -Seconds 1
    Direct-Open 'Disable the first rule: the next one (Direct) applies' $exe.order
    $null = Svc-Ok "enable_rule`t$rO1"; Start-Sleep -Seconds 1
    Via-Open 'Enable it again: Proxy applies again' $exe.order
    Check 'Move the Direct rule to the top' (Svc-Ok "move_rule`t$rO2`t1")
    Check 'The rule list order changed' ((Svc-Id "rulepos`t$rO2") -lt (Svc-Id "rulepos`t$rO1"))
    Start-Sleep -Seconds 1
    Direct-Open 'After the move the Direct rule wins' $exe.order
    $null = Svc-Ok "delete_rule`t$rS"; Start-Sleep -Seconds 1
    Direct-Open 'Delete a rule: that program goes direct' $exe.svc
    Check 'Deleting a rule that is already gone is refused' (-not (Svc-Ok "delete_rule`t$rS"))

    # ---- one client at a time, and a client that dies
    Write-Host "`n=== second client, and a client that is killed" -ForegroundColor Cyan
    Check 'A second client is told the service is BUSY' ((Probe) -match 'BUSY') "answer: $(Probe)"
    $null = Svc-Id "rule`tpbe_after.exe`t*`t*`t*`ttcp`tproxy`t$pA`t0"
    Via-Open 'Before the kill: a fresh rule proxies' $exe.after
    $driver.Kill(); $driver = $null
    Start-Sleep -Seconds 4
    Check 'The service keeps running after its client was killed' ((Get-Service ProxyBridgeSvc).Status -eq 'Running')
    Direct-Open 'The engine was released: the program is no longer proxied' $exe.after
    $p2 = Probe
    Check 'A new client can connect after the old one died' ($p2 -eq 'CONNECTED') "answer: $p2"

    # ======================= the real app =======================
    Write-Host "`n=== the real ProxyBridge app applies a profile to the service" -ForegroundColor Cyan
    $appData = Join-Path $Out 'appdata'; $profDir = Join-Path $appData 'ProxyBridge\profiles'
    New-Item -ItemType Directory -Path $profDir -Force | Out-Null
    $profile = @{ Version = '1.0'; IsTrafficLoggingEnabled = $true
        ProxyConfigs = @(@{ Id = 1; Name = 'nexus-open'; Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_OPEN"; Username = ''; Password = ''; SendDomainToProxy = $true })
        ProxyRules = @(@{ Name = 'pbe_gui.exe'; ProcessName = 'pbe_gui.exe'; TargetHosts = '*'; TargetPorts = '*'; TargetDomains = '*'; Protocol = 'TCP'
                          Action = 'PROXY'; IsEnabled = $true; LocalhostViaProxy = $false; ProxyConfigId = 1 }) }
    ($profile | ConvertTo-Json -Depth 6) | Set-Content -Path (Join-Path $profDir 'e2e.pbprofile') -Encoding UTF8
    (@{ ActiveProfileName = 'e2e'; CheckForUpdatesOnStartup = $false; LastUpdateCheck = ''; StartWithWindows = $false } | ConvertTo-Json) |
        Set-Content -Path (Join-Path $appData 'ProxyBridge\settings.json') -Encoding UTF8
    Direct-Open 'Before the app starts the program is not proxied' $exe.gui
    $oldAppData = $env:APPDATA; $env:APPDATA = $appData
    try { $gui = Start-Process -FilePath (Join-Path $inst 'ProxyBridge.exe') -PassThru } finally { $env:APPDATA = $oldAppData }
    $win = $false
    for ($i = 0; $i -lt 60 -and -not $gui.HasExited; $i++) { $gui.Refresh(); if ($gui.MainWindowHandle -ne 0) { $win = $true; break }; Start-Sleep -Milliseconds 500 }
    Check 'The app starts and opens its window' ($win -and -not $gui.HasExited) "window title '$($gui.MainWindowTitle)'"
    if ($win) {
        Start-Sleep -Seconds 5
        Check 'The app connected to the service (the service is busy for others)' ((Probe) -match 'BUSY')
        Via-Open 'The profile rule is applied: the program goes through the proxy' $exe.gui
        [void]$gui.CloseMainWindow()
        # closing the window sends the app to the tray (it keeps running); end it the hard way, like quitting from a crash
        Start-Sleep -Seconds 2
        if (-not $gui.HasExited) { Stop-Process -Id $gui.Id -Force }
        Start-Sleep -Seconds 3
        Check 'The service keeps running after the app closed' ((Get-Service ProxyBridgeSvc).Status -eq 'Running')
        Direct-Open 'After the app closed the engine is released (no proxy)' $exe.gui
        Check 'The service accepts a new client after the app closed' ((Probe) -eq 'CONNECTED')
    }
}
catch {
    Write-Host "STOPPED: $($_.Exception.Message)" -ForegroundColor Red
    Check 'The service test ran to the end' $false $_.Exception.Message
}
finally {
    foreach ($p in $procs) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch { } }
    if ($driver) { $driver.Kill() }
    if ($gui) { try { if (-not $gui.HasExited) { Stop-Process -Id $gui.Id -Force } } catch { } }
    Get-Process -Name 'pbe_*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    try { Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue } catch { }
    if (Test-Path $publicDir) { Remove-Item $publicDir -Recurse -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 1
}

# ======================= uninstaller =======================
Write-Host "`n=== silent uninstall" -ForegroundColor Cyan
if (Test-Path (Join-Path $inst 'uninst.exe')) {
    $u = Start-Process -FilePath (Join-Path $inst 'uninst.exe') -ArgumentList @('/S', "_?=$inst") -PassThru -Wait
    Check 'Uninstaller finishes silently' ($u.ExitCode -eq 0) "exit code $($u.ExitCode)"
    Start-Sleep -Seconds 2
    Check 'The service is gone' (-not (Get-Service ProxyBridgeSvc -ErrorAction SilentlyContinue))
    Check 'The "ProxyBridge Users" group is gone' ((& net.exe localgroup 'ProxyBridge Users' 2>&1 | Out-String) -notmatch 'Members')
    Check 'The WinDivert driver service is gone' (-not (Get-Service WinDivert -ErrorAction SilentlyContinue))
    Check 'The program files are removed' (@('ProxyBridge.exe', 'ProxyBridge_CLI.exe', 'ProxyBridgeCore.dll', 'ProxyBridgeSvc.exe', 'WinDivert.dll', 'WinDivert64.sys' |
        Where-Object { Test-Path (Join-Path $inst $_) }).Count -eq 0)
    Check 'The install folder is removed from the machine PATH' (-not (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -contains $inst))
    Check 'The uninstall entry is removed' (-not (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyBridge'))
    Remove-Item $inst -Recurse -Force -ErrorAction SilentlyContinue
} else { Skip 'Uninstaller' 'the installation did not complete' }

Write-Host "`n================ summary ================" -ForegroundColor Cyan
$results | Format-Table Test, Result -AutoSize | Out-String | Write-Host
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' })
if ($failed.Count) {
    Write-Host "--- failed checks ---"; $failed | ForEach-Object { Write-Host "  $($_.Test)  ($($_.Detail))" }
    Write-Host "$($failed.Count) of $($results.Count) checks failed" -ForegroundColor Red; exit 1
}
Write-Host "All $($results.Count) checks passed" -ForegroundColor Green
exit 0
