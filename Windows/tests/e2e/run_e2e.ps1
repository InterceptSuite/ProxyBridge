<#
.SYNOPSIS
  Real-traffic end-to-end test of ProxyBridge for Windows: the real engine and WinDivert driver (through
  ProxyBridge_CLI.exe), a real SOCKS5 proxy (Nexus Proxy), a small real HTTP proxy, and real requests to real
  servers. It checks that traffic really goes where the rules say, with real content coming back.

.DESCRIPTION
  The unit tests of run_tests.ps1 use made-up data and never load the driver. This one does the opposite, so it
  catches what they cannot: the driver and redirection, the relay, proxy interoperability, DNS-based rules, UDP.

  It LOADS THE KERNEL DRIVER and redirects traffic of the machine it runs on. It is meant for a disposable CI
  runner (the "Real-traffic end-to-end tests" step of build-windows.yml). It refuses to run elsewhere unless
  -IKnowThisLoadsTheKernelDriver is given.

  Every test client is a copy of curl.exe (or nslookup.exe) with its own file name (pbe_xxx.exe), and each rule
  matches one of those names, so one engine run covers every scenario and nothing else on the machine is touched.

.PARAMETER PbDir  Folder with ProxyBridge_CLI.exe, ProxyBridgeCore.dll, WinDivert.dll and WinDivert64.sys (compile.ps1 output).
.PARAMETER Out    Where logs and test files go.
#>
param(
    [string]$PbDir = (Join-Path $PSScriptRoot '..\..\output'),
    [string]$Out   = (Join-Path $PSScriptRoot 'out'),
    [switch]$IKnowThisLoadsTheKernelDriver
)
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -and -not $IKnowThisLoadsTheKernelDriver) {
    Write-Host "This test loads the WinDivert kernel driver and redirects this machine's traffic. It is for a CI runner." -ForegroundColor Yellow
    Write-Host "Run it on a throw-away VM with -IKnowThisLoadsTheKernelDriver if you really mean to." -ForegroundColor Yellow
    exit 2
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator rights are required (the driver)." -ForegroundColor Red; exit 2
}

$PbDir = (Resolve-Path $PbDir).Path
foreach ($f in 'ProxyBridge_CLI.exe', 'ProxyBridgeCore.dll', 'WinDivert.dll', 'WinDivert64.sys') {
    if (-not (Test-Path (Join-Path $PbDir $f))) { Write-Host "Missing $f in $PbDir" -ForegroundColor Red; exit 2 }
}
if (Test-Path $Out) { [IO.Directory]::Delete($Out, $true) }
New-Item -ItemType Directory -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$bin = Join-Path $Out 'bin'; New-Item -ItemType Directory -Path $bin | Out-Null

# ---- the real SOCKS5 proxy: Nexus Proxy, pinned to a commit and checked against its hash
$nexusSha = '3b7ffe3b78400ae4a4e6f1ba7cbe5c689023f23a'
$nexusHash = 'D20D00364FD4344D333760DF74053CAB85070960590A54559DDA8AD5B7B07E4B'
$nexusJs = Join-Path $Out 'nexus.js'
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/InterceptSuite/nexus-proxy/$nexusSha/script.js" -OutFile $nexusJs -UseBasicParsing
if ((Get-FileHash $nexusJs -Algorithm SHA256).Hash -ne $nexusHash) { Write-Host "nexus.js hash mismatch" -ForegroundColor Red; exit 2 }

# Stock Nexus cannot do UDP ASSOCIATE with current Node.js: its relay socket is IPv6 (dual-stack) but is bound to the IPv4
# address '0.0.0.0', which Node rejects, so it answers "general failure". The Linux suite carries the same fix as a patch
# (Linux/tests/nexus-linux-udp.patch). It only changes the UDP part of the test proxy, never ProxyBridge. Each edit must
# match exactly once, so a new Nexus version cannot silently slip through unpatched.
$nx = [IO.File]::ReadAllText($nexusJs)
$edits = @(
    @("udpRelay.bind(0, '0.0.0.0', () => {", "udpRelay.bind(0, '::', () => {"),
    @("udpRelay.send(data, port, host);", "udpRelay.send(data, port, host.includes(':') ? host : '::ffff:' + host);"),
    @("handleRemoteToClient(msg, rinfo, udpRelay, remoteMap) {", "handleRemoteToClient(msg, rinfo, udpRelay, remoteMap) {`n    rinfo = { ...rinfo, address: rinfo.address.replace(/^::ffff:/i, '') };")
)
foreach ($e in $edits) {
    $n = ([regex]::Matches($nx, [regex]::Escape($e[0]))).Count
    if ($n -ne 1) { Write-Host "Nexus UDP patch: expected one match of '$($e[0])', found $n" -ForegroundColor Red; exit 2 }
    $nx = $nx.Replace($e[0], $e[1])
}
$nexusJs = Join-Path $Out 'nexus-udp.js'
[IO.File]::WriteAllText($nexusJs, $nx)
$node = (Get-Command node -ErrorAction Stop).Source
$python = (Get-Command python -ErrorAction Stop).Source

$PORT_OPEN = 31080; $PORT_AUTH = 31081; $PORT_HTTP = 33128
$logOpen = Join-Path $Out 'nexus-open.log'; $logAuth = Join-Path $Out 'nexus-auth.log'; $logHttp = Join-Path $Out 'http-proxy.log'

$procs = New-Object System.Collections.Generic.List[object]
function Start-Bg($exe, $argv, $log) {
    $p = Start-Process -FilePath $exe -ArgumentList $argv -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -WindowStyle Hidden
    $procs.Add($p); return $p
}
function Wait-Port([int]$port, [int]$seconds) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) {
        try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', $port); $c.Close(); return $true } catch { Start-Sleep -Milliseconds 300 }
    }
    return $false
}
function Count([string]$file, [string]$text) {
    # read with sharing: the proxy that writes the log still has it open
    if (-not (Test-Path $file)) { return 0 }
    try {
        $fs = [IO.File]::Open($file, 'Open', 'Read', 'ReadWrite')
        $sr = New-Object IO.StreamReader($fs); $t = $sr.ReadToEnd(); $sr.Close()
    } catch { return 0 }
    return ([regex]::Matches($t, [regex]::Escape($text))).Count
}

$results = New-Object System.Collections.Generic.List[object]
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $results.Add([pscustomobject]@{ Test = $name; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail })
    Write-Host ("  {0}  {1}{2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $(if (-not $ok -and $detail) { "  ($detail)" } else { '' }))
}

# a test client: a copy of a real program under a name of our own, so a rule can match it alone
function New-Client([string]$name, [string]$source = "$env:SystemRoot\System32\curl.exe") {
    $p = Join-Path $bin "$name.exe"; Copy-Item $source $p; return $p
}
# one request; returns the exit code, the HTTP status and the file the body went to
function Invoke-Curl([string]$exe, [string]$url, [string[]]$extra = @(), [int]$maxTime = 25, [string]$outFile = '') {
    $bodyFile = if ($outFile) { $outFile } else { Join-Path $Out ("body_{0}.bin" -f [guid]::NewGuid().ToString('N').Substring(0, 8)) }
    $a = @('-s', '-S', '-o', $bodyFile, '-w', '%{http_code}', '--max-time', "$maxTime", '--connect-timeout', '15') + $extra + @($url)
    $status = (& $exe @a 2>&1 | Out-String).Trim()
    return [pscustomobject]@{ Exit = $LASTEXITCODE; Status = $status; Body = $bodyFile }
}
function Has-Body($r, [string]$text) { (Test-Path $r.Body) -and ((Get-Content $r.Body -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($text)) }
# expect success: tries twice because the internet is not ours
function Get-Ok([string]$exe, [string]$url, [string]$needle, [string[]]$extra = @()) {
    for ($i = 0; $i -lt 2; $i++) {
        $r = Invoke-Curl $exe $url $extra
        if ($r.Exit -eq 0 -and $r.Status -match '^[23]' -and (Has-Body $r $needle)) { return $r }
        Start-Sleep -Seconds 2
    }
    return $r
}

try {
    # ---- proxies
    Write-Host "`n=== starting proxies" -ForegroundColor Cyan
    Start-Bg $node @($nexusJs, '--port', "$PORT_OPEN", '--verbose') $logOpen | Out-Null
    Start-Bg $node @($nexusJs, '--port', "$PORT_AUTH", '--username', 'pbuser', '--password', 'pbpass123', '--verbose') $logAuth | Out-Null
    Start-Bg $python @((Join-Path $PSScriptRoot 'http_proxy.py'), '--port', "$PORT_HTTP", '--log', $logHttp) "$Out\http-proxy.out" | Out-Null
    foreach ($p in $PORT_OPEN, $PORT_AUTH, $PORT_HTTP) {
        if (-not (Wait-Port $p 20)) { Write-Host "proxy on port $p did not start" -ForegroundColor Red; exit 2 }
    }

    # ---- clients and the profile
    $names = 'socks', 'http', 'auth', 'badauth', 'direct', 'block', 'domain', 'cidr', 'cidr2', 'dl', 'dual'
    foreach ($n in $names) { New-Client "pbe_$n" | Out-Null }
    $udpClient = New-Client 'pbe_udp' "$env:SystemRoot\System32\nslookup.exe"
    $exe = @{}; foreach ($n in $names) { $exe[$n] = Join-Path $bin "pbe_$n.exe" }

    # example.com's real address for the CIDR scenarios
    $ip = ([Net.Dns]::GetHostAddresses('example.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).ToString()
    $octets = $ip.Split('.')
    $cidr = "$($octets[0]).$($octets[1]).0.0/16"
    Write-Host "example.com = $ip  (CIDR rule $cidr)"

    $cfgs = @(
        @{ Id = 1; Name = 'nexus-open';    Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_OPEN"; Username = '';       Password = '';            SendDomainToProxy = $true },
        @{ Id = 2; Name = 'nexus-auth';    Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_AUTH"; Username = 'pbuser'; Password = 'pbpass123';   SendDomainToProxy = $true },
        @{ Id = 3; Name = 'nexus-badauth'; Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_AUTH"; Username = 'pbuser'; Password = 'not-the-one'; SendDomainToProxy = $true },
        @{ Id = 4; Name = 'http';          Type = 'HTTP';   Host = '127.0.0.1'; Port = "$PORT_HTTP"; Username = '';       Password = '';            SendDomainToProxy = $true }
    )
    function Rule($proc, $hosts, $domains, $ports, $proto, $action, $cfg) {
        @{ Name = $proc; ProcessName = $proc; TargetHosts = $hosts; TargetPorts = $ports; TargetDomains = $domains; Protocol = $proto
           Action = $action; IsEnabled = $true; LocalhostViaProxy = $false; ProxyConfigId = $cfg }
    }
    $rules = @(
        (Rule 'pbe_socks.exe'   '*' '*' '*' 'TCP'  'PROXY'  1),
        (Rule 'pbe_http.exe'    '*' '*' '*' 'TCP'  'PROXY'  4),
        (Rule 'pbe_auth.exe'    '*' '*' '*' 'TCP'  'PROXY'  2),
        (Rule 'pbe_badauth.exe' '*' '*' '*' 'TCP'  'PROXY'  3),
        (Rule 'pbe_direct.exe'  '*' '*' '*' 'TCP'  'DIRECT' 0),
        (Rule 'pbe_block.exe'   '*' '*' '*' 'TCP'  'BLOCK'  0),
        (Rule 'pbe_domain.exe'  '*' 'example.com' '*' 'TCP' 'PROXY' 1),
        (Rule 'pbe_cidr.exe'    $cidr '*' '*' 'TCP' 'PROXY' 1),
        (Rule 'pbe_cidr2.exe'   '203.0.113.0/24' '*' '*' 'TCP' 'PROXY' 1),
        (Rule 'pbe_dl.exe'      '*' '*' '*' 'TCP'  'PROXY'  1),
        (Rule 'pbe_udp.exe'     '*' '*' '53' 'UDP' 'PROXY'  1),
        # the "IPv4-only proxy" recipe: IPv6 is blocked for this program, everything else goes through the proxy
        (Rule 'pbe_dual.exe'    '::/0' '*' '*' 'BOTH' 'BLOCK' 0),
        (Rule 'pbe_dual.exe'    '*' '*' '*' 'BOTH' 'PROXY' 1)
    )
    $profile = Join-Path $Out 'e2e.pbprofile'
    (@{ Version = '1.0'; IsTrafficLoggingEnabled = $true; ProxyConfigs = $cfgs; ProxyRules = $rules } | ConvertTo-Json -Depth 6) |
        Set-Content -Path $profile -Encoding UTF8

    # ---- the real engine
    Write-Host "`n=== starting ProxyBridge (real engine, real driver)" -ForegroundColor Cyan
    $cliLog = Join-Path $Out 'cli.log'
    $cli = Start-Process -FilePath (Join-Path $PbDir 'ProxyBridge_CLI.exe') -ArgumentList @('--profile', $profile, '--verbose', '3') `
        -RedirectStandardOutput $cliLog -RedirectStandardError "$cliLog.err" -PassThru -WindowStyle Hidden
    $procs.Add($cli)
    $up = Wait-Port 34010 40            # the relay listens as soon as the engine runs
    if (-not $up -or $cli.HasExited) {
        Write-Host "The engine did not start (driver blocked on this machine?). The CLI said:" -ForegroundColor Red
        Start-Sleep -Seconds 1
        if (Test-Path "$cliLog.err") { Get-Content "$cliLog.err" -Tail 20 }
        if (Test-Path $cliLog) { Get-Content $cliLog -Tail 20 }
        exit 2
    }
    Start-Sleep -Seconds 2
    Write-Host "engine is running"

    # ---- scenarios
    Write-Host "`n=== TCP through a real SOCKS5 proxy" -ForegroundColor Cyan
    $b = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.socks 'http://example.com/' 'Example Domain'
    Check 'SOCKS5: the page comes back through the proxy' ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain')) "exit $($r.Exit) status $($r.Status)"
    Check 'SOCKS5: the proxy saw the connection' ((Count $logOpen '[CONNECT]') -gt $b) 'no [CONNECT] line in the Nexus log'

    Write-Host "`n=== HTTPS download through the proxy, with a checksum" -ForegroundColor Cyan
    $b = Count $logOpen '[CONNECT]'
    $zip = Join-Path $Out 'windivert.zip'
    $r = $null
    for ($i = 0; $i -lt 2; $i++) {
        $r = Invoke-Curl $exe.dl 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' @('-L') 60 $zip
        if ($r.Exit -eq 0 -and (Test-Path $zip)) { break }
        Start-Sleep -Seconds 3
    }
    $hash = if (Test-Path $zip) { (Get-FileHash $zip -Algorithm SHA256).Hash } else { '' }
    Check 'HTTPS download is byte-for-byte correct through the relay' ($hash -eq '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15') "exit $($r.Exit) sha256 $hash"
    Check 'HTTPS download went through the proxy' ((Count $logOpen '[CONNECT]') -gt $b)

    Write-Host "`n=== HTTP proxy" -ForegroundColor Cyan
    $b = Count $logHttp '[CONNECT]'
    $r = Get-Ok $exe.http 'http://example.com/' 'Example Domain'
    Check 'HTTP proxy: the page comes back' ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain')) "exit $($r.Exit) status $($r.Status)"
    Check 'HTTP proxy: the proxy saw the CONNECT' ((Count $logHttp '[CONNECT]') -gt $b)

    Write-Host "`n=== proxy authentication" -ForegroundColor Cyan
    $b = Count $logAuth '[CONNECT]'
    $r = Get-Ok $exe.auth 'http://example.com/' 'Example Domain'
    Check 'SOCKS5 with the right password works' ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain') -and (Count $logAuth '[CONNECT]') -gt $b) "exit $($r.Exit)"
    $b = Count $logAuth '[CONNECT]'
    $r = Invoke-Curl $exe.badauth 'http://example.com/' @() 12
    Check 'SOCKS5 with the wrong password does not get through' ($r.Exit -ne 0 -and -not (Has-Body $r 'Example Domain') -and (Count $logAuth '[CONNECT]') -eq $b) "exit $($r.Exit) status $($r.Status)"

    Write-Host "`n=== Direct and Block" -ForegroundColor Cyan
    $bo = Count $logOpen '[CONNECT]'; $bh = Count $logHttp '[CONNECT]'; $ba = Count $logAuth '[CONNECT]'
    $r = Get-Ok $exe.direct 'http://example.com/' 'Example Domain'
    Check 'Direct: works without any proxy' ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain')) "exit $($r.Exit)"
    $r = Invoke-Curl $exe.block 'http://example.com/' @() 10
    Check 'Block: the connection fails' ($r.Exit -ne 0 -and -not (Has-Body $r 'Example Domain')) "exit $($r.Exit) status $($r.Status)"
    Check 'Direct and Block never touched a proxy' ((Count $logOpen '[CONNECT]') -eq $bo -and (Count $logHttp '[CONNECT]') -eq $bh -and (Count $logAuth '[CONNECT]') -eq $ba)

    Write-Host "`n=== domain rule (needs the DNS answer to be seen)" -ForegroundColor Cyan
    ipconfig /flushdns | Out-Null
    $b = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.domain 'http://example.com/' 'Example Domain'
    Check 'Domain rule: example.com goes through the proxy' ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain') -and (Count $logOpen '[CONNECT]') -gt $b) "exit $($r.Exit)"
    ipconfig /flushdns | Out-Null
    $b = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.domain 'http://example.org/' 'Example Domain'
    Check 'Domain rule: another domain stays direct' ($r.Exit -eq 0 -and (Count $logOpen '[CONNECT]') -eq $b) "exit $($r.Exit)"

    Write-Host "`n=== IPv4 CIDR rule" -ForegroundColor Cyan
    $b = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.cidr "http://$ip/" 'Example Domain' @('-H', 'Host: example.com')
    Check "CIDR $cidr matches and is proxied" ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain') -and (Count $logOpen '[CONNECT]') -gt $b) "exit $($r.Exit)"
    $b = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.cidr2 "http://$ip/" 'Example Domain' @('-H', 'Host: example.com')
    Check 'CIDR 203.0.113.0/24 does not match and stays direct' ($r.Exit -eq 0 -and (Count $logOpen '[CONNECT]') -eq $b) "exit $($r.Exit)"

    Write-Host "`n=== UDP through the proxy (SOCKS5 UDP ASSOCIATE)" -ForegroundColor Cyan
    $b = Count $logOpen '[UDP]'
    $o = ''
    for ($i = 0; $i -lt 2; $i++) {
        $o = (& $udpClient 'example.com' '1.1.1.1' 2>&1 | Out-String)
        if ($o -match 'Name:\s+example\.com' -and $o -notmatch 'timed out') { break }
        Start-Sleep -Seconds 2
    }
    # nslookup prints "Server / Address" for the resolver even when the query timed out: only an answer section counts
    Check 'UDP: a DNS answer comes back' ($o -match 'Name:\s+example\.com' -and $o -notmatch 'timed out') ($o.Trim() -replace '\s+', ' ')
    Check 'UDP: the proxy relayed the datagrams' ((Count $logOpen '[UDP]') -gt $b) 'no [UDP] line in the Nexus log'

    Write-Host "`n=== IPv4-only proxy recipe (IPv6 blocked for the program, rest proxied)" -ForegroundColor Cyan
    $b = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.dual 'https://www.google.com/robots.txt' 'User-agent'
    Check 'The block-IPv6 recipe still reaches a dual-stack site through the proxy' ($r.Exit -eq 0 -and (Has-Body $r 'User-agent') -and (Count $logOpen '[CONNECT]') -gt $b) "exit $($r.Exit) status $($r.Status)"
}
finally {
    # ---- stop everything; the driver is released when the CLI process ends
    foreach ($p in $procs) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch { } }
    Start-Sleep -Seconds 1
}

Write-Host "`n================ summary ================" -ForegroundColor Cyan
$results | Format-Table Test, Result -AutoSize | Out-String | Write-Host
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' })
if (Test-Path $cliLog) { Write-Host "--- last lines of the CLI output ---"; Get-Content $cliLog -Tail 15 }
if ($failed.Count) { Write-Host "$($failed.Count) of $($results.Count) checks failed" -ForegroundColor Red; exit 1 }
Write-Host "All $($results.Count) checks passed" -ForegroundColor Green
exit 0
