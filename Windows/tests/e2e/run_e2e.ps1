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

. (Join-Path $PSScriptRoot 'e2e_common.ps1')

$PORT_OPEN = 31080; $PORT_AUTH = 31081; $PORT_HTTP = 33128; $PORT_MID = 31082; $PORT_DEAD = 31999   # nothing listens on the last one
$logOpen = Join-Path $Out 'nexus-open.log'; $logAuth = Join-Path $Out 'nexus-auth.log'; $logHttp = Join-Path $Out 'http-proxy.log'; $logMid = Join-Path $Out 'nexus-mid.log'

try {
    # ---- proxies
    Write-Host "`n=== starting proxies" -ForegroundColor Cyan
    Start-Bg $node @($nexusJs, '--port', "$PORT_OPEN", '--verbose') $logOpen | Out-Null
    Start-Bg $node @($nexusJs, '--port', "$PORT_AUTH", '--username', 'pbuser', '--password', 'pbpass123', '--verbose') $logAuth | Out-Null
    Start-Bg $python @((Join-Path $PSScriptRoot 'http_proxy.py'), '--port', "$PORT_HTTP", '--log', $logHttp) "$Out\http-proxy.out" | Out-Null
    $nexusMid = Start-Bg $node @($nexusJs, '--port', "$PORT_MID", '--verbose') $logMid     # the one that is killed in the middle of a transfer
    foreach ($p in $PORT_OPEN, $PORT_AUTH, $PORT_HTTP, $PORT_MID) {
        if (-not (Wait-Port $p 20)) { Write-Host "proxy on port $p did not start" -ForegroundColor Red; exit 2 }
    }

    # ---- clients and the profile
    $names = 'socks', 'http', 'auth', 'badauth', 'direct', 'block', 'domain', 'cidr', 'cidr2', 'dl', 'dual',
             'wc_one', 'wc_two', 'multi_a', 'multi_b', 'case', 'ports', 'range', 'wild4', 'range4', 'order', 'order2', 'off',
             'down', 'midkill', 'stress', 'v6'
    foreach ($n in $names) { New-Client "pbe_$n" | Out-Null }
    $udpClient = New-Client 'pbe_udp' "$env:SystemRoot\System32\nslookup.exe"
    $tcpOnlyUdp = New-Client 'pbe_tcponly' "$env:SystemRoot\System32\nslookup.exe"
    # the same file name in two folders (a rule by full path must tell them apart), and a path with a space (quoted in the rule)
    foreach ($d in 'pa', 'pb', 'sp ace') { New-Item -ItemType Directory -Path (Join-Path $bin $d) | Out-Null }
    $pathA = Join-Path $bin 'pa\pbe_path.exe'; $pathB = Join-Path $bin 'pb\pbe_path.exe'; $pathQ = Join-Path $bin 'sp ace\pbe_quoted.exe'
    foreach ($f in $pathA, $pathB, $pathQ) { Copy-Item "$env:SystemRoot\System32\curl.exe" $f }
    $exe = @{}; foreach ($n in $names) { $exe[$n] = Join-Path $bin "pbe_$n.exe" }

    # example.com's real address for the CIDR scenarios
    $ip = ([Net.Dns]::GetHostAddresses('example.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).ToString()
    $octets = $ip.Split('.')
    $cidr = "$($octets[0]).$($octets[1]).0.0/16"
    $wild4 = "$($octets[0]).*.*.*"
    $range4 = "$($octets[0]).$($octets[1]).0.0-$($octets[0]).$($octets[1]).255.255"
    Write-Host "example.com = $ip  (CIDR rule $cidr, wildcard $wild4, range $range4)"
    # does this runner have IPv6 to the internet? (checked before the engine starts)
    & "$env:SystemRoot\System32\curl.exe" -6 -s -o NUL --max-time 8 http://ipv6.google.com/
    $v6Reachable = ($LASTEXITCODE -eq 0)
    Write-Host "IPv6 to the internet: $v6Reachable"

    $cfgs = @(
        @{ Id = 1; Name = 'nexus-open';    Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_OPEN"; Username = '';       Password = '';            SendDomainToProxy = $true },
        @{ Id = 2; Name = 'nexus-auth';    Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_AUTH"; Username = 'pbuser'; Password = 'pbpass123';   SendDomainToProxy = $true },
        @{ Id = 3; Name = 'nexus-badauth'; Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_AUTH"; Username = 'pbuser'; Password = 'not-the-one'; SendDomainToProxy = $true },
        @{ Id = 4; Name = 'http';          Type = 'HTTP';   Host = '127.0.0.1'; Port = "$PORT_HTTP"; Username = '';       Password = '';            SendDomainToProxy = $true },
        @{ Id = 5; Name = 'dead';          Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_DEAD"; Username = '';       Password = '';            SendDomainToProxy = $true },
        @{ Id = 6; Name = 'nexus-mid';     Type = 'SOCKS5'; Host = '127.0.0.1'; Port = "$PORT_MID";  Username = '';       Password = '';            SendDomainToProxy = $true }
    )
    function Rule($proc, $hosts, $domains, $ports, $proto, $action, $cfg, $enabled = $true) {
        @{ Name = $proc; ProcessName = $proc; TargetHosts = $hosts; TargetPorts = $ports; TargetDomains = $domains; Protocol = $proto
           Action = $action; IsEnabled = $enabled; LocalhostViaProxy = $false; ProxyConfigId = $cfg }
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
        (Rule 'pbe_dual.exe'    '*' '*' '*' 'BOTH' 'PROXY' 1),
        # which programs a rule matches
        (Rule 'pbe_wc*.exe'     '*' '*' '*' 'TCP'  'PROXY'  1),                              # wildcard
        (Rule 'pbe_multi_a.exe; pbe_multi_b.exe' '*' '*' '*' 'TCP' 'PROXY' 1),               # several programs in one rule
        (Rule 'PBE_CASE.EXE'    '*' '*' '*' 'TCP'  'PROXY'  1),                              # not case sensitive
        (Rule $pathA            '*' '*' '*' 'TCP'  'PROXY'  1),                              # one exact program, by full path
        (Rule ('"' + $pathQ + '"') '*' '*' '*' 'TCP' 'PROXY' 1),                            # a path with a space, in quotes
        # which destinations
        (Rule 'pbe_ports.exe'   '*' '*' '80' 'TCP' 'PROXY' 1),                               # one port
        (Rule 'pbe_range.exe'   '*' '*' '440-450' 'TCP' 'PROXY' 1),                          # a port range
        (Rule 'pbe_wild4.exe'   $wild4 '*' '*' 'TCP' 'PROXY' 1),                             # IPv4 wildcard
        (Rule 'pbe_range4.exe'  $range4 '*' '*' 'TCP' 'PROXY' 1),                            # IPv4 range
        (Rule 'pbe_tcponly.exe' '*' '*' '*' 'TCP'  'PROXY'  1),                              # a TCP rule must leave UDP alone
        (Rule 'pbe_v6.exe'      '2000::/3' '*' '*' 'TCP' 'PROXY' 1),                         # IPv6 CIDR (global addresses)
        # order: the first matching rule wins
        (Rule 'pbe_order.exe'   '*' '*' '*' 'TCP'  'PROXY'  1),
        (Rule 'pbe_order.exe'   '*' 'example.com' '*' 'TCP' 'DIRECT' 0),
        (Rule 'pbe_order2.exe'  '*' 'example.com' '*' 'TCP' 'DIRECT' 0),
        (Rule 'pbe_order2.exe'  '*' '*' '*' 'TCP'  'PROXY'  1),
        (Rule 'pbe_off.exe'     '*' '*' '*' 'TCP'  'PROXY'  1 $false),                       # a disabled rule does nothing
        # failures and load
        (Rule 'pbe_down.exe'    '*' '*' '*' 'TCP'  'PROXY'  5),                              # the proxy is not running
        (Rule 'pbe_midkill.exe' '*' '*' '*' 'TCP'  'PROXY'  6),                              # the proxy dies during a transfer
        (Rule 'pbe_stress.exe'  '*' '*' '*' 'TCP'  'PROXY'  1)
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
    # nslookup prints "Server / Address" for the resolver even when the query failed, and on a runner its "Name:" label
    # can come out as "(null)": only an address listed after the queried name is an answer
    $dnsAnswer = '(?s)example\.com\s+Address(es)?:\s*[0-9a-fA-F:.]+'
    $b = Count $logOpen '1.1.1.1:53'          # Nexus logs the first datagram to each new destination
    $o = ''
    for ($i = 0; $i -lt 2; $i++) {
        $o = (& $udpClient 'example.com' '1.1.1.1' 2>&1 | Out-String)
        if ($o -match $dnsAnswer) { break }
        Start-Sleep -Seconds 2
    }
    Check 'UDP: a DNS answer comes back' ($o -match $dnsAnswer) ($o.Trim() -replace '\s+', ' ')
    Check 'UDP: the proxy relayed the datagrams' ((Count $logOpen '1.1.1.1:53') -gt $b) 'Nexus never saw a datagram for 1.1.1.1:53'

    Write-Host "`n=== IPv4-only proxy recipe (IPv6 blocked for the program, rest proxied)" -ForegroundColor Cyan
    $b = Count $logOpen '[CONNECT]'
    $r = Get-Ok $exe.dual 'https://www.google.com/robots.txt' 'User-agent'
    Check 'The block-IPv6 recipe still reaches a dual-stack site through the proxy' ($r.Exit -eq 0 -and (Has-Body $r 'User-agent') -and (Count $logOpen '[CONNECT]') -gt $b) "exit $($r.Exit) status $($r.Status)"

    # ======================= which programs a rule matches =======================
    Write-Host "`n=== Applications: wildcard, several programs, case, full path, quoted path" -ForegroundColor Cyan
    function Via-Open([string]$label, [string]$client, [string]$url = 'http://example.com/', [string[]]$extra = @(), [string]$needle = 'Example Domain') {
        $before = Count $logOpen '[CONNECT]'
        $r = Get-Ok $client $url $needle $extra
        Check $label ($r.Exit -eq 0 -and (Has-Body $r $needle) -and (Count $logOpen '[CONNECT]') -gt $before) "exit $($r.Exit) status $($r.Status)"
    }
    function Direct-Open([string]$label, [string]$client, [string]$url = 'http://example.com/', [string[]]$extra = @()) {
        $before = Count $logOpen '[CONNECT]'
        $r = Get-Ok $client $url 'Example Domain' $extra
        Check $label ($r.Exit -eq 0 -and (Has-Body $r 'Example Domain') -and (Count $logOpen '[CONNECT]') -eq $before) "exit $($r.Exit) status $($r.Status)"
    }
    Via-Open 'Wildcard pbe_wc*.exe matches the first program' $exe.wc_one
    Via-Open 'Wildcard pbe_wc*.exe matches the second program' $exe.wc_two
    Via-Open 'Several programs in one rule: the first' $exe.multi_a
    Via-Open 'Several programs in one rule: the second' $exe.multi_b
    Via-Open 'Program names are not case sensitive' $exe.case
    Via-Open 'A rule by full path matches that exact program' $pathA
    Direct-Open 'A rule by full path does NOT match the same file name in another folder' $pathB
    Via-Open 'A quoted full path with a space matches' $pathQ

    # ======================= which destinations =======================
    Write-Host "`n=== ports, address wildcard, address range, protocol split" -ForegroundColor Cyan
    Via-Open    'Port rule (80): port 80 is proxied' $exe.ports 'http://example.com/'
    Direct-Open 'Port rule (80): port 443 stays direct' $exe.ports 'https://example.com/'
    Via-Open    'Port range 440-450: port 443 is proxied' $exe.range 'https://example.com/'
    Direct-Open 'Port range 440-450: port 80 stays direct' $exe.range 'http://example.com/'
    Via-Open "IPv4 wildcard ($wild4) matches" $exe.wild4 "http://$ip/" @('-H', 'Host: example.com')
    Via-Open "IPv4 range ($range4) matches" $exe.range4 "http://$ip/" @('-H', 'Host: example.com')
    $dnsAnswer = '(?s)example\.com\s+Address(es)?:\s*[0-9a-fA-F:.]+'
    $b = Count $logOpen '8.8.8.8:53'
    $o = ''
    for ($i = 0; $i -lt 2; $i++) { $o = (& $tcpOnlyUdp 'example.com' '8.8.8.8' 2>&1 | Out-String); if ($o -match $dnsAnswer) { break }; Start-Sleep -Seconds 2 }
    Check 'A TCP-only rule leaves UDP alone: the DNS query works and never reaches the proxy' ($o -match $dnsAnswer -and (Count $logOpen '8.8.8.8:53') -eq $b) ($o.Trim() -replace '\s+', ' ')
    if ($v6Reachable) {
        Via-Open 'IPv6 CIDR (2000::/3): an IPv6 destination is proxied' $exe.v6 'http://ipv6.google.com/' @('-6', '-L') 'google'
    } else { Skip 'IPv6 CIDR (2000::/3): an IPv6 destination is proxied' 'this runner has no IPv6 to the internet' }

    # ======================= rule order and switched-off rules =======================
    Write-Host "`n=== rule order, disabled rule" -ForegroundColor Cyan
    Via-Open 'Order: a broad rule above a specific one wins (first match)' $exe.order
    ipconfig /flushdns | Out-Null
    Direct-Open 'Order: a specific Direct rule above a broad Proxy rule wins for its domain' $exe.order2 'http://example.com/'
    ipconfig /flushdns | Out-Null
    Via-Open 'Order: other destinations fall through to the broad Proxy rule' $exe.order2 'http://example.org/'
    Direct-Open 'A disabled rule does nothing' $exe.off

    # ======================= failures =======================
    Write-Host "`n=== a proxy that is not running, and one that dies during a transfer" -ForegroundColor Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Curl $exe.down 'http://example.com/' @() 20
    $sw.Stop()
    Check 'Proxy not running: the request fails promptly instead of hanging' ($r.Exit -ne 0 -and $sw.Elapsed.TotalSeconds -lt 18) ("exit $($r.Exit), took {0:N1} s" -f $sw.Elapsed.TotalSeconds)
    Via-Open 'The engine keeps working after a dead proxy' $exe.socks

    $bigUrl = 'https://speed.cloudflare.com/__down?bytes=26214400'
    $midFile = Join-Path $Out 'mid.bin'
    $curlMid = Start-Process -FilePath $exe.midkill -ArgumentList @('-s', '-S', '-o', $midFile, '--limit-rate', '400k', '--max-time', '90', '--connect-timeout', '15', $bigUrl) `
        -PassThru -WindowStyle Hidden
    $t0 = Get-Date
    while ((Count $logMid '[CONNECT]') -lt 1 -and ((Get-Date) - $t0).TotalSeconds -lt 25) { Start-Sleep -Milliseconds 300 }
    $carried = (Count $logMid '[CONNECT]') -ge 1
    if ($carried) {
        Start-Sleep -Seconds 4
        Stop-Process -Id $nexusMid.Id -Force                      # the proxy dies in the middle of the transfer
        $ended = $curlMid.WaitForExit(45000)
        Check 'Proxy dies mid-transfer: the client gets an error and is not left hanging' ($ended -and $curlMid.ExitCode -ne 0) "ended $ended, exit $(if ($ended) { $curlMid.ExitCode })"
    } else { Skip 'Proxy dies mid-transfer' 'the large download did not start (no internet access to the test server?)' }
    try { if (-not $curlMid.HasExited) { Stop-Process -Id $curlMid.Id -Force } } catch { }
    Via-Open 'The engine keeps working after a proxy died mid-transfer' $exe.socks

    # ======================= load =======================
    Write-Host "`n=== load: 30 parallel HTTPS downloads and one large transfer" -ForegroundColor Cyan
    $zipUrl = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
    $zipHash = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
    $stressExe = $exe.stress
    $b = Count $logOpen '[CONNECT]'
    $okCount = (1..30 | ForEach-Object -ThrottleLimit 30 -Parallel {
        $f = Join-Path $using:Out ("par_{0}.zip" -f $_)
        & $using:stressExe -s -S -L --max-time 90 --connect-timeout 20 -o $f $using:zipUrl 2>$null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $f) -and ((Get-FileHash $f -Algorithm SHA256).Hash -eq $using:zipHash)) { 1 } else { 0 }
    } | Measure-Object -Sum).Sum
    Check '30 parallel downloads through the proxy: the files are byte-for-byte correct' ($okCount -ge 28) "$okCount of 30 correct"
    Check '30 parallel downloads all went through the proxy' ((Count $logOpen '[CONNECT]') -ge ($b + 28)) "$((Count $logOpen '[CONNECT]') - $b) new tunnels"
    $bigFile = Join-Path $Out 'big.bin'; $len = 0; $r = $null
    for ($i = 0; $i -lt 2 -and $len -ne 26214400; $i++) {
        $r = Invoke-Curl $exe.stress $bigUrl @() 120 $bigFile
        $len = if (Test-Path $bigFile) { (Get-Item $bigFile).Length } else { 0 }
    }
    Check 'A 25 MB transfer through the relay arrives complete' ($r.Exit -eq 0 -and $len -eq 26214400) "exit $($r.Exit), $len bytes"
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
