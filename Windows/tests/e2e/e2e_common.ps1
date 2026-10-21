# e2e_common.ps1 - helpers shared by run_e2e.ps1 (the engine through the CLI) and run_e2e_service.ps1 (installer, service, app).
# Dot-source it AFTER $Out (a fresh output folder) and $bin (a folder inside it) exist. It downloads the pinned Nexus Proxy,
# patches its UDP part, and defines: Start-Bg, Wait-Port, Count, Check, Skip, New-Client, Invoke-Curl, Has-Body, Get-Ok,
# plus $procs (processes to stop at the end), $results (the checks), $node and $python.

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

function Skip([string]$name, [string]$why) {
    $results.Add([pscustomobject]@{ Test = $name; Result = 'SKIP'; Detail = $why })
    Write-Host ("  SKIP  {0}  ({1})" -f $name, $why)
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

