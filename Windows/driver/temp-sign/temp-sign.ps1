# Test-sign ProxyBridgeDrv.sys with a free self-signed cert (no EV cert needed).
# Run ELEVATED from the folder holding ProxyBridgeDrv.sys. Requires test-signing mode
# (bcdedit /set testsigning on + reboot).
$ErrorActionPreference = 'Stop'

# Create or reuse a self-signed code-signing cert.
$subject = 'CN=ProxyBridge Test Signing'
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
              -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
              -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') -NotAfter (Get-Date).AddYears(5)
}

# Trust it machine-wide (kernel driver load needs Root + TrustedPublisher).
$tmp = Join-Path $env:TEMP 'ProxyBridgeDrv-test.cer'
Export-Certificate -Cert $cert -FilePath $tmp -Force | Out-Null
Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\Root             | Out-Null
Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\LocalMachine\TrustedPublisher  | Out-Null
Remove-Item $tmp -Force

# Sign the .sys the service loads (if installed) and the copy in this folder.
$targets = New-Object System.Collections.Generic.HashSet[string]
$svc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ProxyBridgeDrv' -ErrorAction SilentlyContinue
if ($svc -and $svc.ImagePath) {
    $p = $svc.ImagePath -replace '^\\\?\?\\',''
    if ($p -notmatch '^[A-Za-z]:') { $p = Join-Path $env:SystemRoot $p }
    if (Test-Path $p) { [void]$targets.Add((Resolve-Path $p).Path) }
}
$here = Join-Path $PSScriptRoot 'ProxyBridgeDrv.sys'
if (Test-Path $here) { [void]$targets.Add((Resolve-Path $here).Path) }
if ($targets.Count -eq 0) { Write-Host "No ProxyBridgeDrv.sys found." -ForegroundColor Red; exit 1 }

# Stop + delete the service so the file unlocks and the next launch re-registers the signed one.
cmd /c 'sc stop ProxyBridgeDrv'   | Out-Null
cmd /c 'sc delete ProxyBridgeDrv' | Out-Null
Start-Sleep -Milliseconds 500

# On a dev box, deploy the freshly built .sys (skipped in a plain VM without the build tree).
$built = Join-Path $PSScriptRoot '..\driver\x64\Release\ProxyBridgeDrv.sys'
if (Test-Path $built) { Copy-Item $built (Join-Path $PSScriptRoot 'ProxyBridgeDrv.sys') -Force }

$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue).Source }
if (-not $signtool) { Write-Host "signtool.exe not found - install the Windows SDK/WDK." -ForegroundColor Red; exit 1 }

foreach ($t in $targets) {
    & $signtool sign /v /fd SHA256 /sha1 $cert.Thumbprint $t   # no timestamp: not needed for test-signing
    if ($LASTEXITCODE -ne 0) { Write-Host "signing FAILED: $t" -ForegroundColor Red; continue }
    Write-Host ("{0}: {1}" -f (Get-AuthenticodeSignature $t).Status, $t) -ForegroundColor Green
}

Write-Host "`nDone. Launch ProxyBridge.exe as Administrator, then: sc.exe query ProxyBridgeDrv" -ForegroundColor Yellow
