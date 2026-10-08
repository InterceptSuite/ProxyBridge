# Sign an offline PnP package; never modify an installed service or DriverStore.
param(
    [string]$DriverDirectory = (Join-Path $PSScriptRoot 'driver'),
    [switch]$Trust
)
$ErrorActionPreference = 'Stop'
$DriverDirectory = (Resolve-Path -LiteralPath $DriverDirectory).Path
foreach ($name in @('ProxyBridgeDrv.inf', 'ProxyBridgeDrv.sys')) {
    if (-not (Test-Path -LiteralPath (Join-Path $DriverDirectory $name))) {
        throw "Missing package file: $name"
    }
}
$subject = 'CN=ProxyBridge Test Signing'
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date)
} | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject `
        -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') -NotAfter (Get-Date).AddYears(5)
}
$bin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
$signTool = Get-ChildItem "$bin\*\x64\signtool.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
$inf2cat = Get-ChildItem "$bin\*\x86\Inf2Cat.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $signTool -or -not $inf2cat) { throw 'Install the matching Windows SDK/WDK signing tools.' }
& $signTool sign /fd SHA256 /sha1 $cert.Thumbprint (Join-Path $DriverDirectory 'ProxyBridgeDrv.sys')
if ($LASTEXITCODE -ne 0) { throw 'Driver signing failed.' }
# Changing the SYS invalidates its old catalog. Regenerate it before signing.
& $inf2cat "/driver:$DriverDirectory" /os:10_VB_X64,10_CO_X64,10_NI_X64,10_GE_X64
if ($LASTEXITCODE -ne 0) { throw 'Driver catalog generation failed.' }
& $signTool sign /fd SHA256 /sha1 $cert.Thumbprint (Join-Path $DriverDirectory 'ProxyBridgeDrv.cat')
if ($LASTEXITCODE -ne 0) { throw 'Driver catalog signing failed.' }
if ($Trust) {
    # Explicit lab-only action; requires elevation. Test-signing mode is separate.
    $certificateFile = Join-Path $env:TEMP ([guid]::NewGuid().ToString() + '.cer')
    try {
        Export-Certificate -Cert $cert -FilePath $certificateFile | Out-Null
        Import-Certificate -FilePath $certificateFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $certificateFile -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    } finally { Remove-Item -LiteralPath $certificateFile -Force -ErrorAction SilentlyContinue }
}
