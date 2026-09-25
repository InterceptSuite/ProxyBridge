param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedManifestHash,
    [Parameter(Mandatory=$true)][uint32]$Protocol,
    [Parameter(Mandatory=$true)][uint32]$DriverVersion,
    [Parameter(Mandatory=$true)][version]$AppVersion
)
# Read-only build-time identity check. This is NOT signature validation or the
# native helper's path/handle protection and must not authorize installation.
$ErrorActionPreference = 'Stop'
if (!$Protocol -or !$DriverVersion -or $AppVersion.Build -lt 0 -or $AppVersion.Revision -lt 0) {
    throw 'Explicit protocol, driver version and four-part app version are required.'
}
$root = (Resolve-Path -LiteralPath $Directory).ProviderPath
$names = @('ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe',
           'driver\ProxyBridgeDrv.inf','driver\ProxyBridgeDrv.cat','driver\ProxyBridgeDrv.sys')
$bytes = [IO.File]::ReadAllBytes((Join-Path $root 'payload.manifest'))
if ($bytes.Length -ne 260) { throw 'Invalid manifest length.' }
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $actual = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')
    if ($actual -ne $ExpectedManifestHash) { throw 'Manifest SHA256 mismatch.' }
    $memory = [IO.MemoryStream]::new($bytes, $false)
    $reader = [IO.BinaryReader]::new($memory)
    try {
        $expected = @([uint32]0x314d4250,[uint32]260,[uint32]1,$Protocol,$DriverVersion,
            [uint32]$AppVersion.Major,[uint32]$AppVersion.Minor,[uint32]$AppVersion.Build,[uint32]$AppVersion.Revision)
        for ($i = 0; $i -lt $expected.Count; ++$i) {
            if ($reader.ReadUInt32() -ne $expected[$i]) { throw "Manifest metadata mismatch at field $i." }
        }
        foreach ($name in $names) {
            $expectedFileHash = [BitConverter]::ToString($reader.ReadBytes(32)).Replace('-','')
            $actualFileHash = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash
            if ($actualFileHash -ne $expectedFileHash) { throw "Payload SHA256 mismatch: $name" }
        }
    } finally { $reader.Dispose(); $memory.Dispose() }
} finally { $sha.Dispose() }
[pscustomobject]@{ Directory=$root; ManifestHash=$actual; FilesVerified=$names.Count; IdentityVerified=$true }
