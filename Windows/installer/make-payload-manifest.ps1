param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][uint32]$Protocol,
    [Parameter(Mandatory=$true)][uint32]$DriverVersion,
    [Parameter(Mandatory=$true)][version]$AppVersion
)
$ErrorActionPreference = 'Stop'
if (!$Protocol -or !$DriverVersion -or $AppVersion.Build -lt 0 -or $AppVersion.Revision -lt 0) {
    throw 'Explicit protocol, driver version and four-part app version are required.'
}
$root = (Resolve-Path -LiteralPath $Directory).ProviderPath
$names = @('ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe',
           'driver\ProxyBridgeDrv.inf','driver\ProxyBridgeDrv.cat','driver\ProxyBridgeDrv.sys')
$memory = [IO.MemoryStream]::new()
$writer = [IO.BinaryWriter]::new($memory)
try {
    foreach ($number in @([uint32]0x314d4250,[uint32]260,[uint32]1,$Protocol,$DriverVersion,
                          [uint32]$AppVersion.Major,[uint32]$AppVersion.Minor,[uint32]$AppVersion.Build,[uint32]$AppVersion.Revision)) {
        $writer.Write([uint32]$number)
    }
    foreach ($name in $names) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash
        for ($i = 0; $i -lt 64; $i += 2) { $writer.Write([Convert]::ToByte($hash.Substring($i,2),16)) }
    }
    $writer.Flush()
    $path = Join-Path $root 'payload.manifest'
    # Refuse to replace an existing manifest, especially after signing/release.
    $output = [IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $memory.Position = 0; $memory.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
    Get-FileHash -LiteralPath $path -Algorithm SHA256
} finally { $writer.Dispose(); $memory.Dispose() }
# Run only after all payload signing. The printed hash is build metadata, not
# an authenticated trust source until bound into a signed installer/journal.
