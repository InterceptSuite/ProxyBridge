param([string]$Configuration,[string]$Kind,[string]$Artifact)
$ErrorActionPreference='Stop'
$config=Get-Content -LiteralPath $Configuration -Raw | ConvertFrom-Json
if($config.FailUninstaller -and $Kind -eq 'Uninstaller'){throw 'Injected finalizer failure.'}
[IO.File]::Copy($Artifact,(Join-Path $config.Output ($Kind+'.captured.exe')),$false)
$Kind | Add-Content -LiteralPath (Join-Path $config.Output 'order.txt')
# This observer never signs or executes captured executables.
