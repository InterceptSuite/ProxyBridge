param([Parameter(Mandatory=$true)][string]$Results)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Results){throw 'Fresh results directory required.'}
New-Item -ItemType Directory -Path $Results | Out-Null
$scripts=Split-Path $PSScriptRoot -Parent
$payload=Join-Path $Results 'payload'
New-Item -ItemType Directory -Path (Join-Path $payload 'driver') | Out-Null
foreach($name in @('ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe',
    'driver\ProxyBridgeDrv.inf','driver\ProxyBridgeDrv.cat','driver\ProxyBridgeDrv.sys')){
    [IO.File]::WriteAllText((Join-Path $payload $name),'INERT SIGNING FIXTURE')
}
$launcher=Join-Path $Results 'launcher.exe';[IO.File]::WriteAllText($launcher,'INERT LAUNCHER')
$manifest=& (Join-Path $scripts 'make-payload-manifest.ps1') -Directory $payload -Protocol 4 -DriverVersion 65537 -AppVersion 1.0.0.0
$tool=Join-Path $Results 'fake-signtool.ps1'
'$global:LASTEXITCODE = $global:fixtureToolExit' | Set-Content -LiteralPath $tool
$global:fixtureToolExit=0
$global:pbPackageFixtureSigner='1111111111111111111111111111111111111111'
$global:pbPackageFixtureTimestamp=$true
function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Thumbprint=$global:pbPackageFixtureSigner};TimeStamperCertificate=if($global:pbPackageFixtureTimestamp){[pscustomobject]@{Present=$true}}else{$null}}
}
function Assert-Fails([scriptblock]$Action,[string]$Message){
    $failed=$false;try{& $Action | Out-Null}catch{$failed=$true}
    if(!$failed){throw "Expected refusal: $Message"}
}
$arguments=@{Directory=$payload;Launcher=$launcher;SignTool=$tool;ExpectedManifestHash=$manifest.Hash;
    ExpectedLauncherHash=(Get-FileHash -LiteralPath $launcher).Hash;ExpectedSignerThumbprint=$global:pbPackageFixtureSigner;
    Protocol=4;DriverVersion=65537;AppVersion='1.0.0.0'}
$verify=Join-Path $scripts 'verify-release-inputs.ps1'
$checked=& $verify @arguments
if(!$checked.HostSignaturePolicyVerified){throw 'Input validation failed with signing adapters.'}
$arguments.DriverSignaturePolicy='TestTrusted'
$checked=& $verify @arguments
if($checked.DriverSignaturePolicy -ne 'TestTrusted'){throw 'Test driver policy was not propagated.'}
$arguments.DriverSignaturePolicy='KernelPolicy'
$originalHash=$arguments.ExpectedLauncherHash;$arguments.ExpectedLauncherHash='0'*64
Assert-Fails { & $verify @arguments } 'launcher replacement'
$arguments.ExpectedLauncherHash=$originalHash
$build=Join-Path $scripts 'build-signed-package.ps1'
$buildArgs=$arguments.Clone();$buildArgs.ExpectedLauncherHash='0'*64
$buildArgs.MakeNSIS=$tool;$buildArgs.TimestampServer='https://timestamp.invalid';$buildArgs.OutputDirectory=Join-Path $Results 'rejected-package'
Assert-Fails { & $build @buildArgs } 'wrapper preflight before compilation'
if(Test-Path -LiteralPath $buildArgs.OutputDirectory){throw 'Rejected inputs created package output.'}
$released=[IO.File]::Open($launcher,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$released.Dispose()
$global:pbPackageFixtureSigner='2222222222222222222222222222222222222222'
Assert-Fails { & $verify @arguments } 'unexpected publisher'
$global:pbPackageFixtureSigner=$arguments.ExpectedSignerThumbprint
$global:fixtureToolExit=1;Assert-Fails { & $verify @arguments } 'signature policy failure';$global:fixtureToolExit=0
$output=Join-Path $Results 'package';New-Item -ItemType Directory -Path $output | Out-Null
$configuration=Join-Path $Results 'signing.json'
[pscustomobject]@{OutputDirectory=$output;SignTool=$tool;SignerThumbprint=$global:pbPackageFixtureSigner;
    TimestampServer='http://timestamp.digicert.com';ManifestHash=$manifest.Hash;LauncherHash=$originalHash} |
    ConvertTo-Json | Set-Content -LiteralPath $configuration
$generated=Join-Path $Results 'generated-uninstaller.tmp';[IO.File]::WriteAllText($generated,'INERT UNINSTALLER')
$setup=Join-Path $output 'ProxyBridge-Setup.exe';[IO.File]::WriteAllText($setup,'INERT SETUP')
$finalizer=Join-Path $scripts 'finalize-package-artifact.ps1'
Assert-Fails { & $finalizer -Configuration $configuration -Kind Installer -Artifact $setup } 'missing uninstaller proof'
$global:pbPackageFixtureTimestamp=$false
Assert-Fails { & $finalizer -Configuration $configuration -Kind Uninstaller -Artifact $generated } 'missing timestamp'
$global:pbPackageFixtureTimestamp=$true
& $finalizer -Configuration $configuration -Kind Uninstaller -Artifact $generated
Assert-Fails { & $finalizer -Configuration $configuration -Kind Uninstaller -Artifact $generated } 'duplicate finalization'
$saved=[IO.File]::ReadAllBytes((Join-Path $output 'uninstall.exe'))
[IO.File]::WriteAllText((Join-Path $output 'uninstall.exe'),'ALTERED')
Assert-Fails { & $finalizer -Configuration $configuration -Kind Installer -Artifact $setup } 'uninstaller substitution'
[IO.File]::WriteAllBytes((Join-Path $output 'uninstall.exe'),$saved)
& $finalizer -Configuration $configuration -Kind Installer -Artifact $setup
$receipt=Get-Content -LiteralPath (Join-Path $output 'Installer.json') -Raw | ConvertFrom-Json
if($receipt.SHA256 -ne (Get-FileHash -LiteralPath $setup).Hash){throw 'Final hash mismatch.'}
Write-Output 'PASS input pinning and finalization order, wrong publisher/hash/policy/timestamp, missing/tampered evidence, duplicate refusal. INERT fixtures with signing/trust adapters; no real signing or trust claim.'
