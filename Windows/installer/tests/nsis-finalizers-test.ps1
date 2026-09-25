param([Parameter(Mandatory=$true)][string]$Results,[Parameter(Mandatory=$true)][string]$MakeNSIS)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Results){throw 'Fresh results directory required.'}
New-Item -ItemType Directory -Path (Join-Path $Results 'payload\driver') | Out-Null
$payload=Join-Path $Results 'payload'
foreach($name in @('ProxyBridge.exe','ProxyBridge_CLI.exe','ProxyBridgeCore.dll','ProxyBridgeDriverSetup.exe','payload.manifest',
    'driver\ProxyBridgeDrv.inf','driver\ProxyBridgeDrv.cat','driver\ProxyBridgeDrv.sys')){
    [IO.File]::WriteAllText((Join-Path $payload $name),'INERT: NOT INSTALLABLE')
}
$launcher=Join-Path $Results 'launcher.exe';[IO.File]::WriteAllText($launcher,'INERT: NOT EXECUTABLE')
$shell=Join-Path $PSHOME 'powershell.exe';if(!(Test-Path -LiteralPath $shell)){$shell=Join-Path $PSHOME 'pwsh.exe'}
foreach($failure in @($false,$true)){
    $output=Join-Path $Results $(if($failure){'failure'}else{'success'});New-Item -ItemType Directory -Path $output | Out-Null
    $config=Join-Path $output 'config.json'
    [pscustomobject]@{Output=$output;FailUninstaller=$failure}|ConvertTo-Json|Set-Content -LiteralPath $config
    $args=@('/V2','/DTRANSACTION_REHEARSAL',"/DPAYLOAD_DIR=$payload","/DLAUNCHER_FILE=$launcher",
        ('/DMANIFEST_SHA256='+('A'*64)),"/DSETUP_OUTPUT=$output\NOT-INSTALLABLE.exe",
        "/DPACKAGE_FINALIZER=$PSScriptRoot\capture-nsis-finalizer.ps1","/DPACKAGE_SIGNING_CONFIG=$config",
        "/DPACKAGE_POWERSHELL=$shell",(Join-Path (Split-Path $PSScriptRoot -Parent) 'ProxyBridge-transaction.nsi'))
    & $MakeNSIS @args *> (Join-Path $output 'compile.log')
    if($failure){if(!$LASTEXITCODE){throw 'NSIS accepted a failed uninstaller hook.'}}
    else{
        if($LASTEXITCODE){throw 'NSIS hook compilation failed; inspect compile.log.'}
        $order=@(Get-Content -LiteralPath (Join-Path $output 'order.txt'))
        if($order.Count -ne 2 -or $order[0] -ne 'Uninstaller' -or $order[1] -ne 'Installer'){throw 'Wrong finalization order.'}
        if((Get-FileHash -LiteralPath (Join-Path $output 'Installer.captured.exe')).Hash -ne
            (Get-FileHash -LiteralPath (Join-Path $output 'NOT-INSTALLABLE.exe')).Hash){throw 'Final installer capture mismatch.'}
    }
}
Write-Output 'PASS real NSIS finalizer order, output capture and compilation refusal after uninstaller hook failure. INERT inputs; no generated executable run or signed.'
$global:LASTEXITCODE=0
