param(
    [Parameter(Mandatory=$true)][string]$DvlTool,
    [Parameter(Mandatory=$true)][string]$Sarif,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [version]$MinimumRuleSetVersion = '1.2.0.0',
    # Explicit route documented by Microsoft for May-2026 HLK / Windows 11 25H2.
    # This prepares evidence; it cannot apply or approve the controller waiver.
    [switch]$Prepare25H2Waiver320241
)
$ErrorActionPreference = 'Stop'
$tool = (Resolve-Path -LiteralPath $DvlTool).ProviderPath
$toolVersion = (Get-Item -LiteralPath $tool).VersionInfo.FileVersion
if ($Prepare25H2Waiver320241 -and $toolVersion -ne '10.0.28000.1761') {
    throw 'The documented 25H2 waiver route requires DVL generator 10.0.28000.1761.'
}
$inputFile = (Resolve-Path -LiteralPath $Sarif).ProviderPath
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Output directory must be new.' }
New-Item -ItemType Directory -Path $output | Out-Null
$copy = Join-Path $output 'ProxyBridgeDrv-CodeQL.sarif'
[IO.File]::Copy($inputFile, $copy, $false)
$inputHash = (Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash
if ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ne $inputHash) {
    throw 'SARIF changed during copy.'
}
Push-Location $output
try {
    $log = & $tool /manualCreate ProxyBridgeDrv X64 /sarifPath $output 2>&1
    $code = $LASTEXITCODE
    $log | Set-Content -LiteralPath (Join-Path $output 'generation.log') -Encoding UTF8
    if ($code -ne 0) { throw "DVL generator failed ($code). See generation.log." }
} finally { Pop-Location }
$xmlPath = Join-Path $output 'ProxyBridgeDrv.DVL.XML'
[xml]$xml = Get-Content -LiteralPath $xmlPath -Raw
$ruleSetText = $xml.Data.GetAttribute('ruleSetVersion')
$ruleSet = $null
$compatible = [version]::TryParse($ruleSetText, [ref]$ruleSet) -and $ruleSet -ge $MinimumRuleSetVersion
$blocking = @($xml.Data.AssessmentScore | Where-Object {
    $_.ScoreUnit -match '^SEMMLE_(MUSTFIX_(FAILED|SKIPPED)|MUSTRUN_SKIPPED)$'
} | ForEach-Object {
    [pscustomobject]@{Name=$_.ScoreName; Count=$_.ScoreValue; Status=$_.ScoreUnit}
})
$review = @($xml.Data.AssessmentScore | Where-Object {
    $_.ScoreUnit -match '^SEMMLE_(MUSTRUN|RECOMMENDED)_FAILED$'
} | ForEach-Object {
    [pscustomobject]@{Name=$_.ScoreName; Count=$_.ScoreValue; Status=$_.ScoreUnit}
})
$waiverRoute = $Prepare25H2Waiver320241 -and $xml.Data.GetAttribute('version') -eq '1.1.0.0' -and !$ruleSetText
$report = [pscustomobject]@{
    Generator=$tool; GeneratorVersion=$toolVersion
    GeneratorSHA256=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash
    SourceSarif=$inputFile; SarifSHA256=$inputHash
    Dvl=$xmlPath; DvlSHA256=(Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash
    XmlVersion=$xml.Data.GetAttribute('version'); RuleSetVersion=$ruleSetText
    MinimumRuleSetVersion=$MinimumRuleSetVersion.ToString(); RuleSetCompatible=$compatible
    BlockingScores=$blocking
    ReviewScores=$review
    WaiverReference=if ($waiverRoute) {'320241'} else {$null}
    ControllerWaiverVerified=$false
    # These are diagnostic gates, not an HLK pass or proof of SARIF/source freshness.
    GeneratedEvidenceChecksPassed=($compatible -and $blocking.Count -eq 0)
    HlkAcceptanceVerified=$false
}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'generation.json') -Encoding UTF8
if (!$compatible -and !$waiverRoute) { throw 'DVL ruleset is missing or below the required version. See generation.json.' }
if ($blocking.Count) { throw 'DVL contains required queries failed/skipped. See generation.json; XML was not edited.' }
if ($waiverRoute) { Write-Warning '25H2 evidence prepared; waiver #320241 must still be confirmed/applied on the affected HLK controller.' }
$report
