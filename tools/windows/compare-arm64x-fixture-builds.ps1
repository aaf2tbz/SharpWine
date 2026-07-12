# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ManifestA,
    [Parameter(Mandatory = $true)][string]$EvidenceA,
    [Parameter(Mandatory = $true)][string]$ManifestB,
    [Parameter(Mandatory = $true)][string]$EvidenceB,
    [Parameter(Mandatory = $true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Arm64xFixtureManifest.psm1') -Force
function Fail([string]$Message) { throw "ARM64X fixture comparison: $Message" }
function Canonical($Value) { $Value | ConvertTo-Json -Depth 30 -Compress }
function Exact($Object, [string[]]$Names, [string]$Context) {
    if ($null -eq $Object) { Fail "$Context is absent" }
    $actual = @($Object.PSObject.Properties.Name)
    foreach ($name in $Names) { if ($actual -cnotcontains $name) { Fail "$Context lacks $name" } }
    foreach ($name in $actual) { if ($Names -cnotcontains $name) { Fail "$Context contains unknown $name" } }
}
function Read-Evidence([string]$Path, [string]$ManifestPath, $Manifest) {
    try { $value = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -ErrorAction Stop }
    catch { Fail "invalid inspection evidence '$Path': $($_.Exception.Message)" }
    $names = @($value.PSObject.Properties.Name)
    foreach ($required in @('schemaVersion', 'distribution', 'manifestSha256', 'dllSha256', 'parser')) { if ($names -cnotcontains $required) { Fail "inspection evidence lacks $required" } }
    foreach ($name in $names) { if (@('schemaVersion', 'distribution', 'manifestSha256', 'dllSha256', 'parser') -cnotcontains $name) { Fail "inspection evidence contains unknown $name" } }
    if ($value.schemaVersion -ne 1 -or $value.distribution -cne 'build-tree-only') { Fail 'inspection evidence contract is invalid' }
    $manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ManifestPath).Hash.ToLowerInvariant()
    if ($value.manifestSha256 -cne $manifestHash -or $value.dllSha256 -cne $Manifest.outputs.dll.sha256) { Fail 'inspection evidence does not bind to its manifest and DLL' }
    if ($null -eq $value.parser) { Fail 'inspection evidence has no parser result' }
    Exact $value.parser @('schemaVersion', 'machine', 'sectionCount', 'imageBase', 'imageSize', 'entryPointRva', 'loadConfig', 'chpeMetadata', 'counts', 'codeRanges', 'entryRanges', 'redirections') 'parser evidence'
    Exact $value.parser.loadConfig @('rva', 'size', 'fileOffset') 'parser loadConfig'
    Exact $value.parser.chpeMetadata @('rva', 'version', 'minimumSize', 'fileOffset') 'parser chpeMetadata'
    Exact $value.parser.counts @('codeRanges', 'entryRanges', 'redirections') 'parser counts'
    foreach ($range in @($value.parser.codeRanges)) { Exact $range @('startRva', 'endRva', 'isa', 'startOffset', 'endByteOffset') 'parser code range' }
    foreach ($range in @($value.parser.entryRanges)) { Exact $range @('startRva', 'endRva', 'entryPointRva', 'startOffset', 'endByteOffset', 'entryPointOffset') 'parser entry range' }
    foreach ($record in @($value.parser.redirections)) { Exact $record @('sourceRva', 'destinationRva', 'sourceOffset', 'destinationOffset') 'parser redirection' }
    if ($value.parser.schemaVersion -ne 1 -or $value.parser.machine -ne 0xaa64) { Fail 'parser evidence contract or metadata-classified ARM64 machine is invalid' }
    if ($value.parser.loadConfig.rva -le 0 -or $value.parser.chpeMetadata.rva -le 0) { Fail 'parser evidence lacks required metadata mappings' }
    if ($value.parser.counts.codeRanges -ne @($value.parser.codeRanges).Count -or $value.parser.counts.entryRanges -ne @($value.parser.entryRanges).Count -or $value.parser.counts.redirections -ne @($value.parser.redirections).Count) { Fail 'parser evidence record counts are invalid' }
    $classes = @($value.parser.codeRanges | ForEach-Object { $_.isa })
    foreach ($required in @('arm64', 'arm64ec', 'x64')) { if ($classes -cnotcontains $required) { Fail "parser evidence lacks $required" } }
    return $value
}

if (Test-Path -LiteralPath $OutputPath) { Fail 'comparison output path must be initially absent' }
$a = Test-Arm64xBuildManifest $ManifestA
$b = Test-Arm64xBuildManifest $ManifestB
$ea = Read-Evidence $EvidenceA $ManifestA $a
$eb = Read-Evidence $EvidenceB $ManifestB $b
if ($a.outputs.host.sha256 -cne $b.outputs.host.sha256) {
    $hostA = Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath($ManifestA))) $a.outputs.host.path
    $hostB = Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath($ManifestB))) $b.outputs.host.path
    $bytesA = [IO.File]::ReadAllBytes($hostA)
    $bytesB = [IO.File]::ReadAllBytes($hostB)
    $differences = [Collections.Generic.List[string]]::new()
    $limit = [Math]::Min($bytesA.Length, $bytesB.Length)
    for ($index = 0; $index -lt $limit -and $differences.Count -lt 32; ++$index) {
        if ($bytesA[$index] -ne $bytesB[$index]) {
            $differences.Add(('{0:x8}:{1:x2}/{2:x2}' -f $index, $bytesA[$index], $bytesB[$index]))
        }
    }
    Fail "normalized hostSha256 differs between clean builds; sizes=$($bytesA.Length)/$($bytesB.Length); firstBytes=$($differences -join ',')"
}
$comparisons = [ordered]@{
    producerLock = @($a.producerLock, $b.producerLock)
    source = @((Canonical $a.source), (Canonical $b.source))
    dllSha256 = @($a.outputs.dll.sha256, $b.outputs.dll.sha256)
    hostSha256 = @($a.outputs.host.sha256, $b.outputs.host.sha256)
    outputs = @((Canonical $a.outputs), (Canonical $b.outputs))
    parser = @((Canonical $ea.parser), (Canonical $eb.parser))
}
foreach ($name in $comparisons.Keys) {
    if ($comparisons[$name][0] -cne $comparisons[$name][1]) { Fail "normalized $name differs between clean builds" }
}
$result = [ordered]@{
    schemaVersion = 1
    distribution = 'build-tree-only'
    equal = $true
    producerLock = $a.producerLock
    source = $a.source
    outputs = $a.outputs
    parser = $ea.parser
}
$parent = Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent | Out-Null }
$temp = Join-Path $parent ('.arm64x-comparison-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    $result | ConvertTo-Json -Depth 30 -Compress | Set-Content -Encoding utf8 -LiteralPath $temp
    Move-Item -LiteralPath $temp -Destination $OutputPath -Force
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
}
Write-Output $OutputPath
