# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ManifestPath,
    [Parameter(Mandatory = $true)][string]$Inspector,
    [Parameter(Mandatory = $true)][string]$EvidencePath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Arm64xFixtureManifest.psm1') -Force
function Fail([string]$Message) { throw "ARM64X fixture inspection: $Message" }
function Exact($Object, [string[]]$Names, [string]$Context) {
    if ($null -eq $Object) { Fail "$Context is absent" }
    $actual = @($Object.PSObject.Properties.Name)
    foreach ($name in $Names) { if ($actual -cnotcontains $name) { Fail "$Context is missing '$name'" } }
    foreach ($name in $actual) { if ($Names -cnotcontains $name) { Fail "$Context contains unknown '$name'" } }
}
function Natural($Value, [string]$Context) {
    if ($Value -isnot [ValueType] -or [decimal]$Value -lt 0 -or [decimal]$Value % 1 -ne 0) { Fail "$Context is not a natural number" }
}

if (Test-Path -LiteralPath $EvidencePath) { Fail 'evidence path must be initially absent' }
$manifestDirectory = [IO.Path]::GetFullPath((Split-Path -Parent $ManifestPath)).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$evidenceFullPath = [IO.Path]::GetFullPath($EvidencePath)
if (-not $evidenceFullPath.StartsWith($manifestDirectory + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { Fail 'evidence must remain beneath the fixture build directory' }
$manifest = Test-Arm64xBuildManifest $ManifestPath
$dll = Resolve-Arm64xManifestArtifact $ManifestPath $manifest.outputs.dll.path
if (-not (Test-Path -LiteralPath $Inspector -PathType Leaf)) { Fail 'inspector executable is missing' }
$raw = & $Inspector $dll | Out-String
if ($LASTEXITCODE -ne 0) { Fail "repository inspector exited with $LASTEXITCODE" }
try { $parser = $raw | ConvertFrom-Json -ErrorAction Stop }
catch { Fail "repository inspector returned invalid JSON: $($_.Exception.Message)" }
Exact $parser @('schemaVersion', 'machine', 'sectionCount', 'imageBase', 'imageSize', 'entryPointRva', 'loadConfig', 'chpeMetadata', 'counts', 'codeRanges', 'entryRanges', 'redirections') 'parser result'
if ($parser.schemaVersion -ne 1) { Fail 'parser result schemaVersion is not 1' }
if ($parser.machine -ne 0xaa64) { Fail 'linked DLL is not an ARM64 image with checked CHPE metadata' }
foreach ($field in @('sectionCount', 'imageBase', 'imageSize', 'entryPointRva')) { Natural $parser.$field "parser result $field" }
Exact $parser.loadConfig @('rva', 'size', 'fileOffset') 'loadConfig'
Exact $parser.chpeMetadata @('rva', 'version', 'minimumSize', 'fileOffset') 'chpeMetadata'
if ($parser.loadConfig.rva -le 0 -or $parser.loadConfig.size -le 0) { Fail 'load-config mapping is incomplete' }
if ($parser.chpeMetadata.rva -le 0 -or $parser.chpeMetadata.minimumSize -notin @(80, 92)) { Fail 'CHPE metadata mapping is incomplete' }
foreach ($record in @($parser.loadConfig, $parser.chpeMetadata)) {
    foreach ($property in $record.PSObject.Properties.Name) { Natural $record.$property "mapped $property" }
}
Exact $parser.counts @('codeRanges', 'entryRanges', 'redirections') 'counts'
if ($parser.counts.codeRanges -ne @($parser.codeRanges).Count -or $parser.counts.entryRanges -ne @($parser.entryRanges).Count -or $parser.counts.redirections -ne @($parser.redirections).Count) { Fail 'record counts do not match arrays' }
$classes = @{}
foreach ($range in @($parser.codeRanges)) {
    Exact $range @('startRva', 'endRva', 'isa', 'startOffset', 'endByteOffset') 'code range'
    foreach ($field in @('startRva', 'endRva', 'startOffset', 'endByteOffset')) { Natural $range.$field "code range $field" }
    if ($range.endRva -le $range.startRva) { Fail 'code range is empty or reversed' }
    $classes[$range.isa] = $true
}
foreach ($required in @('arm64', 'arm64ec', 'x64')) { if (-not $classes.ContainsKey($required)) { Fail "CHPE code map lacks $required" } }
foreach ($range in @($parser.entryRanges)) {
    Exact $range @('startRva', 'endRva', 'entryPointRva', 'startOffset', 'endByteOffset', 'entryPointOffset') 'entry range'
    foreach ($field in @('startRva', 'endRva', 'entryPointRva', 'startOffset', 'endByteOffset')) { Natural $range.$field "entry range $field" }
    if ($range.entryPointRva -ne 0) { Natural $range.entryPointOffset 'entry point offset' }
}
foreach ($record in @($parser.redirections)) {
    Exact $record @('sourceRva', 'destinationRva', 'sourceOffset', 'destinationOffset') 'redirection'
    foreach ($field in $record.PSObject.Properties.Name) { Natural $record.$field "redirection $field" }
}
$evidence = [ordered]@{
    schemaVersion = 1
    distribution = 'build-tree-only'
    manifestSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ManifestPath).Hash.ToLowerInvariant()
    dllSha256 = $manifest.outputs.dll.sha256
    parser = $parser
}
$parent = Split-Path -Parent ([IO.Path]::GetFullPath($EvidencePath))
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent | Out-Null }
$temp = Join-Path $parent ('.arm64x-inspection-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    $evidence | ConvertTo-Json -Depth 20 -Compress | Set-Content -Encoding utf8 -LiteralPath $temp
    Move-Item -LiteralPath $temp -Destination $EvidencePath -Force
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
}
Write-Output $EvidencePath
