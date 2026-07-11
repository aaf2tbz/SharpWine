# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$TestDir)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Arm64xFixtureManifest.psm1') -Force
if (Test-Path -LiteralPath $TestDir) { throw 'manifest TestDir must be initially absent' }
New-Item -ItemType Directory -Path $TestDir | Out-Null
function Hash([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function Write-Json($Value, [string]$Name) {
    $path = Join-Path $TestDir $Name
    $Value | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 -LiteralPath $path
    return $path
}
function Clone($Value) { return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json) }
function Reject([string]$Name, [scriptblock]$Action) {
    try { & $Action | Out-Null } catch { Write-Output "rejected: $Name"; return }
    throw "malformed manifest was accepted: $Name"
}
$hash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
$tool = { [ordered]@{ version = '1'; sha256 = $hash } }
$provenance = [ordered]@{
    schemaVersion = 1; status = 'reviewed'; producer = 'producer'; documentation = @('https://example.invalid/arm64x')
    sourceLicense = 'Apache-2.0'; distribution = 'build-tree-only'; reviewEvidence = [ordered]@{
        workflowRun = 'run'; runnerImageOS = 'windows'; runnerImageVersion = '1'; nativeMachine = '0xAA64'
        visualStudioVersion = '1'; visualStudioInstallationVersion = '1'
    }
    pin = [ordered]@{
        vcToolsVersion = '1'; windowsSdkVersion = '1'; tools = [ordered]@{
            arm64 = [ordered]@{ cl = (& $tool); link = (& $tool); lib = (& $tool) }
            arm64ec = [ordered]@{
                compiler = 'shared-arm64-cl'; compilerMode = '/arm64EC'; linker = 'shared-arm64-link'
                linkerMode = '/MACHINE:ARM64EC'; cl = (& $tool); link = (& $tool); lib = (& $tool)
            }
            x64 = [ordered]@{ cl = (& $tool); link = (& $tool); lib = (& $tool) }
        }; dumpbin = (& $tool)
    }
    reviewRequirement = 'review required'
}
$provenancePath = Write-Json $provenance 'provenance.json'
Test-Arm64xProvenanceLock $provenancePath | Out-Null
Set-Content -LiteralPath (Join-Path $TestDir 'invalid.json') -Value '{'
Reject 'invalid JSON' { Test-Arm64xProvenanceLock (Join-Path $TestDir 'invalid.json') }
$duplicateJson = ($provenance | ConvertTo-Json -Depth 20 -Compress) -replace '"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'
Set-Content -LiteralPath (Join-Path $TestDir 'duplicate.json') -Value $duplicateJson
Reject 'duplicate JSON property' { Test-Arm64xProvenanceLock (Join-Path $TestDir 'duplicate.json') }
foreach ($case in @(
    @{ Name = 'wrong provenance schema'; Apply = { param($x) $x.schemaVersion = 2 } },
    @{ Name = 'string provenance schema'; Apply = { param($x) $x.schemaVersion = '1' } },
    @{ Name = 'missing reviewed status'; Apply = { param($x) $x.status = 'pending' } },
    @{ Name = 'unknown top-level property'; Apply = { param($x) $x | Add-Member noteproperty extra 1 } },
    @{ Name = 'scalar pin'; Apply = { param($x) $x.pin = 'pin' } },
    @{ Name = 'unknown pin property'; Apply = { param($x) $x.pin | Add-Member noteproperty extra 1 } },
    @{ Name = 'array tools'; Apply = { param($x) $x.pin.tools = @() } },
    @{ Name = 'unknown tools property'; Apply = { param($x) $x.pin.tools | Add-Member noteproperty extra 1 } },
    @{ Name = 'scalar target'; Apply = { param($x) $x.pin.tools.arm64 = 1 } },
    @{ Name = 'unknown target property'; Apply = { param($x) $x.pin.tools.arm64 | Add-Member noteproperty extra 1 } },
    @{ Name = 'array tool record'; Apply = { param($x) $x.pin.tools.arm64.cl = @('cl') } },
    @{ Name = 'unknown tool record property'; Apply = { param($x) $x.pin.tools.arm64.cl | Add-Member noteproperty extra 1 } },
    @{ Name = 'numeric tool version'; Apply = { param($x) $x.pin.tools.arm64.cl.version = 1 } },
    @{ Name = 'array tool version'; Apply = { param($x) $x.pin.dumpbin.version = @('1') } },
    @{ Name = 'scalar review evidence'; Apply = { param($x) $x.reviewEvidence = 1 } },
    @{ Name = 'unknown review evidence property'; Apply = { param($x) $x.reviewEvidence | Add-Member noteproperty extra 1 } },
    @{ Name = 'scalar documentation'; Apply = { param($x) $x.documentation = 'url' } },
    @{ Name = 'non-string documentation entry'; Apply = { param($x) $x.documentation = @(1) } },
    @{ Name = 'missing pin'; Apply = { param($x) $x.PSObject.Properties.Remove('pin') } },
    @{ Name = 'missing nested tool'; Apply = { param($x) $x.pin.tools.arm64.PSObject.Properties.Remove('cl') } },
    @{ Name = 'uppercase hash'; Apply = { param($x) $x.pin.dumpbin.sha256 = $hash.ToUpperInvariant() } },
    @{ Name = 'short hash'; Apply = { param($x) $x.pin.dumpbin.sha256 = 'abc' } },
    @{ Name = 'non-hex hash'; Apply = { param($x) $x.pin.dumpbin.sha256 = ('g' * 64) } }
)) {
    $copy = Clone $provenance; & $case.Apply $copy
    $path = Write-Json $copy ("bad-provenance-$($case.Name -replace ' ', '-').json")
    Reject $case.Name { Test-Arm64xProvenanceLock $path }
}

foreach ($name in @('dll.bin', 'host.bin')) { Set-Content -NoNewline -LiteralPath (Join-Path $TestDir $name) -Value $name }
$source = [ordered]@{}
foreach ($name in @('CMakeLists.txt', 'arm64x.cmake', 'fixture.c', 'fixture_x64.c', 'fixture_api.h', 'host.c', 'fixture.def')) { $source[$name] = $hash }
$build = [ordered]@{
    schemaVersion = 2; producerLock = $hash; source = $source
    outputs = [ordered]@{
        dll = [ordered]@{ type = 'dll'; path = 'dll.bin'; sha256 = (Hash (Join-Path $TestDir 'dll.bin')) }
        host = [ordered]@{ type = 'host'; path = 'host.bin'; sha256 = (Hash (Join-Path $TestDir 'host.bin')) }
    }
    distribution = 'build-tree-only'
}
$buildPath = Write-Json $build 'build.json'
Test-Arm64xBuildManifest $buildPath | Out-Null
$cases = @(
    @{ Name = 'wrong build schema'; Apply = { param($x) $x.schemaVersion = 1 } },
    @{ Name = 'string build schema'; Apply = { param($x) $x.schemaVersion = '2' } },
    @{ Name = 'fractional build schema'; Apply = { param($x) $x.schemaVersion = 2.5 } },
    @{ Name = 'unknown property'; Apply = { param($x) $x | Add-Member noteproperty extra 1 } },
    @{ Name = 'missing source'; Apply = { param($x) $x.source.PSObject.Properties.Remove('host.c') } },
    @{ Name = 'wrong distribution'; Apply = { param($x) $x.distribution = 'repository' } },
    @{ Name = 'absolute path'; Apply = { param($x) $x.outputs.dll.path = 'C:\escape.dll' } },
    @{ Name = 'parent traversal'; Apply = { param($x) $x.outputs.dll.path = '..\escape.dll' } },
    @{ Name = 'missing artifact'; Apply = { param($x) $x.outputs.dll.path = 'missing.dll' } },
    @{ Name = 'hash mismatch'; Apply = { param($x) $x.outputs.dll.sha256 = $hash } },
    @{ Name = 'substituted artifact'; Apply = { param($x) $x.outputs.dll.path = 'host.bin' } },
    @{ Name = 'output type mismatch'; Apply = { param($x) $x.outputs.dll.type = 'host' } },
    @{ Name = 'missing output'; Apply = { param($x) $x.outputs.PSObject.Properties.Remove('host') } }
)
foreach ($case in $cases) {
    $copy = Clone $build; & $case.Apply $copy
    $path = Write-Json $copy ("bad-build-$($case.Name -replace ' ', '-').json")
    Reject $case.Name { Test-Arm64xBuildManifest $path }
}

function Try-NewTestReparsePoint([string]$Path, [string]$Target, [switch]$File) {
    $types = if ($File) { @('SymbolicLink') } else { @('Junction', 'SymbolicLink') }
    foreach ($type in $types) {
        try {
            New-Item -ItemType $type -Path $Path -Target $Target -ErrorAction Stop | Out-Null
            if (((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
        } catch {
            Write-Host "reparse test setup unavailable ($type): $($_.Exception.Message)"
        }
    }
    return $false
}

$outside = Join-Path $TestDir 'reparse-target'
New-Item -ItemType Directory -Path $outside | Out-Null
Set-Content -NoNewline -LiteralPath (Join-Path $outside 'outside.bin') -Value 'outside'
$parentLink = Join-Path $TestDir 'artifact-parent-link'
if (Try-NewTestReparsePoint $parentLink $outside) {
    $copy = Clone $build
    $copy.outputs.dll.path = 'artifact-parent-link/outside.bin'
    $copy.outputs.dll.sha256 = Hash (Join-Path $outside 'outside.bin')
    $path = Write-Json $copy 'bad-build-reparse-parent.json'
    Reject 'artifact parent reparse point' { Test-Arm64xBuildManifest $path }
}
$fileLink = Join-Path $TestDir 'artifact-file-link.bin'
if (Try-NewTestReparsePoint $fileLink (Join-Path $TestDir 'host.bin') -File) {
    $copy = Clone $build
    $copy.outputs.dll.path = 'artifact-file-link.bin'
    $copy.outputs.dll.sha256 = Hash (Join-Path $TestDir 'host.bin')
    $path = Write-Json $copy 'bad-build-reparse-file.json'
    Reject 'artifact file reparse point' { Test-Arm64xBuildManifest $path }
}
$realRoot = Join-Path $TestDir 'manifest-root-target'
New-Item -ItemType Directory -Path $realRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $TestDir 'dll.bin'), (Join-Path $TestDir 'host.bin') -Destination $realRoot
$rootManifest = Join-Path $realRoot 'build.json'
$build | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 -LiteralPath $rootManifest
$rootLink = Join-Path $TestDir 'manifest-root-link'
if (Try-NewTestReparsePoint $rootLink $realRoot) {
    Reject 'manifest root reparse point' { Test-Arm64xBuildManifest (Join-Path $rootLink 'build.json') }
}
Write-Output 'ARM64X fixture manifest tests passed'
