# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceRoot,
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [Parameter(Mandatory = $true)][string]$LockFile
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Arm64xFixtureManifest.psm1') -Force
function Fail([string]$Message) { throw "ARM64X fixture build: $Message" }
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { Fail "$Program exited with $LASTEXITCODE" }
}
function Hash([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

$sourcePath = [IO.Path]::GetFullPath($SourceRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
$buildPath = [IO.Path]::GetFullPath($BuildDir).TrimEnd([IO.Path]::DirectorySeparatorChar)
$lockPath = [IO.Path]::GetFullPath($LockFile)
if ($buildPath.StartsWith($sourcePath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or $buildPath -eq $sourcePath) {
    Fail 'BuildDir must remain outside the source tree'
}
if (Test-Path -LiteralPath $buildPath) { Fail 'BuildDir must be initially absent' }
$lock = Test-Arm64xProvenanceLock $lockPath

$fixtureSource = Join-Path $sourcePath 'tests\fixtures\arm64x_linked'
if (-not (Test-Path -LiteralPath (Join-Path $fixtureSource 'CMakeLists.txt'))) { Fail 'fixture source is absent' }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { Fail 'vswhere.exe is absent' }
$installation = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.ARM64 -format json | ConvertFrom-Json | Select-Object -First 1)
if ($null -eq $installation) { Fail 'Visual Studio ARM64 tools are absent' }
$vcRoot = Join-Path $installation.installationPath 'VC\Tools\MSVC'
$vcVersion = (Get-ChildItem -LiteralPath $vcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name
if ($vcVersion -cne $lock.pin.vcToolsVersion) { Fail 'selected VC tools differ from the reviewed lock' }
$x64Cl = Join-Path $vcRoot "$vcVersion\bin\Hostarm64\x64\cl.exe"
if (-not (Test-Path -LiteralPath $x64Cl -PathType Leaf)) { Fail 'pinned x64 compiler is absent' }
if ((Hash $x64Cl) -cne $lock.pin.tools.x64.cl.sha256) { Fail 'x64 compiler hash differs from the reviewed lock' }

New-Item -ItemType Directory -Path $buildPath | Out-Null
$arm64Build = Join-Path $buildPath 'arm64'
$arm64ecBuild = Join-Path $buildPath 'arm64ec'
$reproDir = Join-Path $buildPath 'repro'
Invoke-Checked cmake @('-S', $fixtureSource, '-B', $arm64Build, '-G', 'Visual Studio 17 2022', '-A', 'ARM64', '-DBUILD_AS_ARM64X=ARM64', "-DMSWR_ARM64_REPRO_DIR=$reproDir")
Invoke-Checked cmake @('--build', $arm64Build, '--config', 'Release', '--target', 'arm64x_fixture', 'arm64x_fixture_inspector', '--', '/m:1')
$reproFile = Join-Path $reproDir 'arm64x_fixture.rsp'
if (-not (Test-Path -LiteralPath $reproFile -PathType Leaf)) { Fail 'ARM64 linker response file was not produced' }
Invoke-Checked cmake @('-S', $fixtureSource, '-B', $arm64ecBuild, '-G', 'Visual Studio 17 2022', '-A', 'ARM64EC', '-DBUILD_AS_ARM64X=ARM64EC', "-DMSWR_ARM64_REPRO_DIR=$reproDir", "-DMSWR_X64_CL=$x64Cl")
Invoke-Checked cmake @('--build', $arm64ecBuild, '--config', 'Release', '--target', 'arm64x_fixture', 'arm64x_fixture_host', '--', '/m:1')

$dllRelative = 'arm64ec/Release/arm64x_fixture.dll'
$hostRelative = 'arm64ec/Release/arm64x_fixture_host.exe'
$dll = Join-Path $buildPath $dllRelative
$validationHost = Join-Path $buildPath $hostRelative
foreach ($output in @($dll, $validationHost)) { if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { Fail "missing output $output" } }
$sourceFiles = @('CMakeLists.txt', 'arm64x.cmake', 'fixture.c', 'fixture_x64.c', 'fixture_api.h', 'host.c', 'fixture.def')
$sourceHashes = [ordered]@{}
foreach ($name in $sourceFiles) { $sourceHashes[$name] = Hash (Join-Path $fixtureSource $name) }
$manifest = [ordered]@{
    schemaVersion = 2
    producerLock = (Hash $lockPath)
    source = $sourceHashes
    outputs = [ordered]@{
        dll = [ordered]@{ type = 'dll'; path = $dllRelative; sha256 = (Hash $dll) }
        host = [ordered]@{ type = 'host'; path = $hostRelative; sha256 = (Hash $validationHost) }
    }
    distribution = 'build-tree-only'
}
$manifestPath = Join-Path $buildPath 'arm64x-fixture-build.manifest.json'
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -LiteralPath $manifestPath
Test-Arm64xBuildManifest $manifestPath | Out-Null
Write-Output $manifestPath
