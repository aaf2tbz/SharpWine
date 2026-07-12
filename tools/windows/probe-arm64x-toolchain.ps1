# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BuildDir,
    [Parameter(Mandatory = $true)][string]$LockFile
)
$ErrorActionPreference = 'Stop'
function Fail([string]$Message) { throw "ARM64X toolchain probe: $Message" }
function Hash([string]$Path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
if ($env:PROCESSOR_ARCHITECTURE -ne 'ARM64') { Fail 'PROCESSOR_ARCHITECTURE is not ARM64' }
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'Arm64') { Fail '.NET OSArchitecture is not Arm64' }
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class NativeMachine { [DllImport("kernel32.dll", SetLastError=true)] public static extern bool IsWow64Process2(IntPtr p, out ushort process, out ushort native); }
'@
$processMachine = [UInt16]0; $nativeMachine = [UInt16]0
if (-not [NativeMachine]::IsWow64Process2([Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$processMachine, [ref]$nativeMachine) -or $nativeMachine -ne 0xAA64) { Fail 'IsWow64Process2 does not report native ARM64' }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { Fail 'vswhere.exe is required; Visual Studio was not searched by any other method' }
$installation = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.ARM64 Microsoft.VisualStudio.Component.VC.Tools.ARM64EC -format json | ConvertFrom-Json | Select-Object -First 1)
if ($null -eq $installation) { Fail 'Visual Studio ARM64 and ARM64EC components are absent' }
$vcRoot = Join-Path $installation.installationPath 'VC\Tools\MSVC'
$vcVersion = (Get-ChildItem -LiteralPath $vcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name
if ([string]::IsNullOrEmpty($vcVersion)) { Fail 'VC tools version is absent' }
$toolRoot = Join-Path $vcRoot "$vcVersion\bin\Hostarm64"
$tools = @{}
foreach ($target in @('arm64', 'x64')) {
  $cl = Join-Path $toolRoot "$target\cl.exe"; $link = Join-Path $toolRoot "$target\link.exe"; $lib = Join-Path $toolRoot "$target\lib.exe"
  foreach ($path in @($cl, $link, $lib)) { if (-not (Test-Path -LiteralPath $path)) { Fail "missing $target tool $path" } }
  $tools[$target] = @{ cl = @{ version = (Get-Item $cl).VersionInfo.FileVersion; sha256 = Hash $cl }; link = @{ version = (Get-Item $link).VersionInfo.FileVersion; sha256 = Hash $link }; lib = @{ version = (Get-Item $lib).VersionInfo.FileVersion; sha256 = Hash $lib } }
}
$ml64 = Join-Path $toolRoot 'x64\ml64.exe'
if (-not (Test-Path -LiteralPath $ml64)) { Fail 'x64 ml64.exe is absent' }
$tools['x64']['ml64'] = @{ version = (Get-Item $ml64).VersionInfo.FileVersion; sha256 = Hash $ml64 }
$arm64Cl = Join-Path $toolRoot 'arm64\cl.exe'
$arm64Link = Join-Path $toolRoot 'arm64\link.exe'
$clHelp = & $arm64Cl '/?' 2>&1 | Out-String
$linkHelp = & $arm64Link '/?' 2>&1 | Out-String
if ($clHelp -notmatch '(?i)/arm64EC') { Fail '/arm64EC is not supported by the selected ARM64 compiler' }
if ($linkHelp -notmatch '(?i)ARM64EC') { Fail '/MACHINE:ARM64EC is not supported by the selected ARM64 linker' }
if ($linkHelp -notmatch '(?i)ARM64X') { Fail '/MACHINE:ARM64X is not supported by the selected ARM64 linker' }
$tools['arm64ec'] = @{ compiler = 'shared-arm64-cl'; compilerMode = '/arm64EC'; linker = 'shared-arm64-link'; linkerMode = '/MACHINE:ARM64EC'; cl = $tools.arm64.cl; link = $tools.arm64.link; lib = $tools.arm64.lib }
$dumpbin = Join-Path $toolRoot 'x64\dumpbin.exe'; if (-not (Test-Path $dumpbin)) { Fail 'dumpbin.exe is absent' }
$sdkRoot = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').'KitsRoot10'
if ([string]::IsNullOrEmpty($sdkRoot)) { Fail 'Windows 11 SDK is absent' }
$windows11SdkBuild = 22000
$sdkCandidates = Get-ChildItem (Join-Path $sdkRoot 'Lib') -Directory |
  ForEach-Object {
    if ($_.Name -match '^10\.0\.(\d+)\.\d+$') {
      [PSCustomObject]@{ Name = $_.Name; Build = [UInt32]$Matches[1] }
    }
  } |
  Where-Object { $_.Build -ge $windows11SdkBuild } |
  Sort-Object Build, Name -Descending
$sdkVersion = ($sdkCandidates | Select-Object -First 1).Name
if ([string]::IsNullOrEmpty($sdkVersion)) { Fail 'Windows 11 SDK 10.0.22000.0 or newer libraries are absent' }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
$manifest = [ordered]@{ schemaVersion = 1; runner = @{ processorArchitecture = $env:PROCESSOR_ARCHITECTURE; osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString(); nativeMachine = ('0x{0:X4}' -f $nativeMachine); osVersion = [Environment]::OSVersion.VersionString; imageVersion = $env:ImageVersion; imageOS = $env:ImageOS }; visualStudio = @{ version = $installation.catalog.productDisplayVersion; installationVersion = $installation.installationVersion }; vcToolsVersion = $vcVersion; windowsSdkVersion = $sdkVersion; tools = $tools; dumpbin = @{ version = (Get-Item $dumpbin).VersionInfo.FileVersion; sha256 = Hash $dumpbin }; documentation = @('https://learn.microsoft.com/en-us/windows/arm/arm64x-build', 'https://learn.microsoft.com/en-us/windows/arm/arm64ec-build', 'https://learn.microsoft.com/en-us/windows/arm/arm64ec'); sourceLicense = 'Apache-2.0'; distribution = 'build-tree-only' }
$manifestPath = Join-Path $BuildDir 'arm64x-toolchain-probe.manifest.json'; $manifest | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $manifestPath
$lock = Get-Content -Raw -LiteralPath $LockFile | ConvertFrom-Json
if ($lock.status -eq 'reviewed') {
  if ($null -eq $lock.pin -or $lock.pin.vcToolsVersion -ne $vcVersion -or $lock.pin.windowsSdkVersion -ne $sdkVersion) { Fail 'reviewed provenance lock does not match selected versions' }
  foreach ($target in @('arm64', 'arm64ec', 'x64')) {
    $names = if ($target -eq 'x64') { @('cl', 'link', 'lib', 'ml64') } else { @('cl', 'link', 'lib') }
    foreach ($name in $names) { if ($lock.pin.tools.$target.$name.sha256 -ne $tools[$target][$name].sha256) { Fail "reviewed provenance hash drift: $target/$name" } }
  }
  if ($null -eq $lock.pin.dumpbin -or $lock.pin.dumpbin.sha256 -ne (Hash $dumpbin)) { Fail 'reviewed provenance hash drift: dumpbin' }
} elseif ($lock.status -ne 'pending-first-native-arm64-review') { Fail 'unrecognized provenance lock status' }
Write-Output $manifestPath
