# SPDX-License-Identifier: Apache-2.0
Set-StrictMode -Version Latest

function Assert-Arm64xExactProperties {
    param([Parameter(Mandatory = $true)]$Object, [Parameter(Mandatory = $true)][string[]]$Names, [Parameter(Mandatory = $true)][string]$Context)
    if ($null -eq $Object -or $Object -isnot [System.Management.Automation.PSCustomObject]) { throw "$Context must be an object" }
    $actual = @($Object.PSObject.Properties.Name)
    foreach ($name in $Names) { if ($actual -cnotcontains $name) { throw "$Context is missing '$name'" } }
    foreach ($name in $actual) { if ($Names -cnotcontains $name) { throw "$Context contains unknown property '$name'" } }
}

function Assert-Arm64xString {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Context)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) { throw "$Context must be a non-empty string" }
}

function Assert-Arm64xJsonNoDuplicateProperties {
    param([Parameter(Mandatory = $true)][System.Text.Json.JsonElement]$Element, [Parameter(Mandatory = $true)][string]$Context)
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw "$Context contains duplicate property '$($property.Name)'" }
            Assert-Arm64xJsonNoDuplicateProperties $property.Value "$Context.$($property.Name)"
        }
    } elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-Arm64xJsonNoDuplicateProperties $item "$Context[$index]"
            $index++
        }
    }
}

function Assert-Arm64xHash {
    param([Parameter(Mandatory = $true)]$Value, [Parameter(Mandatory = $true)][string]$Context)
    if ($Value -isnot [string] -or $Value -cnotmatch '^[0-9a-f]{64}$') { throw "$Context must be a lowercase SHA-256" }
}

function Read-Arm64xJson {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $json = Get-Content -Raw -LiteralPath $Path -ErrorAction Stop
        $document = [System.Text.Json.JsonDocument]::Parse($json)
        try { Assert-Arm64xJsonNoDuplicateProperties $document.RootElement 'JSON' } finally { $document.Dispose() }
        return $json | ConvertFrom-Json -ErrorAction Stop
    } catch { throw "invalid JSON in '$Path': $($_.Exception.Message)" }
}

function Test-Arm64xProvenanceLock {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $lock = Read-Arm64xJson $Path
    Assert-Arm64xExactProperties $lock @('schemaVersion', 'status', 'producer', 'documentation', 'sourceLicense', 'distribution', 'reviewEvidence', 'pin', 'reviewRequirement') 'provenance'
    if (($lock.schemaVersion -isnot [int] -and $lock.schemaVersion -isnot [long]) -or $lock.schemaVersion -ne 1) { throw 'provenance schemaVersion must be integer 1' }
    if ($lock.status -isnot [string] -or $lock.status -cne 'reviewed') { throw 'provenance status must be reviewed' }
    foreach ($name in @('producer', 'sourceLicense', 'distribution', 'reviewRequirement')) { Assert-Arm64xString $lock.$name "provenance $name" }
    if ($lock.documentation -isnot [array] -or $lock.documentation.Count -eq 0) { throw 'provenance documentation must be a non-empty array' }
    foreach ($entry in $lock.documentation) { Assert-Arm64xString $entry 'provenance documentation entry' }
    $reviewNames = @('workflowRun', 'runnerImageOS', 'runnerImageVersion', 'nativeMachine', 'visualStudioVersion', 'visualStudioInstallationVersion')
    Assert-Arm64xExactProperties $lock.reviewEvidence $reviewNames 'provenance reviewEvidence'
    foreach ($name in $reviewNames) { Assert-Arm64xString $lock.reviewEvidence.$name "provenance reviewEvidence.$name" }
    Assert-Arm64xExactProperties $lock.pin @('vcToolsVersion', 'windowsSdkVersion', 'tools', 'dumpbin') 'provenance pin'
    foreach ($name in @('vcToolsVersion', 'windowsSdkVersion')) { Assert-Arm64xString $lock.pin.$name "provenance pin.$name" }
    Assert-Arm64xExactProperties $lock.pin.tools @('arm64', 'arm64ec', 'x64') 'provenance pin.tools'
    foreach ($target in @('arm64', 'arm64ec', 'x64')) {
        $toolset = $lock.pin.tools.$target
        $toolsetNames = if ($target -eq 'arm64ec') { @('compiler', 'compilerMode', 'linker', 'linkerMode', 'cl', 'link', 'lib') } elseif ($target -eq 'x64') { @('cl', 'link', 'lib', 'ml64') } else { @('cl', 'link', 'lib') }
        Assert-Arm64xExactProperties $toolset $toolsetNames "provenance pin.tools.$target"
        if ($target -eq 'arm64ec') {
            foreach ($name in @('compiler', 'compilerMode', 'linker', 'linkerMode')) { Assert-Arm64xString $toolset.$name "provenance pin.tools.$target.$name" }
        }
        $tools = if ($target -eq 'x64') { @('cl', 'link', 'lib', 'ml64') } else { @('cl', 'link', 'lib') }
        foreach ($tool in $tools) {
            Assert-Arm64xExactProperties $toolset.$tool @('version', 'sha256') "provenance pin.tools.$target.$tool"
            Assert-Arm64xString $toolset.$tool.version "provenance pin.tools.$target.$tool.version"
            Assert-Arm64xHash $toolset.$tool.sha256 "provenance pin.tools.$target.$tool.sha256"
        }
    }
    Assert-Arm64xExactProperties $lock.pin.dumpbin @('version', 'sha256') 'provenance pin.dumpbin'
    Assert-Arm64xString $lock.pin.dumpbin.version 'provenance pin.dumpbin.version'
    Assert-Arm64xHash $lock.pin.dumpbin.sha256 'provenance pin.dumpbin.sha256'
    return $lock
}

function Resolve-Arm64xManifestArtifact {
    param([Parameter(Mandatory = $true)][string]$ManifestPath, [Parameter(Mandatory = $true)][string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath)) { throw "artifact path must be relative: '$RelativePath'" }
    if (($RelativePath -split '[\\/]') -contains '..') { throw "artifact path traverses its manifest directory: '$RelativePath'" }
    $base = [IO.Path]::GetFullPath((Split-Path -Parent $ManifestPath)).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $resolved = [IO.Path]::GetFullPath((Join-Path $base $RelativePath))
    $prefix = $base + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "artifact path escapes its manifest directory: '$RelativePath'" }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "artifact is missing: '$RelativePath'" }
    $cursor = Get-Item -LiteralPath $resolved -Force
    while ($true) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "artifact path contains a reparse point: '$RelativePath'" }
        $cursorPath = $cursor.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        if ([string]::Equals($cursorPath, $base, [StringComparison]::OrdinalIgnoreCase)) { break }
        $parentPath = Split-Path -Parent $cursor.FullName
        if ([string]::IsNullOrEmpty($parentPath)) { throw "artifact path has no confined parent: '$RelativePath'" }
        $cursor = Get-Item -LiteralPath $parentPath -Force
    }
    return $resolved
}

function Test-Arm64xBuildManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $manifest = Read-Arm64xJson $Path
    Assert-Arm64xExactProperties $manifest @('schemaVersion', 'gitCommit', 'producerLock', 'source', 'outputs', 'distribution') 'build manifest'
    if (($manifest.schemaVersion -isnot [int] -and $manifest.schemaVersion -isnot [long]) -or $manifest.schemaVersion -ne 3) { throw 'build manifest schemaVersion must be integer 3' }
    if ($manifest.gitCommit -isnot [string] -or $manifest.gitCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'build manifest gitCommit must be a lowercase Git SHA' }
    if ($manifest.distribution -cne 'build-tree-only') { throw 'build manifest distribution must be build-tree-only' }
    Assert-Arm64xHash $manifest.producerLock 'build manifest producerLock'
    $sources = @('CMakeLists.txt', 'arm64x.cmake', 'fixture.c', 'fixture_x64.c', 'fixture_x64_roundtrip.asm', 'fixture_api.h', 'host.c', 'fixture.def')
    Assert-Arm64xExactProperties $manifest.source $sources 'build manifest source'
    foreach ($name in $sources) { Assert-Arm64xHash $manifest.source.$name "build manifest source.$name" }
    Assert-Arm64xExactProperties $manifest.outputs @('dll', 'host') 'build manifest outputs'
    foreach ($name in @('dll', 'host')) {
        $record = $manifest.outputs.$name
        Assert-Arm64xExactProperties $record @('type', 'path', 'sha256') "build manifest outputs.$name"
        if ($record.type -cne $name) { throw "build manifest outputs.$name has the wrong type" }
        Assert-Arm64xHash $record.sha256 "build manifest outputs.$name.sha256"
        $artifact = Resolve-Arm64xManifestArtifact $Path $record.path
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
        if ($actual -cne $record.sha256) { throw "artifact hash mismatch: '$($record.path)'" }
    }
    return $manifest
}

Export-ModuleMember -Function Test-Arm64xProvenanceLock, Test-Arm64xBuildManifest, Resolve-Arm64xManifestArtifact
