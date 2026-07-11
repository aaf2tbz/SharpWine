# SPDX-License-Identifier: Apache-2.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InspectionA,
    [Parameter(Mandatory = $true)][string]$ExecutionA,
    [Parameter(Mandatory = $true)][string]$InspectionB,
    [Parameter(Mandatory = $true)][string]$ExecutionB
)
$ErrorActionPreference = 'Stop'
function Fail([string]$Message) { throw "ARM64X issue #11 evidence: $Message" }
function Read-Json([string]$Path, [string]$Kind) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "$Kind is absent: $Path" }
    try { return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -ErrorAction Stop }
    catch { Fail "$Kind is invalid JSON: $($_.Exception.Message)" }
}
function Exact($Object, [string[]]$Names, [string]$Context) {
    if ($null -eq $Object) { Fail "$Context is absent" }
    $actual = @($Object.PSObject.Properties.Name)
    foreach ($name in $Names) { if ($actual -cnotcontains $name) { Fail "$Context lacks $name" } }
    foreach ($name in $actual) { if ($Names -cnotcontains $name) { Fail "$Context contains unknown $name" } }
}
function Natural($Value, [string]$Context) {
    if ($Value -isnot [ValueType] -or [decimal]$Value -lt 0 -or [decimal]$Value % 1 -ne 0) {
        Fail "$Context is not a natural number"
    }
}
function Is-Code-Rva($Parser, [uint64]$Rva, [string]$Isa) {
    foreach ($range in @($Parser.codeRanges)) {
        if ($range.isa -ceq $Isa -and $Rva -ge [uint64]$range.startRva -and $Rva -lt [uint64]$range.endRva) { return $true }
    }
    return $false
}
function Validate-Pair([string]$InspectionPath, [string]$ExecutionPath, [string]$Name) {
    $inspection = Read-Json $InspectionPath "inspection evidence $Name"
    Exact $inspection @('schemaVersion', 'distribution', 'manifestSha256', 'dllSha256', 'parser') "inspection evidence $Name"
    if ($inspection.schemaVersion -ne 1 -or $inspection.distribution -cne 'build-tree-only') { Fail "inspection evidence $Name has the wrong contract" }

    $execution = Read-Json $ExecutionPath "execution evidence $Name"
    Exact $execution @('schemaVersion', 'distribution', 'producer', 'dynarmicCommit', 'dllSha256',
        'inspectionSha256', 'nativeMachine', 'contextSize', 'imageBase', 'loadedBase', 'blinkLoaded',
        'x64InstructionsFetched', 'passed', 'stages') "execution evidence $Name"
    if ($execution.schemaVersion -ne 1 -or $execution.distribution -cne 'build-tree-only' -or
        $execution.producer -cne 'arm64x_issue11_probe') { Fail "execution evidence $Name has the wrong contract" }
    if ($execution.dynarmicCommit -cne 'a41c380246d3d9f9874f0f792d234dc0cc17c180') { Fail "execution evidence $Name did not use pinned Dynarmic" }
    if ($execution.dllSha256 -cne $inspection.dllSha256) { Fail "execution evidence $Name is not bound to the inspected DLL" }
    $inspectionHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $InspectionPath).Hash.ToLowerInvariant()
    if ($execution.inspectionSha256 -cne $inspectionHash) { Fail "execution evidence $Name is not bound to its inspection" }
    if ($execution.nativeMachine -cne 'arm64' -or $execution.contextSize -ne 720 -or
        $execution.blinkLoaded -cne $false -or $execution.x64InstructionsFetched -ne 0 -or
        $execution.passed -cne $true) { Fail "execution evidence $Name violates native, ABI, boundary, or no-Blink requirements" }
    foreach ($field in @('imageBase', 'loadedBase', 'contextSize', 'x64InstructionsFetched')) { Natural $execution.$field "execution evidence $Name/$field" }

    $required = @('integerExit', 'floatingExit', 'aggregateExit', 'variadicExit', 'entryInteger')
    $seen = @{}
    $exitBoundaries = @{}
    $checkerVa = $null
    foreach ($stage in @($execution.stages)) {
        Exact $stage @('name', 'passed', 'startVa', 'boundaryVa', 'instructionsRetired', 'transitions',
            'descriptorVa', 'entryThunkVa', 'checkerVa') "execution stage $Name"
        if ($required -cnotcontains $stage.name -or $seen.ContainsKey($stage.name)) { Fail "execution stage $Name has an unknown or duplicate name" }
        $seen[$stage.name] = $stage
        foreach ($field in @('startVa', 'boundaryVa', 'instructionsRetired', 'transitions', 'descriptorVa', 'entryThunkVa', 'checkerVa')) { Natural $stage.$field "execution stage $Name/$($stage.name)/$field" }
        if ($stage.passed -cne $true -or $stage.instructionsRetired -le 0 -or $stage.transitions -gt 8) { Fail "execution stage $Name/$($stage.name) did not pass bounded execution" }
        if ($stage.name -like '*Exit') {
            if ($exitBoundaries.ContainsKey([string]$stage.boundaryVa)) { Fail "execution stage $Name/$($stage.name) reused an x64 boundary" }
            $exitBoundaries[[string]$stage.boundaryVa] = $true
            if ($null -eq $checkerVa) { $checkerVa = $stage.checkerVa }
            elseif ($stage.checkerVa -ne $checkerVa) { Fail "execution stage $Name/$($stage.name) used a different checker" }
            if ($stage.boundaryVa -lt $execution.loadedBase) { Fail "execution stage $Name/$($stage.name) has an invalid boundary" }
            $rva = [uint64]$stage.boundaryVa - [uint64]$execution.loadedBase
            if (-not (Is-Code-Rva $inspection.parser $rva 'x64')) { Fail "execution stage $Name/$($stage.name) did not stop at checked x64 metadata" }
            if ($stage.checkerVa -lt $execution.loadedBase) { Fail "execution stage $Name/$($stage.name) has an invalid checker" }
            $checkerRva = [uint64]$stage.checkerVa - [uint64]$execution.loadedBase
            if (-not (Is-Code-Rva $inspection.parser $checkerRva 'arm64ec')) { Fail "execution stage $Name/$($stage.name) did not execute a metadata-classified ARM64EC checker" }
        } else {
            if ($stage.descriptorVa -eq 0 -or $stage.entryThunkVa -eq 0) { Fail "entry stage $Name lacks descriptor evidence" }
        }
    }
    foreach ($stage in $required) { if (-not $seen.ContainsKey($stage)) { Fail "execution evidence $Name lacks $stage" } }
    return $execution
}
function Normalize($Execution) {
    $records = foreach ($stage in @($Execution.stages)) {
        [ordered]@{
            name = $stage.name
            startRva = [uint64]$stage.startVa - [uint64]$Execution.loadedBase
            boundaryRva = if ([uint64]$stage.boundaryVa -ge [uint64]$Execution.loadedBase) { [uint64]$stage.boundaryVa - [uint64]$Execution.loadedBase } else { 0 }
            retired = $stage.instructionsRetired
            transitions = $stage.transitions
            descriptorRva = if ([uint64]$stage.descriptorVa -ge [uint64]$Execution.loadedBase) { [uint64]$stage.descriptorVa - [uint64]$Execution.loadedBase } else { 0 }
            thunkRva = if ([uint64]$stage.entryThunkVa -ge [uint64]$Execution.loadedBase) { [uint64]$stage.entryThunkVa - [uint64]$Execution.loadedBase } else { 0 }
            checkerRva = if ([uint64]$stage.checkerVa -ge [uint64]$Execution.loadedBase) { [uint64]$stage.checkerVa - [uint64]$Execution.loadedBase } else { 0 }
        }
    }
    return ($records | ConvertTo-Json -Depth 5 -Compress)
}
$a = Validate-Pair $InspectionA $ExecutionA 'A'
$b = Validate-Pair $InspectionB $ExecutionB 'B'
if ((Normalize $a) -cne (Normalize $b)) { Fail 'clean builds disagree on normalized execution evidence' }
Write-Output 'ARM64X issue #11 execution evidence passed'
