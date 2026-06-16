# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

# Run formatting, clippy and tests across all supported targets.
# Cross targets are linted and built (cargo test --no-run); the host
# target is fully tested.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Tell the test runner not to re-enter the check suite from our cargo test runs.
$env:LANDSTRIP_RUNNER_NESTED = "1"

$Targets = @(
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-gnu"
)
$HostTarget = "x86_64-pc-windows-gnu"

function Invoke-Cargo {
    param([string[]]$CargoArgs)
    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error ("command failed: cargo " + ($CargoArgs -join " "))
    }
}

# Extra command a target needs to link; empty means the host linker suffices.
function Get-TargetLinker {
    param([string]$Target)
    switch ($Target) {
        "x86_64-pc-windows-gnu" { "x86_64-w64-mingw32-dlltool" }
        default { "" }
    }
}

# Whether a target can be built here. Missing std or cross toolchain -> skip.
function Test-TargetAvailable {
    param([string]$Target)
    if ((rustup target list --installed) -notcontains $Target) {
        Write-Warning "skipping ${Target}: rustup target not installed"
        return $false
    }
    $linker = Get-TargetLinker $Target
    if ($linker -and -not (Get-Command $linker -ErrorAction SilentlyContinue)) {
        Write-Warning "skipping ${Target}: missing toolchain ($linker)"
        return $false
    }
    return $true
}

Invoke-Cargo @("fmt", "--all", "--check")

foreach ($target in $Targets) {
    if (-not (Test-TargetAvailable $target)) {
        continue
    }

    Invoke-Cargo @("clippy", "--target", $target, "--all-targets", "--", "-D", "warnings")

    if ($target -eq $HostTarget) {
        Invoke-Cargo @("test", "--target", $target)
    } else {
        Invoke-Cargo @("test", "--target", $target, "--no-run")
    }
}
