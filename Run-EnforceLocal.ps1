<#
.SYNOPSIS
    Runs Invoke-NetworkEnforceProcess.ps1 targeting the local build of netwinmon.exe
    with a local logs directory and all monitoring options enabled.
#>

$ErrorActionPreference = 'Stop'

# Determine workspace root (where this script resides)
$RepoRoot = $PSScriptRoot
if ($null -eq $RepoRoot -or $RepoRoot -eq '') {
    $RepoRoot = Get-Location
}

$ExePath = Join-Path $RepoRoot "dist\netwinmon.exe"
$LogRoot = Join-Path $RepoRoot "logs"

# Ensure the executable exists
if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Warning "Executable not found at '$ExePath'. Please run 'task build' first to build it."
}

# Allowed destinations by default (Google DNS 8.8.8.8 and example.com)
$AllowedRemoteAddresses = @('8.8.8.8', '93.184.216.34')
$AllowedRemotePorts = @(53, 80)

# Run the enforce process wrapper script
$EnforceScript = Join-Path $RepoRoot "scripts\Invoke-NetworkEnforceProcess.ps1"
& $EnforceScript `
    -ExePath $ExePath `
    -LogRoot $LogRoot `
    -AllowedRemoteAddresses $AllowedRemoteAddresses `
    -AllowedRemotePorts $AllowedRemotePorts `
    -Protocol 'Any' `
    -EnableAll `
    -PassThruExitCode `
    -Arguments ($args -join ' ')
