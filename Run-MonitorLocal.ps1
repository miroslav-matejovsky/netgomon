<#
.SYNOPSIS
    Runs Invoke-NetworkMonitorProcess.ps1 targeting the local build of netwinmon.exe
    with a local logs directory and all monitoring features enabled.
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

# Run the monitor process wrapper script
$MonitorScript = Join-Path $RepoRoot "scripts\Invoke-NetworkMonitorProcess.ps1"
& $MonitorScript -ExePath $ExePath -LogRoot $LogRoot -EnableAll -PassThruExitCode -Arguments ($args -join ' ')
