<#
.SYNOPSIS
    Wraps an executable with Windows network monitoring.

.DESCRIPTION
    Invoke-NetworkMonitorProcess.ps1 is a small self-contained CLI-style wrapper for Windows that can:

      1. Run a target executable.
      2. Monitor mode:
         - apply no network restrictions
         - enable firewall logging
         - optionally start a WFP capture
         - optionally record TCP connection snapshots

    Architectural notes:
      - Monitoring uses Windows Firewall profile logging and optionally netsh WFP capture.

    Requirements:
      - Administrator privileges
      - Windows 10/11 or Windows Server with Defender Firewall / NetSecurity cmdlets

.PARAMETER ExePath
    Full path to the executable to run.

.PARAMETER Arguments
    Raw argument string passed to the target executable.

.PARAMETER WorkingDirectory
    Working directory for the target process.
    Defaults to the executable's parent directory.

.PARAMETER LogRoot
    Root directory for wrapper logs, WFP output, and snapshots.

.PARAMETER EnableWfpCapture
    Starts a WFP diagnostic capture using:
        netsh wfp capture start ...
    and stops it automatically on exit.

.PARAMETER EnableFirewallLogAllowed
    Enables logging of allowed traffic in the Windows Firewall log.

.PARAMETER EnableFirewallLogBlocked
    Enables logging of blocked traffic in the Windows Firewall log.
    Enabled by default.

.PARAMETER EnableTcpSnapshots
    Writes periodic 'netstat -ano -p tcp' snapshots to a log file while the wrapped
    process is running.

.PARAMETER SnapshotIntervalSeconds
    Interval for TCP snapshots. Used only when -EnableTcpSnapshots is specified.

.PARAMETER NoWindow
    Starts the target process hidden.

.PARAMETER PassThruExitCode
    If specified, the wrapper exits with the target process exit code.

.EXAMPLE
    # Monitoring only, no restrictions, full diagnostics
    .\Invoke-NetworkMonitorProcess.ps1 `
      -ExePath "C:\Tools\MyApp\myapp.exe" `
      -EnableWfpCapture `
      -EnableFirewallLogAllowed `
      -EnableFirewallLogBlocked `
      -EnableTcpSnapshots

.EXAMPLE
    # Display help
    Get-Help .\Invoke-NetworkMonitorProcess.ps1 -Full

.NOTES
    Important limitations:
      - Firewall profile logging is profile-wide, not process-local.
      - WFP capture is a system diagnostic capture, not a process-exclusive trace.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$ExePath,

    [Parameter(Position = 1)]
    [string]$Arguments = '',

    [Parameter()]
    [string]$WorkingDirectory = '',

    [Parameter()]
    [string]$LogRoot = 'C:\ProgramData\ProcNetWrap',

    [Parameter()]
    [switch]$EnableWfpCapture,

    [Parameter()]
    [switch]$EnableFirewallLogAllowed,

    [Parameter()]
    [switch]$EnableFirewallLogBlocked = $true,

    [Parameter()]
    [switch]$EnableTcpSnapshots,

    [Parameter()]
    [ValidateRange(1, 86400)]
    [int]$SnapshotIntervalSeconds = 5,

    [Parameter()]
    [switch]$NoWindow,

    [Parameter()]
    [switch]$PassThruExitCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------
# Utility functions
# ----------------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (-not (Test-IsAdmin)) {
        throw "Administrator privileges are required."
    }
}

function Ensure-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-RunLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "[{0}] {1}" -f (Get-Date -Format 's'), $Message
    $line | Tee-Object -FilePath $script:RunLog -Append
}

function Get-ProcNetWrapPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExePath,

        [Parameter(Mandatory = $true)]
        [string]$LogRoot
    )

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $exeName   = [System.IO.Path]::GetFileNameWithoutExtension($ExePath)

    return [pscustomobject]@{
        Timestamp       = $timestamp
        ExeName         = $exeName
        RunLog          = Join-Path $LogRoot "$exeName-$timestamp-monitor-wrapper.log"
        NetstatLog      = Join-Path $LogRoot "$exeName-$timestamp-monitor-netstat.log"
        WfpCaptureBase  = Join-Path $LogRoot "$exeName-$timestamp-monitor-wfp"
        FirewallLog     = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    }
}

function Start-WfpCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputBase
    )

    Write-RunLog "Starting WFP capture: $OutputBase"
    & netsh wfp capture start file="$OutputBase" cab=off traceonly=off |
        Tee-Object -FilePath $script:RunLog -Append | Out-Null
}

function Stop-WfpCapture {
    Write-RunLog "Stopping WFP capture"
    & netsh wfp capture stop |
        Tee-Object -FilePath $script:RunLog -Append | Out-Null
}

function Configure-FirewallLogging {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FirewallLogPath,

        [Parameter(Mandatory = $true)]
        [bool]$LogAllowed,

        [Parameter(Mandatory = $true)]
        [bool]$LogBlocked
    )

    Write-RunLog "Configuring firewall profile logging"
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -LogFileName $FirewallLogPath `
        -LogAllowed $LogAllowed `
        -LogBlocked $LogBlocked
}

function Start-WrappedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExePath,

        [Parameter()]
        [string]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [bool]$NoWindow
    )

    $windowStyle = if ($NoWindow) { 'Hidden' } else { 'Normal' }

    $proc = Start-Process `
        -FilePath $ExePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -PassThru `
        -WindowStyle $windowStyle

    return $proc
}

function Write-TcpSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Pid,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $stamp = Get-Date -Format 's'
    "===== $stamp PID=$Pid =====" | Out-File -FilePath $OutputPath -Append -Encoding utf8
    cmd /c "netstat -ano -p tcp" | Out-File -FilePath $OutputPath -Append -Encoding utf8
}

# ----------------------------
# Main
# ----------------------------

Assert-Admin

$ExePath = [System.IO.Path]::GetFullPath($ExePath)
if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $WorkingDirectory = Split-Path -Parent $ExePath
}

Ensure-Directory -Path $LogRoot

$paths         = Get-ProcNetWrapPaths -ExePath $ExePath -LogRoot $LogRoot
$script:RunLog = $paths.RunLog

Write-RunLog "Starting ProcNetMonitor session"
Write-RunLog "ExePath=$ExePath"
Write-RunLog "WorkingDirectory=$WorkingDirectory"
Write-RunLog "Arguments=$Arguments"
Write-RunLog "FirewallLog=$($paths.FirewallLog)"
Write-RunLog "EnableWfpCapture=$EnableWfpCapture"
Write-RunLog "EnableFirewallLogAllowed=$EnableFirewallLogAllowed"
Write-RunLog "EnableFirewallLogBlocked=$EnableFirewallLogBlocked"
Write-RunLog "EnableTcpSnapshots=$EnableTcpSnapshots"
Write-RunLog "SnapshotIntervalSeconds=$SnapshotIntervalSeconds"
Write-RunLog "NoWindow=$NoWindow"
Write-RunLog "PassThruExitCode=$PassThruExitCode"

$proc = $null

try {
    Configure-FirewallLogging `
        -FirewallLogPath $paths.FirewallLog `
        -LogAllowed ([bool]$EnableFirewallLogAllowed) `
        -LogBlocked ([bool]$EnableFirewallLogBlocked)

    if ($EnableWfpCapture) {
        Start-WfpCapture -OutputBase $paths.WfpCaptureBase
    }

    Write-RunLog "Launching target process"
    $proc = Start-WrappedProcess `
        -ExePath $ExePath `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -NoWindow ([bool]$NoWindow)

    Write-RunLog "Started PID=$($proc.Id)"

    while (-not $proc.HasExited) {
        if ($EnableTcpSnapshots) {
            Write-TcpSnapshot -Pid $proc.Id -OutputPath $paths.NetstatLog
        }

        Start-Sleep -Seconds $SnapshotIntervalSeconds
        $proc.Refresh()
    }

    Write-RunLog "Target process exited with code $($proc.ExitCode)"
}
finally {
    if ($EnableWfpCapture) {
        try {
            Stop-WfpCapture
        }
        catch {
            Write-RunLog "WFP capture stop failed: $($_.Exception.Message)"
        }
    }

    Write-RunLog "ProcNetMonitor session finished"
    Write-RunLog "RunLog=$($paths.RunLog)"
    Write-RunLog "FirewallLog=$($paths.FirewallLog)"

    if ($EnableTcpSnapshots) {
        Write-RunLog "TcpSnapshotLog=$($paths.NetstatLog)"
    }

    if ($EnableWfpCapture) {
        Write-RunLog "WfpCaptureBase=$($paths.WfpCaptureBase)"
    }

    if ($PassThruExitCode -and $null -ne $proc) {
        exit $proc.ExitCode
    }
}
