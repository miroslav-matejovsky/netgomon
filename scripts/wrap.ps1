<#
.SYNOPSIS
    Wraps a target executable with temporary outbound Windows Firewall rules
    and optional WFP diagnostic capture.

.DESCRIPTION
    This script implements an ephemeral, process-scoped outbound allowlist
    around a target executable path using Windows Defender Firewall cmdlets.
    It can also:
      - Enable firewall logging for allowed/blocked traffic
      - Start and stop a WFP (Windows Filtering Platform) capture
      - Produce local wrapper logs and periodic netstat snapshots

    The intended model is:
      1. Create a block-all-outbound rule for the target executable
      2. Add explicit outbound allow rules for approved IPs/ports
      3. Launch the target executable
      4. Record diagnostics while it runs
      5. Remove the temporary rules on exit

    Notes:
      - Must be run elevated as Administrator
      - Firewall rules are scoped to the executable path
      - If the target launches helper binaries that perform networking,
        those binaries are NOT covered unless additional rules are created

.PARAMETER ExePath
    Full path to the executable to wrap.

.PARAMETER AllowedRemoteAddresses
    List of approved remote IP addresses (IPv4/IPv6) or ranges accepted by
    Windows Firewall for RemoteAddress.

.PARAMETER AllowedRemotePorts
    List of approved remote ports.

.PARAMETER Protocol
    Transport protocol for allow rules. Typical values: TCP, UDP, Any.

.PARAMETER WorkingDirectory
    Optional working directory for the target process. Defaults to the
    executable's parent directory.

.PARAMETER Arguments
    Optional raw argument string passed to the target process.

.PARAMETER LogRoot
    Base directory used for wrapper logs and WFP output.

.PARAMETER EnableWfpCapture
    If set, starts a WFP diagnostic capture via `netsh wfp capture start`
    and stops it on exit.

.PARAMETER EnableFirewallLogAllowed
    If set, enables logging of allowed traffic in the firewall profile log.

.PARAMETER EnableFirewallLogBlocked
    If set, enables logging of blocked traffic in the firewall profile log.
    Default is enabled.

.EXAMPLE
    .\Invoke-NetworkWrappedProcess.ps1 `
      -ExePath "C:\Tools\MyApp\myapp.exe" `
      -Arguments "--mode sync --verbose" `
      -AllowedRemoteAddresses "203.0.113.10" `
      -AllowedRemotePorts 443 `
      -EnableWfpCapture `
      -EnableFirewallLogAllowed `
      -EnableFirewallLogBlocked

.EXAMPLE
    .\Invoke-NetworkWrappedProcess.ps1 `
      -ExePath "C:\Tools\MyApp\myapp.exe" `
      -AllowedRemoteAddresses "203.0.113.10","198.51.100.22" `
      -AllowedRemotePorts 443,8443 `
      -EnableWfpCapture

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExePath,

    [Parameter()]
    [string[]]$AllowedRemoteAddresses = @(),

    [Parameter()]
    [int[]]$AllowedRemotePorts = @(443),

    [Parameter()]
    [ValidateSet("TCP", "UDP", "Any")]
    [string]$Protocol = "TCP",

    [Parameter()]
    [string]$WorkingDirectory = "",

    [Parameter()]
    [string]$Arguments = "",

    [Parameter()]
    [string]$LogRoot = "C:\ProgramData\ProcNetWrap",

    [Parameter()]
    [switch]$EnableWfpCapture,

    [Parameter()]
    [switch]$EnableFirewallLogAllowed,

    [Parameter()]
    [switch]$EnableFirewallLogBlocked = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    <#
    .SYNOPSIS
        Verifies that the current PowerShell session is elevated.
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run elevated as Administrator."
    }
}

function Ensure-Directory {
    <#
    .SYNOPSIS
        Creates a directory if it does not already exist.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function New-RuleName {
    <#
    .SYNOPSIS
        Builds a readable temporary firewall rule name for this wrapper session.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Base,

        [Parameter(Mandatory = $true)]
        [string]$Suffix
    )

    return "$Base | $Suffix"
}

function Write-RunLog {
    <#
    .SYNOPSIS
        Writes a timestamped line both to console and to the wrapper log file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "[{0}] {1}" -f (Get-Date -Format "s"), $Message
    $line | Tee-Object -FilePath $script:RunLog -Append
}

Assert-Admin

# Normalize and validate paths
$ExePath = [System.IO.Path]::GetFullPath($ExePath)

if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $WorkingDirectory = Split-Path -Parent $ExePath
}

Ensure-Directory -Path $LogRoot

# Session-level identifiers and log files
$timestamp       = Get-Date -Format "yyyyMMdd-HHmmss"
$exeName         = [System.IO.Path]::GetFileNameWithoutExtension($ExePath)
$sessionId       = [guid]::NewGuid().ToString()
$sessionPrefix   = "ProcNetWrap $exeName $sessionId"
$ruleGroup       = $sessionPrefix

$script:RunLog   = Join-Path $LogRoot "$exeName-$timestamp-wrapper.log"
$netstatLog      = Join-Path $LogRoot "$exeName-$timestamp-netstat.log"
$rulesAuditLog   = Join-Path $LogRoot "$exeName-$timestamp-rules.txt"
$wfpCaptureBase  = Join-Path $LogRoot "$exeName-$timestamp-wfp"

# Standard Windows Firewall log file
$firewallLog     = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

Write-RunLog "Starting wrapper session"
Write-RunLog "ExePath=$ExePath"
Write-RunLog "WorkingDirectory=$WorkingDirectory"
Write-RunLog "Arguments=$Arguments"
Write-RunLog "AllowedRemoteAddresses=$($AllowedRemoteAddresses -join ',')"
Write-RunLog "AllowedRemotePorts=$($AllowedRemotePorts -join ',')"
Write-RunLog "Protocol=$Protocol"
Write-RunLog "FirewallLog=$firewallLog"
Write-RunLog "EnableWfpCapture=$EnableWfpCapture"
Write-RunLog "EnableFirewallLogAllowed=$EnableFirewallLogAllowed"
Write-RunLog "EnableFirewallLogBlocked=$EnableFirewallLogBlocked"

# Configure Windows Firewall profile logging
# This affects the configured profiles globally, not only the target executable.
Write-RunLog "Configuring firewall profile logging"
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -LogFileName $firewallLog `
    -LogAllowed ([bool]$EnableFirewallLogAllowed) `
    -LogBlocked ([bool]$EnableFirewallLogBlocked)

# Keep track of created rule names for cleanup
$createdRuleNames = New-Object System.Collections.Generic.List[string]

try {
    #
    # Rule strategy:
    #   1) Block all outbound traffic for this executable
    #   2) Add explicit allow rules for approved remote address/port combinations
    #
    # This gives a deny-by-default outbound model for the specified executable path.
    #

    # 1) Block all outbound traffic for the executable
    $blockRuleName = New-RuleName -Base $sessionPrefix -Suffix "BLOCK outbound all"

    New-NetFirewallRule `
        -DisplayName $blockRuleName `
        -Group $ruleGroup `
        -Direction Outbound `
        -Program $ExePath `
        -Action Block `
        -Enabled True `
        -Profile Domain,Private,Public | Out-Null

    $createdRuleNames.Add($blockRuleName) | Out-Null
    Write-RunLog "Created block rule: $blockRuleName"

    # 2) Add allow rules for the approved destinations
    if ($AllowedRemoteAddresses.Count -gt 0 -and $AllowedRemotePorts.Count -gt 0) {
        foreach ($addr in $AllowedRemoteAddresses) {
            foreach ($port in $AllowedRemotePorts) {
                $allowRuleName = New-RuleName -Base $sessionPrefix -Suffix "ALLOW $Protocol $addr:$port"

                New-NetFirewallRule `
                    -DisplayName $allowRuleName `
                    -Group $ruleGroup `
                    -Direction Outbound `
                    -Program $ExePath `
                    -Action Allow `
                    -Protocol $Protocol `
                    -RemoteAddress $addr `
                    -RemotePort $port `
                    -Enabled True `
                    -Profile Domain,Private,Public | Out-Null

                $createdRuleNames.Add($allowRuleName) | Out-Null
                Write-RunLog "Created allow rule: $allowRuleName"
            }
        }
    }
    else {
        Write-RunLog "No allow rules created because AllowedRemoteAddresses or AllowedRemotePorts is empty"
        Write-RunLog "Result: target executable will have all outbound traffic blocked"
    }

    # Optional WFP diagnostic capture
    if ($EnableWfpCapture) {
        Write-RunLog "Starting WFP capture: $wfpCaptureBase"
        & netsh wfp capture start file="$wfpCaptureBase" cab=off traceonly=off |
            Tee-Object -FilePath $script:RunLog -Append
    }

    # Launch target process
    Write-RunLog "Launching target process"
    $proc = Start-Process `
        -FilePath $ExePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -PassThru `
        -WindowStyle Normal

    Write-RunLog "Started PID=$($proc.Id)"

    # Periodic connection snapshots for operator convenience.
    # These are NOT authoritative enforcement logs; they are convenience snapshots.
    while (-not $proc.HasExited) {
        $stamp = Get-Date -Format "s"
        "===== $stamp PID=$($proc.Id) =====" | Out-File -FilePath $netstatLog -Append -Encoding utf8
        cmd /c "netstat -ano -p tcp" | Out-File -FilePath $netstatLog -Append -Encoding utf8
        Start-Sleep -Seconds 5
        $proc.Refresh()
    }

    Write-RunLog "Process exited with code $($proc.ExitCode)"
}
finally {
    # Stop WFP capture if enabled
    if ($EnableWfpCapture) {
        Write-RunLog "Stopping WFP capture"
        try {
            & netsh wfp capture stop | Tee-Object -FilePath $script:RunLog -Append
        }
        catch {
            Write-RunLog "WFP capture stop failed: $($_.Exception.Message)"
        }
    }

    # Export a simple firewall-rule audit for the created group
    try {
        Get-NetFirewallRule -Group $ruleGroup |
            Get-NetFirewallPortFilter |
            Format-Table -AutoSize | Out-String |
            Out-File -FilePath $rulesAuditLog -Encoding utf8

        Write-RunLog "Exported firewall rule audit to $rulesAuditLog"
    }
    catch {
        Write-RunLog "Firewall rule audit export failed: $($_.Exception.Message)"
    }

    # Cleanup temporary rules
    foreach ($ruleName in $createdRuleNames) {
        try {
            Remove-NetFirewallRule -DisplayName $ruleName
            Write-RunLog "Removed rule: $ruleName"
        }
        catch {
            Write-RunLog "Failed removing rule $ruleName : $($_.Exception.Message)"
        }
    }

    Write-RunLog "Wrapper session finished"
}