<#
.SYNOPSIS
    Wraps an executable with Windows network monitoring and outbound restrictions.

.DESCRIPTION
    Invoke-NetworkEnforceProcess.ps1 is a small self-contained CLI-style wrapper for Windows that can:

      1. Run a target executable.
      2. Enforce mode:
         - create a temporary block-all-outbound rule for the target executable
         - add explicit outbound allow rules for approved remote IP/port combinations
         - enable firewall logging
         - optionally start a WFP capture
         - optionally record TCP connection snapshots
         - remove temporary rules on exit

    Architectural notes:
      - Firewall rule scope is the executable path specified by -ExePath.
      - Monitoring uses Windows Firewall profile logging and optionally netsh WFP capture.
      - Enforcement uses Windows Defender Firewall PowerShell cmdlets.
      - Rule cleanup occurs in a finally block.

    Requirements:
      - Administrator privileges
      - Windows 10/11 or Windows Server with Defender Firewall / NetSecurity cmdlets

.PARAMETER ExePath
    Full path to the executable to run.

.PARAMETER AllowedRemoteAddresses
    Approved remote IP addresses, CIDR ranges, or values accepted by Windows Firewall
    for RemoteAddress.

.PARAMETER AllowedRemotePorts
    Approved remote ports.

.PARAMETER Protocol
    Transport protocol for allow rules.
    Accepted values: TCP, UDP, Any

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

.PARAMETER EnableUdpSnapshots
    Writes periodic 'netstat -ano -p udp' snapshots to a log file while the wrapped
    process is running.

.PARAMETER EnableAll
    Enables all monitoring and auditing options: WFP capture, allowed/blocked firewall logging, TCP/UDP netstat snapshots, and rule auditing.

.PARAMETER SnapshotIntervalSeconds
    Interval for TCP/UDP snapshots. Used only when -EnableTcpSnapshots or -EnableUdpSnapshots is specified.

.PARAMETER NoWindow
    Starts the target process hidden.

.PARAMETER PassThruExitCode
    If specified, the wrapper exits with the target process exit code.

.PARAMETER ShowRuleAudit
    Exports a rule audit for rules created by this wrapper session.

.PARAMETER StrictAllowList
    - if set and no allowlist is supplied, the process gets no outbound access
    - if not set and no allowlist is supplied, the script throws before launch

.EXAMPLE
    # Strict enforcement: only TCP 443 to one remote address
    .\Invoke-NetworkEnforceProcess.ps1 `
      -ExePath "C:\Tools\MyApp\myapp.exe" `
      -AllowedRemoteAddresses "203.0.113.10" `
      -AllowedRemotePorts 443 `
      -Protocol TCP `
      -EnableWfpCapture `
      -ShowRuleAudit `
      -PassThruExitCode

.EXAMPLE
    # Enforce mode with explicit full deny (no allow rules)
    .\Invoke-NetworkEnforceProcess.ps1 `
      -ExePath "C:\Tools\MyApp\myapp.exe" `
      -StrictAllowList

.EXAMPLE
    # Display help
    Get-Help .\Invoke-NetworkEnforceProcess.ps1 -Full

.NOTES
    Important limitations:
      - Rules are scoped to the executable path. If the target process spawns a helper
        executable that performs networking, that helper is not automatically covered.
      - Firewall profile logging is profile-wide, not process-local.
      - WFP capture is a system diagnostic capture, not a process-exclusive trace.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$ExePath,

    [Parameter(Position = 1)]
    [string[]]$AllowedRemoteAddresses = @(),

    [Parameter()]
    [int[]]$AllowedRemotePorts = @(),

    [Parameter()]
    [ValidateSet('TCP', 'UDP', 'Any')]
    [string]$Protocol = 'TCP',

    [Parameter()]
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
    [switch]$EnableUdpSnapshots,

    [Parameter()]
    [switch]$EnableAll,

    [Parameter()]
    [ValidateRange(1, 86400)]
    [int]$SnapshotIntervalSeconds = 5,

    [Parameter()]
    [switch]$NoWindow,

    [Parameter()]
    [switch]$PassThruExitCode,

    [Parameter()]
    [switch]$ShowRuleAudit,

    [Parameter()]
    [switch]$StrictAllowList
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

function New-SessionId {
    return ([guid]::NewGuid().ToString())
}

function New-RuleName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Base,

        [Parameter(Mandatory = $true)]
        [string]$Suffix
    )

    return "$Base | $Suffix"
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
        Timestamp           = $timestamp
        ExeName             = $exeName
        RunLog              = Join-Path $LogRoot "$exeName-$timestamp-enforce-wrapper.log"
        NetstatLog          = Join-Path $LogRoot "$exeName-$timestamp-enforce-netstat.log"
        RuleAuditLog        = Join-Path $LogRoot "$exeName-$timestamp-enforce-rules.txt"
        WfpCaptureBase      = Join-Path $LogRoot "$exeName-$timestamp-enforce-wfp"
        FirewallLog         = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
        FirewallFilteredLog = Join-Path $LogRoot "$exeName-$timestamp-enforce-firewall.log"
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

    $allowedStr = if ($LogAllowed) { "True" } else { "False" }
    $blockedStr = if ($LogBlocked) { "True" } else { "False" }

    Write-RunLog "Configuring firewall profile logging"
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -LogFileName $FirewallLogPath `
        -LogAllowed $allowedStr `
        -LogBlocked $blockedStr
}

function Add-EnforcementRules {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExePath,

        [Parameter(Mandatory = $true)]
        [string]$RuleGroup,

        [Parameter(Mandatory = $true)]
        [string]$SessionPrefix,

        [Parameter(Mandatory = $true)]
        [string[]]$AllowedRemoteAddresses,

        [Parameter(Mandatory = $true)]
        [int[]]$AllowedRemotePorts,

        [Parameter(Mandatory = $true)]
        [string]$Protocol,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$CreatedRuleNames,

        [Parameter(Mandatory = $true)]
        [bool]$StrictAllowList
    )

    Write-RunLog "Enforcement mode: applying temporary firewall restrictions"

    $blockRuleName = New-RuleName -Base $SessionPrefix -Suffix "BLOCK outbound all"

    New-NetFirewallRule `
        -DisplayName $blockRuleName `
        -Group $RuleGroup `
        -Direction Outbound `
        -Program $ExePath `
        -Action Block `
        -Enabled True `
        -Profile Domain,Private,Public | Out-Null

    $CreatedRuleNames.Add($blockRuleName) | Out-Null
    Write-RunLog "Created block rule: $blockRuleName"

    $hasAddresses = $AllowedRemoteAddresses.Count -gt 0
    $hasPorts     = $AllowedRemotePorts.Count -gt 0

    if (-not $hasAddresses -or -not $hasPorts) {
        if ($StrictAllowList) {
            Write-RunLog "StrictAllowList active and allowlist missing: process will have no outbound connectivity"
            return
        }
        else {
            throw "Enforce mode requires both -AllowedRemoteAddresses and -AllowedRemotePorts unless -StrictAllowList is specified."
        }
    }

    foreach ($addr in $AllowedRemoteAddresses) {
        foreach ($port in $AllowedRemotePorts) {
            $allowRuleName = New-RuleName -Base $SessionPrefix -Suffix "ALLOW $Protocol $addr:$port"

            New-NetFirewallRule `
                -DisplayName $allowRuleName `
                -Group $RuleGroup `
                -Direction Outbound `
                -Program $ExePath `
                -Action Allow `
                -Protocol $Protocol `
                -RemoteAddress $addr `
                -RemotePort $port `
                -Enabled True `
                -Profile Domain,Private,Public | Out-Null

            $CreatedRuleNames.Add($allowRuleName) | Out-Null
            Write-RunLog "Created allow rule: $allowRuleName"
        }
    }
}

function Remove-TemporaryRules {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$CreatedRuleNames
    )

    foreach ($ruleName in $CreatedRuleNames) {
        try {
            Remove-NetFirewallRule -DisplayName $ruleName
            Write-RunLog "Removed rule: $ruleName"
        }
        catch {
            Write-RunLog "Failed removing rule '$ruleName' : $($_.Exception.Message)"
        }
    }
}

function Export-RuleAudit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleGroup,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        $rules = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
        if ($null -eq $rules) {
            "No rules found for group: $RuleGroup" | Out-File -FilePath $OutputPath -Encoding utf8
            Write-RunLog "No rules found for audit"
            return
        }

        $rules | Format-List * | Out-String | Out-File -FilePath $OutputPath -Encoding utf8
        Write-RunLog "Exported firewall rule audit to $OutputPath"
    }
    catch {
        Write-RunLog "Firewall rule audit export failed: $($_.Exception.Message)"
    }
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
    "===== TCP $stamp PID=$Pid =====" | Out-File -FilePath $OutputPath -Append -Encoding utf8
    cmd /c "netstat -ano -p tcp" | Out-File -FilePath $OutputPath -Append -Encoding utf8
}

function Write-UdpSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Pid,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $stamp = Get-Date -Format 's'
    "===== UDP $stamp PID=$Pid =====" | Out-File -FilePath $OutputPath -Append -Encoding utf8
    cmd /c "netstat -ano -p udp" | Out-File -FilePath $OutputPath -Append -Encoding utf8
}

function Track-ProcessPorts {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Pid,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$TrackedPorts
    )

    try {
        $tcpConnections = Get-NetTCPConnection -OwningProcess $Pid -ErrorAction SilentlyContinue
        if ($null -ne $tcpConnections) {
            foreach ($conn in $tcpConnections) {
                $TrackedPorts['TCP'].Add([int]$conn.LocalPort) | Out-Null
            }
        }

        $udpEndpoints = Get-NetUDPEndpoint -OwningProcess $Pid -ErrorAction SilentlyContinue
        if ($null -ne $udpEndpoints) {
            foreach ($ep in $udpEndpoints) {
                $TrackedPorts['UDP'].Add([int]$ep.LocalPort) | Out-Null
            }
        }
    }
    catch {
        # Ignore errors tracking ports
    }
}

function Filter-FirewallLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FirewallLogPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [int]$Pid,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$LocalPorts,

        [Parameter(Mandatory = $true)]
        [DateTime]$StartTime,

        [Parameter(Mandatory = $true)]
        [DateTime]$EndTime
    )

    if (-not (Test-Path -LiteralPath $FirewallLogPath)) {
        Write-RunLog "Firewall log file not found at $FirewallLogPath, skipping filtering."
        return
    }

    Write-RunLog "Filtering firewall log for PID=$Pid"

    $bufferStart = $StartTime.AddSeconds(-15)
    $bufferEnd = $EndTime.AddSeconds(15)

    $filteredLines = [System.Collections.Generic.List[string]]::new()
    $filteredLines.Add("# Filtered Firewall Log for PID=$Pid")
    $filteredLines.Add("# Process lifetime: $($StartTime.ToString('s')) to $($EndTime.ToString('s'))")
    $filteredLines.Add("# TCP Ports: $(($LocalPorts['TCP'] | Sort-Object) -join ',')")
    $filteredLines.Add("# UDP Ports: $(($LocalPorts['UDP'] | Sort-Object) -join ',')")
    $filteredLines.Add("")

    $lines = Get-Content -LiteralPath $FirewallLogPath -ErrorAction SilentlyContinue
    if ($null -eq $lines) {
        return
    }

    foreach ($line in $lines) {
        if ($line.StartsWith('#')) {
            if ($line.StartsWith('#Fields:')) {
                $filteredLines.Add($line)
            }
            continue
        }

        $parts = $line -split '\s+' | Where-Object { $_ }
        if ($parts.Count -ge 8) {
            $dateStr = $parts[0]
            $timeStr = $parts[1]
            $dt = $null
            if ([DateTime]::TryParse("$dateStr $timeStr", [ref]$dt)) {
                if ($dt -ge $bufferStart -and $dt -le $bufferEnd) {
                    $proto = $parts[3].ToUpper()
                    $srcPortStr = $parts[6]
                    $dstPortStr = $parts[7]

                    if ($proto -eq "TCP" -or $proto -eq "UDP") {
                        $srcPort = 0
                        $dstPort = 0
                        if ([int]::TryParse($srcPortStr, [ref]$srcPort) -and [int]::TryParse($dstPortStr, [ref]$dstPort)) {
                            if ($LocalPorts[$proto].Contains($srcPort) -or $LocalPorts[$proto].Contains($dstPort)) {
                                $filteredLines.Add($line)
                            }
                        }
                    }
                }
            }
        }
    }

    $filteredLines | Out-File -FilePath $OutputPath -Encoding utf8
    Write-RunLog "Exported filtered firewall log to $OutputPath"
}

# ----------------------------
# Main
# ----------------------------

Assert-Admin

$ExePath = [System.IO.Path]::GetFullPath($ExePath)
if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

if ($EnableAll) {
    $EnableWfpCapture = $true
    $EnableFirewallLogAllowed = $true
    $EnableFirewallLogBlocked = $true
    $EnableTcpSnapshots = $true
    $EnableUdpSnapshots = $true
    $ShowRuleAudit = $true
}

if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $WorkingDirectory = Split-Path -Parent $ExePath
}

Ensure-Directory -Path $LogRoot

$paths         = Get-ProcNetWrapPaths -ExePath $ExePath -LogRoot $LogRoot
$script:RunLog = $paths.RunLog

$sessionId     = New-SessionId
$sessionPrefix = "ProcNetEnforce $($paths.ExeName) $sessionId"
$ruleGroup     = $sessionPrefix

$createdRuleNames = [System.Collections.Generic.List[string]]::new()

Write-RunLog "Starting ProcNetEnforce session"
Write-RunLog "ExePath=$ExePath"
Write-RunLog "WorkingDirectory=$WorkingDirectory"
Write-RunLog "Arguments=$Arguments"
Write-RunLog "AllowedRemoteAddresses=$($AllowedRemoteAddresses -join ',')"
Write-RunLog "AllowedRemotePorts=$($AllowedRemotePorts -join ',')"
Write-RunLog "Protocol=$Protocol"
Write-RunLog "FirewallLog=$($paths.FirewallLog)"
Write-RunLog "FirewallFilteredLog=$($paths.FirewallFilteredLog)"
Write-RunLog "EnableWfpCapture=$EnableWfpCapture"
Write-RunLog "EnableFirewallLogAllowed=$EnableFirewallLogAllowed"
Write-RunLog "EnableFirewallLogBlocked=$EnableFirewallLogBlocked"
Write-RunLog "EnableTcpSnapshots=$EnableTcpSnapshots"
Write-RunLog "EnableUdpSnapshots=$EnableUdpSnapshots"
Write-RunLog "EnableAll=$EnableAll"
Write-RunLog "SnapshotIntervalSeconds=$SnapshotIntervalSeconds"
Write-RunLog "NoWindow=$NoWindow"
Write-RunLog "PassThruExitCode=$PassThruExitCode"
Write-RunLog "ShowRuleAudit=$ShowRuleAudit"
Write-RunLog "StrictAllowList=$StrictAllowList"

$trackedPorts = @{
    TCP = [System.Collections.Generic.HashSet[int]]::new()
    UDP = [System.Collections.Generic.HashSet[int]]::new()
}
$startTime = [DateTime]::Now

$proc = $null

try {
    Configure-FirewallLogging `
        -FirewallLogPath $paths.FirewallLog `
        -LogAllowed ([bool]$EnableFirewallLogAllowed) `
        -LogBlocked ([bool]$EnableFirewallLogBlocked)

    Add-EnforcementRules `
        -ExePath $ExePath `
        -RuleGroup $ruleGroup `
        -SessionPrefix $sessionPrefix `
        -AllowedRemoteAddresses $AllowedRemoteAddresses `
        -AllowedRemotePorts $AllowedRemotePorts `
        -Protocol $Protocol `
        -CreatedRuleNames $createdRuleNames `
        -StrictAllowList ([bool]$StrictAllowList)

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
    Track-ProcessPorts -Pid $proc.Id -TrackedPorts $trackedPorts

    while (-not $proc.HasExited) {
        Track-ProcessPorts -Pid $proc.Id -TrackedPorts $trackedPorts
        if ($EnableTcpSnapshots) {
            Write-TcpSnapshot -Pid $proc.Id -OutputPath $paths.NetstatLog
        }
        if ($EnableUdpSnapshots) {
            Write-UdpSnapshot -Pid $proc.Id -OutputPath $paths.NetstatLog
        }

        Start-Sleep -Seconds $SnapshotIntervalSeconds
        $proc.Refresh()
    }

    Write-RunLog "Target process exited with code $($proc.ExitCode)"
}
finally {
    $endTime = [DateTime]::Now
    if ($null -ne $proc) {
        try {
            Filter-FirewallLog `
                -FirewallLogPath $paths.FirewallLog `
                -OutputPath $paths.FirewallFilteredLog `
                -Pid $proc.Id `
                -LocalPorts $trackedPorts `
                -StartTime $startTime `
                -EndTime $endTime
        }
        catch {
            Write-RunLog "Failed filtering firewall log: $($_.Exception.Message)"
        }
    }

    if ($EnableWfpCapture) {
        try {
            Stop-WfpCapture
        }
        catch {
            Write-RunLog "WFP capture stop failed: $($_.Exception.Message)"
        }
    }

    if ($ShowRuleAudit) {
        Export-RuleAudit -RuleGroup $ruleGroup -OutputPath $paths.RuleAuditLog
    }

    if ($createdRuleNames.Count -gt 0) {
        Remove-TemporaryRules -CreatedRuleNames $createdRuleNames
    }

    Write-RunLog "ProcNetEnforce session finished"
    Write-RunLog "RunLog=$($paths.RunLog)"
    Write-RunLog "FirewallLog=$($paths.FirewallLog)"
    if ($null -ne $proc -and (Test-Path -LiteralPath $paths.FirewallFilteredLog)) {
        Write-RunLog "FirewallFilteredLog=$($paths.FirewallFilteredLog)"
    }

    if ($EnableTcpSnapshots) {
        Write-RunLog "TcpSnapshotLog=$($paths.NetstatLog)"
    }

    if ($EnableUdpSnapshots) {
        Write-RunLog "UdpSnapshotLog=$($paths.NetstatLog)"
    }

    if ($EnableWfpCapture) {
        Write-RunLog "WfpCaptureBase=$($paths.WfpCaptureBase)"
    }

    if ($ShowRuleAudit) {
        Write-RunLog "RuleAuditLog=$($paths.RuleAuditLog)"
    }

    if ($PassThruExitCode -and $null -ne $proc) {
        exit $proc.ExitCode
    }
}
