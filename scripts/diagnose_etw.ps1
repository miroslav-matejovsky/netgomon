param()

$ErrorActionPreference = "Stop"

Write-Host "ETW Diagnostics Script" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan

# Ensure admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as an Administrator to query ETW sessions and providers properly."
    Write-Warning "Please restart PowerShell as Administrator and run again."
    exit
}

Write-Host "`n[1/6] Windows Version Information" -ForegroundColor Yellow
Get-ComputerInfo | Select-Object OsName, OsVersion, WindowsBuildLabEx | Format-List

Write-Host "`n[2/6] Audit Policy for Filtering Platform Connection" -ForegroundColor Yellow
try {
    auditpol /get /subcategory:"Filtering Platform Connection"
} catch {
    Write-Warning "Failed to query auditpol: $_"
}

Write-Host "`n[3/6] Checking Microsoft-Windows-Kernel-Network Provider" -ForegroundColor Yellow
try {
    logman query providers "Microsoft-Windows-Kernel-Network"
} catch {
    Write-Warning "Failed to query provider: $_"
}

Write-Host "`n[4/6] Active ETW Sessions" -ForegroundColor Yellow
try {
    $sessions = logman query -ets
    $sessions
} catch {
    Write-Warning "Failed to query sessions: $_"
}

Write-Host "`n[5/6] Searching for Orphaned NetWinMon Sessions" -ForegroundColor Yellow
if ($sessions) {
    $orphaned = $sessions | Select-String -Pattern "NetWinMon"
    if ($orphaned) {
        Write-Host "Found potentially orphaned NetWinMon sessions:" -ForegroundColor Red
        $orphaned
        Write-Host "You can stop them using: logman stop <session_name> -ets"
    } else {
        Write-Host "No orphaned NetWinMon sessions found." -ForegroundColor Green
    }
}

Write-Host "`n[6/6] Test ETW Capture using Logman" -ForegroundColor Yellow
$testSessionName = "NetWinMon_Diag_Test"
$providerGuid = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
$traceFile = "$env:TEMP\netwinmon_diag.etl"

if (Test-Path $traceFile) {
    Remove-Item $traceFile -Force
}

# Ensure session is stopped if it existed
logman stop $testSessionName -ets 2>$null

Write-Host "Starting trace session '$testSessionName'..."
try {
    # Start ETW session and enable the provider
    $startResult = logman start $testSessionName -p $providerGuid 0xffffffffffffffff 0xff -ets -o $traceFile -ErrorAction Continue
    
    if ($LASTEXITCODE -eq 0 -or $startResult -match "successfully") {
        Write-Host "Generating some network traffic (pinging google.com)..."
        Test-NetConnection -ComputerName google.com -InformationLevel Quiet | Out-Null
        Start-Sleep -Seconds 2
    
        Write-Host "Stopping trace session..."
        logman stop $testSessionName -ets | Out-Null
        
        if (Test-Path $traceFile) {
            $fileSize = (Get-Item $traceFile).Length
            Write-Host "Trace file created: $traceFile (Size: $fileSize bytes)"
            
            Write-Host "Extracting events from trace file..."
            try {
                $events = Get-WinEvent -Path $traceFile -Oldest -MaxEvents 20 -ErrorAction SilentlyContinue
                if ($events) {
                    Write-Host "Successfully captured events outside of Go!" -ForegroundColor Green
                    $events | Select-Object TimeCreated, Id, ProviderName, TaskDisplayName | Format-Table -AutoSize
                } else {
                    Write-Host "Failed to read events or no events captured in the ETL file. This indicates a system-level issue." -ForegroundColor Red
                }
            } catch {
                Write-Warning "Could not read events using Get-WinEvent: $_"
            }
        } else {
            Write-Host "Trace file was not created." -ForegroundColor Red
        }
    } else {
        Write-Host "Failed to start test trace session." -ForegroundColor Red
    }
} catch {
    Write-Warning "Error during ETW capture test: $_"
    logman stop $testSessionName -ets 2>$null
}

Write-Host "`nDiagnostics complete." -ForegroundColor Cyan
