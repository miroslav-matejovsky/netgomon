# Scripts

This directory contains PowerShell wrapper scripts for network monitoring and enforcement.

## Scripts

### [Invoke-NetworkMonitorProcess.ps1](file:///C:/dev/personal/netwinmon/scripts/Invoke-NetworkMonitorProcess.ps1)

Wraps an executable and monitors its outbound network connections. It:
- Applies no network restrictions.
- Configures Windows Firewall profile logging.
- Optionally starts WFP diagnostic captures.
- Optionally logs TCP connection snapshots.
