# Scripts

This directory contains PowerShell wrapper scripts for network monitoring and enforcement.

## Scripts

### [Invoke-NetworkMonitorProcess.ps1](file:///C:/dev/personal/netwinmon/scripts/Invoke-NetworkMonitorProcess.ps1)

Wraps an executable and monitors its outbound network connections. It:
- Applies no network restrictions.
- Configures Windows Firewall profile logging.
- Optionally starts WFP diagnostic captures.
- Optionally logs TCP connection snapshots.

### [Invoke-NetworkEnforceProcess.ps1](file:///C:/dev/personal/netwinmon/scripts/Invoke-NetworkEnforceProcess.ps1)

Wraps an executable and restricts its outbound network connections to approved addresses and ports. It:
- Creates a temporary block-all-outbound rule for the target executable.
- Adds explicit outbound allow rules for approved remote IP/port combinations.
- Configures Windows Firewall profile logging, WFP capture, and TCP snapshots.
- Removes temporary firewall rules on exit.
