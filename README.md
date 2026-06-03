# Netwinmon

Windows-only network activity monitor for a single executable.

## Features
- **Process Wait**: Waits for the next process instance of a target executable.
- **Dual Engines**:
  - **ETW (Primary)**: Captures real-time connection events via `Microsoft-Windows-Kernel-Network` provider. Shows exact remote UDP endpoints.
  - **Polling (Fallback)**: Periodically queries TCP/UDP state tables via IP Helper API. Used if running without admin rights or if ETW fails.
- **Endpoint Aggregation**: Groups connection events by remote endpoint (IP and Port) to show where the process connected and how often.
- **HTTP Inference**: Marks connections as HTTP based on port metadata (80 or 8080).
- **Detailed Logging**: Writes granular internal logs to aid in troubleshooting missing connections.

## CLI Usage
Must run in elevated PowerShell or command prompt (Administrator privileges required for full ETW features).

```cmd
netwinmon.exe <path-to-target-executable> <path-to-report-json> <path-to-monitor-log>
```

### Arguments
1. `<path-to-target-executable>`: Executable name (e.g. `probe.exe`) or absolute path to monitor.
2. `<path-to-report-json>`: Output path for the aggregated endpoint report.
3. `<path-to-monitor-log>`: Output path for detailed monitor logs.

### Example
```cmd
netwinmon.exe C:\tools\probe.exe report.json monitor.log
```

## Report Format (report.json)
```json
{
  "pid": 1234,
  "path": "C:\\tools\\probe.exe",
  "start_time": "2026-06-03T10:00:00Z",
  "end_time": "2026-06-03T10:00:10Z",
  "engine": "etw",
  "tcp_connections": [
    {
      "remote_address": "8.8.8.8",
      "remote_port": 80,
      "first_seen": "2026-06-03T10:00:02Z",
      "last_seen": "2026-06-03T10:00:08Z",
      "count": 5,
      "inferred_http": true,
      "states": {
        "CONNECT": 1,
        "SEND": 2,
        "RECEIVE": 2
      }
    }
  ],
  "udp_endpoints": [
    {
      "remote_address": "8.8.8.8",
      "remote_port": 53,
      "first_seen": "2026-06-03T10:00:02Z",
      "last_seen": "2026-06-03T10:00:02Z",
      "count": 1,
      "inferred_http": false
    }
  ]
}
```

## Logging and Troubleshooting
The log file records:
- Startup parameters and privilege status.
- Which monitoring engine was loaded (ETW or Polling).
- PID detection events.
- Snap iterations, tables sizes, and matching PID records.
- ETW events decoded and filtered.
- Process exit state.

Use these logs to verify if connections were missed due to short process lifetimes or lack of admin permissions.

## Development
To test and build:
```powershell
task all
```
