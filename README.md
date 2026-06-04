# Netwinmon

Windows-only network activity monitor for target executables.

## Features
- **Multi-Process Monitoring**: Monitor multiple executables concurrently.
- **Dual Engines**:
  - **ETW (Primary)**: Captures real-time connection events via `Microsoft-Windows-Kernel-Network` provider. Shows exact remote UDP endpoints. Uses goetw (primary) with rawsec fallback.
  - **Polling (Fallback)**: Periodically queries TCP/UDP state tables via IP Helper API. Used automatically if running without admin rights or if ETW fails.
- **Endpoint Aggregation**: Groups connection events by remote endpoint (IP and Port).
- **Behavior Analysis**: Tracks connection failures and event frequency (events/minute).
- **HTTP API**: Real-time state query via `GET /state` and `GET /state/{pid}`.
- **HTTP Inference**: Marks connections as HTTP based on port metadata (80 or 8080).
- **Detailed Logging**: Diagnostic counters and event dumps for troubleshooting.
- **Graceful Degradation**: No hard admin gate - ETW attempted, polling fallback automatic.

## CLI Usage

```cmd
netwinmon.exe <path-to-target-executable> <path-to-report-json> <path-to-monitor-log>
```

### Arguments
1. `<path-to-target-executable>`: Executable name (e.g. `probe.exe`) or absolute path to monitor.
2. `<path-to-report-json>`: Output path for the aggregated endpoint report.
3. `<path-to-monitor-log>`: Output path for detailed monitor logs.

### Example
```cmd
netwinmon.exe probe.exe report.json monitor.log
```

## API Endpoints
- `GET /state` - Returns JSON snapshot of all monitored processes.
- `GET /state/{pid}` - Returns JSON snapshot of a single monitored process.

## Report Format (report.json)
```json
{
  "generated_at": "2026-06-03T10:00:10Z",
  "processes": [
    {
      "pid": 1234,
      "path": "C:\\tools\\probe.exe",
      "start_time": "2026-06-03T10:00:00Z",
      "tcp_connections": [
        {
          "remote_address": "8.8.8.8",
          "remote_port": 80,
          "first_seen": "2026-06-03T10:00:02Z",
          "last_seen": "2026-06-03T10:00:08Z",
          "count": 5,
          "inferred_http": true,
          "states": {"CONNECT": 1, "SEND": 2, "RECEIVE": 2},
          "tool": "goetw",
          "failed_connections": 0,
          "event_frequency_per_min": 50.0
        }
      ],
      "udp_endpoints": [
        {
          "remote_address": "8.8.8.8",
          "remote_port": 53,
          "first_seen": "2026-06-03T10:00:02Z",
          "last_seen": "2026-06-03T10:00:02Z",
          "count": 1,
          "inferred_http": false,
          "tool": "goetw",
          "event_frequency_per_min": 1.0
        }
      ]
    }
  ]
}
```

## Architecture

See [docs/monitoring-approaches.md](docs/monitoring-approaches.md) for comparison of network monitoring approaches.

## Logging and Troubleshooting
The log file records:
- Startup parameters and privilege status.
- Which monitoring engine was loaded (ETW or Polling).
- PID detection events.
- ETW diagnostic counters (total/matched/mapped/failed).
- First N event samples with full field dumps.
- Process exit state.

## Development
To test and build:
```powershell
task all
```
