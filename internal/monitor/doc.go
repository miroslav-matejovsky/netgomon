// Package monitor provides Windows-specific network activity monitoring for target processes.
//
// Domain Concepts:
//   - Process Discovery: Polls running processes using toolhelp snapshots to find target binaries.
//     Supports multiple target executables monitored concurrently.
//   - Connection Tracking: Snaps TCP and UDP tables (polling fallback) or consumes kernel trace events (ETW).
//   - Endpoint Aggregation: Groups network events by remote endpoint (IP and port) to show where connections went and how often.
//   - Multi-Engine: Supports ETW backends (custom primary, goetw/rawsec fallback). Each record is tagged with a "tool" field.
//   - Behavior Analysis: Tracks connection failures (CONNECT_FAIL) and calculates event frequency (events/minute).
//
// Design Decisions & Tradeoffs:
//   - Multi-Process: Monitor.Run() continuously scans for target processes and spawns a goroutine per PID.
//     Each PID has its own aggregation maps and process lifetime watcher.
//   - Single ETW Backend: Uses custom engine (direct Win32 syscalls) as primary, falls back to goetw then rawsec.
//     Avoids double-counting events from the same provider.
//   - Fallback Engine (Polling): Automatically falls back to IP Helper tables if no ETW engines start.
//   - Thread Safety: A sync.RWMutex on Monitor protects aggregation maps and activeProcesses.
//   - Report: Multi-process report written atomically by a single writer goroutine.
//   - Admin Gate: No hard admin gate. Monitor starts, attempts ETW, falls back gracefully.
//   - Tradeoff (Polling vs ETW): Polling misses short-lived/transient connections. ETW captures every event but requires admin.
//   - Tradeoff (UDP Remote Endpoints): Polling only has local bindings. ETW provides actual remote IP and port.
package monitor
