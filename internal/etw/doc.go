// Package etw defines the common interface and types for ETW-based network event tracing.
//
// Domain Concepts:
//   - NetworkEvent: A single observed network event (TCP or UDP) with PID, remote/local addresses,
//     protocol, state, timestamp, and originating tool name.
//   - Engine: An interface for ETW tracing backends. Implementations produce NetworkEvent values
//     on a channel for consumption by the monitor.
//   - PID Extraction: Shared helpers (FindPIDInMap, FindPIDInSlice) use case-insensitive key
//     matching to find PID fields in ETW EventData, handling provider-specific key variations.
//
// Design Decisions:
//   - Implementations live in sub-packages (rawsec, goetw) and are selected by the monitor.
//   - goetw is primary, rawsec is fallback. Only one backend runs per PID to avoid double-counting.
//   - Each implementation tags events with its own tool name.
//   - Event parsing (IP, port, PID, event ID mapping) is shared via helpers in this package.
//   - Diagnostic counters (total/matched/mapped/failed) are tracked per engine for troubleshooting.
package etw
