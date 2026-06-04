// Package monitor provides Windows-specific network activity monitoring for a target process.
//
// Domain Concepts:
//   - Process Discovery: Polls running processes using toolhelp snapshots to find the target binary.
//   - Connection Tracking: Snaps TCP and UDP tables (polling fallback) or consumes kernel trace events (ETW).
//   - Endpoint Aggregation: Groups network events by remote endpoint (IP and port) to show where connections went and how often.
//   - Multi-Engine: Supports running multiple ETW backends simultaneously (rawsec, goetw). Each record is tagged with a "tool" field identifying which backend produced it.
//
// Design Decisions & Tradeoffs:
//   - ETW Engines: Uses the etw.Engine interface (internal/etw) with implementations in rawsec and goetw sub-packages. Both are started if possible; events are merged via fan-in goroutines.
//   - Fallback Engine (Polling): Automatically falls back to IP Helper tables if no ETW engines start (e.g., lacks administrative rights).
//   - Thread Safety: A sync.RWMutex on Monitor protects aggregation maps since ETW events arrive on background goroutines.
//   - Tool Tag: Each endpoint record carries a "tool" field so the report distinguishes which ETW backend (or polling) observed a connection.
//   - Tradeoff (Polling vs ETW): Polling does not miss long-lived connections but can miss short-lived/transient connections. ETW captures every event but requires administrator privileges.
//   - Tradeoff (UDP Remote Endpoints): In polling fallback, Windows UDP table only contains local bindings, so UDP remote endpoints are wildcards. ETW provides the actual remote IP and port for UDP sends and receives.
package monitor
