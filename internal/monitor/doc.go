// Package monitor provides Windows-specific network activity monitoring for a target process.
//
// Domain Concepts:
// - Process Discovery: Polls running processes using toolhelp snapshots to find the target binary.
// - Connection Tracking: Snaps TCP and UDP tables (polling fallback) or consumes kernel trace events (ETW).
// - Endpoint Aggregation: Groups network events by remote endpoint (IP and port) to show where connections went and how often.
//
// Design Decisions & Tradeoffs:
// - Primary Engine (ETW): Uses "Microsoft-Windows-Kernel-Network" ETW trace session to capture all connection attempts, sends, and receives in real-time.
// - Fallback Engine (Polling): Automatically falls back to IP Helper tables if ETW trace session fails to start (e.g., lacks administrative rights).
// - Tradeoff (Polling vs ETW): Polling does not miss long-lived connections but can miss short-lived/transient connections. ETW captures every event but requires administrator privileges.
// - Tradeoff (UDP Remote Endpoints): In polling fallback, Windows UDP table only contains local bindings, so UDP remote endpoints are wildcards. ETW provides the actual remote IP and port for UDP sends and receives.
package monitor
