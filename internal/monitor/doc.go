// Package monitor provides Windows-specific network activity monitoring for a target process.
//
// Domain Concepts:
// - Process Discovery: Polls running processes using toolhelp snapshots to find the target binary.
// - Connection Tracking: Snaps TCP and UDP state tables at regular intervals.
// - State Aggregation: Groups network events by address, port, and state, tracking first/last seen times and observation counts.
//
// Design Decisions & Tradeoffs:
// - IP Helper API (iphlpapi.dll): Chosen as simplest fallback instead of ETW.
// - Tradeoff (Polling vs ETW): Polling does not miss long-lived connections but can miss short-lived/transient connections that exist only between poll intervals.
// - Tradeoff (UDP Remote Endpoints): Windows UDP table (MIB_UDPTABLE_OWNER_PID) only contains local bindings. Remote address/port for UDP is always reported as wildcard (e.g., 0.0.0.0:0).
package monitor
