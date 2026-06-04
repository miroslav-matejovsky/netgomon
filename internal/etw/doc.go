// Package etw defines the common interface and types for ETW-based network event tracing.
//
// Domain Concepts:
//   - NetworkEvent: A single observed network event (TCP or UDP) with remote/local addresses,
//     protocol, state, timestamp, and originating tool name.
//   - Engine: An interface for ETW tracing backends. Multiple implementations can run
//     concurrently, each producing NetworkEvent values on a shared channel.
//
// Design Decisions:
//   - Implementations live in sub-packages (rawsec, goetw) and are selected by the monitor.
//   - Each implementation tags events with its own tool name so the report can distinguish
//     which backend produced a given observation.
//   - The Engine interface is minimal: Start, Stop, and a channel for events.
//   - Event parsing (IP, port, event ID mapping) is shared via helpers in this package
//     since both backends use the same Microsoft-Windows-Kernel-Network provider.
package etw
