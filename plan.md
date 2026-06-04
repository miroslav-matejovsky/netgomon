# Netwinmon Enhancement Plan

This document outlines the verifiable steps to enhance `netwinmon` into an active, multi-process network monitoring tool with an HTTP API and behavior analysis, as well as fixing the current bug where only 2 out of 3 connections are reported.

## Step 1: Bugfix - Capture All Network Connections
**Goal**: Ensure all 3 connections (HTTP, TCP, UDP) initiated by the probe are properly captured and reported.
- **Analysis**: The `probe` makes three connections: HTTP (port 80 to example.com), TCP (port 80 to google.com), and UDP (port 53 to 8.8.8.8). Currently, only 2 connections appear in the logs/report. The `testTCP` function dials `google.com`, which frequently resolves to an IPv6 address. `etw_windows.go` maps specific Event IDs (e.g., 10-18 for IPv4, 20-29 for IPv6), but these mappings might be incomplete or incorrect for IPv6 TCP events (e.g., TCPv6 Connect/Disconnect might be unmapped or misidentified). Additionally, `testTCP` writes and closes immediately, which might generate events that are missed if the ETW consumer drops unmapped IDs.
- **Action**:
  - Add a fallback logging mechanism in `consumer.EventCallback` to log *all* ETW events for the target PID, even if `parseEventNetworkTuple` returns empty, to identify the missing Event IDs.
  - Update `parseEventNetworkTuple` with the correct missing Event IDs for IPv6 TCP/UDP traffic (e.g., Event IDs 24/25 for TCPv6 Connect/Disconnect).
  - Ensure `parseIP` correctly extracts the IP address from IPv6 EventData structures.
- **Verification**: Run `probe` and verify `monitor.log` and `report.json` include the third missing connection (TCP to google.com or its IP).

## Step 2: Multi-Process Monitoring Support
**Goal**: Allow monitoring of multiple wrapped processes concurrently.
- **Analysis**: Currently, `Monitor.TargetExe` is a single string, and `Run()` blocks waiting for the *next* single instance of that executable. State is tied to one `TargetPID`.
- **Action**:
  - Update `Monitor` struct to accept a list of targets (e.g., `TargetExes []string`).
  - Modify `findCurrentPIDs()` to match against any executable in the list.
  - Refactor `Run()` to use a continuous scanning loop. When a new matching PID is found, spawn a new goroutine to handle monitoring for that specific PID.
  - Update the ETW Engine to use a single global ETW Session that filters events by a thread-safe map of active target PIDs, rather than creating a new ETW session per PID (which could cause conflicts or hit session limits).
- **Verification**: Run two different dummy probe executables simultaneously and confirm both are monitored concurrently, with their network activity correctly attributed to their respective PIDs.

## Step 3: Implement HTTP API for Current State
**Goal**: Expose a simple HTTP API to query the real-time state of all monitored processes.
- **Analysis**: Currently, state is only dumped to `report.json` via continuous file writes.
- **Action**:
  - Create a new `api` package (e.g., `internal/api/server.go`).
  - Define an HTTP server that exposes a `GET /state` endpoint.
  - In `monitor.go`, protect the aggregation maps with a `sync.RWMutex` and expose a `GetState()` method that returns the current combined snapshot for all active PIDs.
  - The `/state` endpoint will return JSON containing active PIDs, their paths, start times, and real-time network statistics.
- **Verification**: Start `netwinmon` with the API enabled. Run the probe, and use `curl http://localhost:8080/state` to verify the JSON response reflects the real-time network activity of the probe.

## Step 4: Basic Behavior Analysis
**Goal**: Analyze connection behavior, such as call frequency and success/failure rates.
- **Analysis**: The current reports track `Count` and `States` (e.g., `DISCONNECT`: 6). It does not explicitly track connection failures, duration, or calculate frequency.
- **Action**:
  - Enhance `TCPEndpointRecord` and `UDPEndpointRecord` to include new fields:
    - `FailedConnections` (incremented on Event ID 17 - Connect Fail, or similar IPv6 failure events).
    - `CallFrequency` (calculated dynamically as `Count` divided by the duration between `FirstSeen` and `LastSeen`, expressed as calls per minute/second).
  - Add logic in the ETW event handler to properly classify failures vs. successful connections.
  - Include these new metrics in both the `/state` HTTP API and the final `report.json`.
- **Verification**: Modify `probe` to include a test that attempts to connect to an unreachable/blackholed IP. Verify the API and report show `FailedConnections > 0` and that the `CallFrequency` is calculated correctly for all endpoints.
