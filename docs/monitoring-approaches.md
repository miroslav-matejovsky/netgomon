# Network Monitoring Approaches on Windows

Comparison of approaches for monitoring network activity of specific processes on Windows.

## Summary

| Approach | Admin | PID Filter | Short-lived | UDP Remote | Go Lib | Complexity | Status |
|----------|-------|-----------|-------------|------------|--------|------------|--------|
| ETW Kernel-Network | YES | Post-filter | YES | YES | rawsec, goetw | Medium | **Primary** |
| IP Helper Polling | NO | YES | NO | NO | stdlib | Low | **Fallback** |
| WFP | YES | Via app path | YES | YES | None | HIGH | Not viable |
| npcap/gopacket | YES* | No (correlate) | YES | YES | gopacket | HIGH | Not viable |
| ETW PID Filter | YES | Kernel-level | YES | YES | Same | Low delta | **Future** |
| DLL Injection | YES | YES | YES | YES | None | VERY HIGH | Not viable |

## Current Implementation

### ETW (Primary Engine)

Uses `Microsoft-Windows-Kernel-Network` ETW provider via two Go libraries:
- `tekert/goetw` (primary)
- `0xrawsec/golang-etw` (fallback)

**Pros:**
- Captures every network event (connect, send, recv, disconnect)
- Sees actual remote IP:port for UDP
- Captures short-lived connections
- Real-time, event-driven (no polling gap)

**Cons:**
- Requires Administrator privileges
- All events delivered for all PIDs, filtered in userspace (overhead on busy machines)
- ETW session limit (64 max per system)

### IP Helper Polling (Fallback Engine)

Uses `GetExtendedTcpTable` / `GetExtendedUdpTable` via `iphlpapi.dll`.

**Pros:**
- No admin privileges required
- Direct PID filtering (built into API)
- Simple implementation

**Cons:**
- Misses connections that open and close between polls (< 100ms)
- UDP table only shows local endpoints, not remote IP:port
- Polling overhead (minor at 100ms interval)

## Evaluated Alternatives

### Windows Filtering Platform (WFP)

The WFP API (`fwpuclnt.dll`) provides `FwpmNetEventSubscribe0` for subscribing to network events at the Application Layer Enforcement (ALE) level.

**Why not used:**
- Requires admin privileges (same as ETW)
- No PID filter - uses app path (`FWPM_CONDITION_ALE_APP_ID`) instead
- No Go library exists - requires ~200+ lines of struct definitions and raw syscalls
- C function pointer callback bridging from Go is complex
- Only captures connect/disconnect events (no send/recv byte tracking)
- WFP monitoring sees less data than ETW for same privilege cost

### npcap/gopacket (Packet Capture)

Full packet capture at network interface level using `gopacket` library with npcap driver.

**Why not used:**
- Requires npcap installation (external dependency, not single-binary deployable)
- Requires admin privileges (or npcap group membership)
- No PID filtering at capture level - must correlate via IP Helper tables (racey for short-lived)
- High overhead on busy machines (captures ALL traffic on interface)
- Loopback capture requires special npcap adapter configuration
- AV/EDR products may interfere

### ETW PID Filter Descriptor (Future Enhancement)

The `EVENT_FILTER_TYPE_PID` filter (value `0x80000004`) passed via `ENABLE_TRACE_PARAMETERS` to `EnableTraceEx2` tells the kernel ETW infrastructure to deliver events only for specific PIDs.

**Status:** Not yet implemented. Requires investigation of whether `tekert/goetw` and `0xrawsec/golang-etw` expose the `ENABLE_TRACE_PARAMETERS` structure in their provider enable calls. If supported, this would dramatically reduce CPU overhead on busy machines by filtering at kernel level instead of userspace.

**Potential benefit:** 10-100x reduction in events processed on busy systems.

### DLL Injection / API Hooking

Inject a DLL into the target process to hook Winsock functions (WSASend, WSARecv, connect, etc.).

**Why not used:**
- Requires admin privileges
- Go cannot produce suitable injection DLLs without complex CGO setup
- AV/EDR products aggressively flag injection
- Breaks with 32/64-bit mismatches, protected processes, anti-injection hardening
- Not viable from Go without a separate C/C++ DLL component

### Other Evaluated Approaches

| Approach | Result |
|----------|--------|
| `netsh trace start` | Wraps ETW, offline only, no streaming API |
| Performance Counters (PDH) | Aggregate I/O per process, no per-connection data |
| `NtQuerySystemInformation` | Can enumerate handles but not socket endpoints |
| IP interface change notifications | Fires on interface/route changes, not connections |

## Recommendation

The current dual-engine approach (ETW primary + IP Helper polling fallback) is the best pragmatic design for this use case:

1. **ETW covers admin scenario completely** - real-time, event-driven, full TCP/UDP/IPv4/IPv6
2. **IP Helper covers non-admin scenario** - misses short-lived connections but captures long-lived ones
3. **No external dependencies** - single binary deployment
4. **Proven Go libraries** - both ETW backends are maintained

**Next improvement:** Implement ETW PID filter descriptor if library support exists, to reduce overhead on busy machines.
