# ETW Engine Analysis

## Summary

All three ETW engines (custom, goetw, rawsec) receive **0 events** when run as admin.
Sessions start, providers enable, ProcessTrace blocks, but callbacks are never invoked.
This document captures root cause analysis and fixes applied.

## Bugs Found and Fixed (custom engine)

### Bug 1: EVENT_TRACE_HEADER wrong size

`eventTraceHeader` was defined as `[80]byte` instead of a proper 48-byte struct.
This shifted all fields in `eventTraceLogfileW` by 32 bytes, placing `EventRecordCallback`
and `Context` at wrong offsets. OpenTraceW read zeros instead of callback pointers.

**Fix:** Replaced `[80]byte` with a properly-defined `eventTraceHeader` struct (48 bytes).
Added offset verification test (`TestEventTraceLogfileOffsets`) confirming all fields
match the Windows ABI layout.

### Bug 2: Wrong calling convention for callbacks

Used `windows.NewCallback()` (stdcall) instead of `syscall.NewCallbackCDecl()` (cdecl).
ETW callbacks use cdecl calling convention. On 64-bit Windows both conventions produce
identical machine code (x64 has one calling convention), but cdecl is required on 32-bit
and is what both goetw and rawsec libraries use.

**Fix:** Changed to `syscall.NewCallbackCDecl()` for both `EventRecordCallback` and
`BufferCallback`.

### Bug 3: Missing BufferCallback

Both goetw and rawsec set a `BufferCallback` that returns 1 (continue processing).
The custom engine had no BufferCallback. While the docs say it's optional, both
established libraries set it.

**Fix:** Added `bufferCallbackTrampoline` that returns 1.

## Struct Layout Verification

After fixes, all offsets verified against Windows x64 ABI:

| Field               | Expected Offset | Verified |
|---------------------|-----------------|----------|
| LogFileName         | 0               | yes      |
| LoggerName          | 8               | yes      |
| CurrentTime         | 16              | yes      |
| BuffersRead         | 24              | yes      |
| Union1              | 28              | yes      |
| CurrentEvent        | 32              | yes      |
| LogfileHeader       | 120             | yes      |
| BufferCallback      | 400             | yes      |
| BufferSize          | 408             | yes      |
| Filled              | 412             | yes      |
| EventsLost          | 416             | yes      |
| EventRecordCallback | 424             | yes      |
| IsKernelTrace       | 432             | yes      |
| Context             | 440             | yes      |
| Total size          | 448             | yes      |

## Unsolved: All Engines Get 0 Events

Even after fixing the custom engine bugs above, there may still be 0 events.
Reason: the goetw and rawsec libraries have **correct** struct layouts, correct cdecl
callbacks, correct LockOSThread usage, and ALSO get 0 events on this machine.

### What works correctly (all engines)

- `StartTraceW` returns success, valid session handle
- `EnableTraceEx2` returns success (provider enabled)
- `OpenTraceW` returns valid trace handle
- `ProcessTrace` blocks (waiting for events)
- Probe generates real TCP/UDP/HTTP traffic during test

### Possible causes for 0 events

1. **Windows security policy or audit configuration** - Group Policy or Windows Defender
   Application Control may restrict which processes can receive kernel ETW events,
   even with admin privileges. Check: `auditpol /get /subcategory:"Filtering Platform Connection"`.

2. **ETW session limit reached** - Windows limits concurrent ETW sessions (typically 64).
   If many sessions exist from prior crashed tests, new sessions might not receive
   events. Check: `logman query -ets` to list active sessions.

3. **Provider not registered** - The Microsoft-Windows-Kernel-Network provider might
   not be registered on this Windows build. Check: `logman query providers | findstr Kernel-Network`.

4. **Antivirus/EDR interference** - Some endpoint security products hook into ETW
   and can intercept or redirect events from kernel providers.

5. **Windows version regression** - Behavior of real-time kernel network ETW may
   have changed in newer Windows builds. The provider GUID and event schemas are
   documented for Windows 10+.

6. **Admin elevation level** - Running as admin might not be sufficient. Some kernel
   ETW providers require `SeSystemProfilePrivilege` or membership in
   `Performance Log Users` group. Try running from an elevated command prompt
   (Run as Administrator).

### Diagnostic steps to try

```powershell
# 1. Check if provider is registered
logman query providers "Microsoft-Windows-Kernel-Network"

# 2. List active ETW sessions (check for conflicts)
logman query -ets

# 3. Try xperf/tracelog to verify provider works outside Go
tracelog -start MyTest -guid #7DD42A49-5329-4832-8DFD-43D979153A88 -rt -level 5
tracelog -stop MyTest

# 4. Check Windows build
winver

# 5. Clean up orphaned sessions
logman query -ets | findstr NetWinMon
logman stop <session_name> -ets
```

## Architecture

```
internal/etw/custom/
  doc.go           - Package docs, domain concepts
  structs.go       - Win32 ETW structures with verified offsets
  syscall.go       - advapi32.dll proc bindings
  event.go         - Raw UserData parsing for Kernel-Network events
  engine.go        - etw.Engine implementation
  engine_test.go   - Unit tests (struct sizes, offsets, event parsing)
  integration_test.go - Admin-required integration test
```

The custom engine uses NO third-party ETW libraries. Only `golang.org/x/sys/windows`
and direct advapi32.dll syscalls. This makes the entire ETW pipeline transparent
and debuggable.
