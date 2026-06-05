// Package custom implements the etw.Engine interface using direct Win32 ETW syscalls.
//
// Domain Concepts:
//   - Zero-external-dependency ETW backend. Uses only golang.org/x/sys/windows
//     and direct advapi32.dll calls (StartTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace).
//   - Specialized for Microsoft-Windows-Kernel-Network provider only. Not a general ETW library.
//   - Parses EVENT_RECORD.UserData directly using known binary layouts for Kernel-Network events,
//     avoiding the TDH (Trace Data Helper) dependency entirely.
//
// Design Decisions:
//   - ProcessTrace runs on a locked OS thread (runtime.LockOSThread) because the Win32 callback
//     must execute on a stable thread.
//   - ETW callbacks use cdecl calling convention (syscall.NewCallbackCDecl). Required on 32-bit
//     Windows, matches x64 convention on 64-bit.
//   - Both EventRecordCallback and BufferCallback are registered. BufferCallback returns 1
//     to keep ProcessTrace consuming events.
//   - Struct layouts verified against Windows x64 ABI with offset tests.
//     See TestEventTraceLogfileOffsets in engine_test.go.
//   - Event data layouts hardcoded per event ID. IPv4 events use 4-byte addresses,
//     IPv6 events use 16-byte addresses. Ports in network byte order.
//   - Session names include PID and timestamp to avoid collisions.
//   - Defensive cleanup: orphan sessions stopped before creating new ones.
//   - Admin privileges required to trace kernel providers.
//
// See docs/analysis.md for full investigation of the 0-event issue affecting all ETW engines.
package custom
