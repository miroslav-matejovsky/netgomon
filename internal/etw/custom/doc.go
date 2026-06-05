// Package custom implements the etw.Engine interface using direct Win32 ETW syscalls.
//
// Domain Concepts:
//   - This is a zero-external-dependency ETW backend. Uses only golang.org/x/sys/windows
//     and direct advapi32.dll calls (StartTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace).
//   - Specialized for Microsoft-Windows-Kernel-Network provider only. Not a general ETW library.
//   - Parses EVENT_RECORD.UserData directly using known binary layouts for Kernel-Network events,
//     avoiding the TDH (Trace Data Helper) dependency entirely.
//
// Design Decisions:
//   - ProcessTrace runs on a locked OS thread (runtime.LockOSThread) because the Win32 callback
//     must execute on a stable thread. This is likely the root cause of failures in goetw/rawsec.
//   - Event data layouts are hardcoded per event ID. IPv4 events use 4-byte addresses,
//     IPv6 events use 16-byte addresses. Ports are in network byte order.
//   - Session names include PID and timestamp to avoid collisions.
//   - Defensive cleanup: orphan sessions are stopped before creating new ones.
//   - Admin privileges required to trace kernel providers.
package custom
