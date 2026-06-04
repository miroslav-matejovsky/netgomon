//go:build windows

// This file previously contained the ETWEngine implementation.
// That code has been refactored into internal/etw/ with sub-packages:
//   - internal/etw/rawsec/ (wraps github.com/0xrawsec/golang-etw)
//   - internal/etw/goetw/ (wraps github.com/tekert/goetw)
//
// Shared parsing logic (ParseIP, ParsePort, MapEventID) lives in internal/etw/parse.go.
// The monitor now uses the etw.Engine interface and fan-in pattern for multi-engine support.
package monitor
