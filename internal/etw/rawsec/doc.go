// Package rawsec implements the etw.Engine interface using github.com/0xrawsec/golang-etw.
//
// This is the original ETW backend. It uses RealTimeSession and RealTimeConsumer
// from the rawsec library to capture Microsoft-Windows-Kernel-Network events.
package rawsec
