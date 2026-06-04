//go:build windows

package etw

import "time"

// NetworkEvent represents a single network event captured by an ETW engine.
type NetworkEvent struct {
	PID        uint32
	RemoteIP   string
	RemotePort uint16
	LocalIP    string
	LocalPort  uint16
	IsUDP      bool
	State      string
	Timestamp  time.Time
	Tool       string // identifies which ETW backend produced this event
}

// Engine is the interface all ETW tracing backends must implement.
type Engine interface {
	// Start begins consuming ETW events. Events are sent to the channel
	// returned by Events(). Must be called before Events() produces data.
	Start() error

	// Stop terminates the ETW session and closes the events channel.
	Stop()

	// Events returns a read-only channel of captured network events.
	Events() <-chan NetworkEvent
}
