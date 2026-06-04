//go:build windows

package monitor

import (
	"log/slog"
	"sync"
	"time"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
)

// Monitor monitors a single target executable's network activity.
type Monitor struct {
	PID      uint32
	Path     string
	Interval time.Duration

	logger  *slog.Logger
	mu      sync.RWMutex
	engines []etwapi.Engine

	state *ProcessState
}

type ProcessState struct {
	PID       uint32
	Path      string
	StartTime time.Time
	TCP       map[string]*TCPEndpoint
	UDP       map[string]*UDPEndpoint
}

type TCPEndpoint struct {
	RemoteAddress     string
	RemotePort        uint16
	FirstSeen         string
	LastSeen          string
	Count             int
	InferredHTTP      bool
	States            map[string]int
	Tool              string
	FailedConnections int
}

type UDPEndpoint struct {
	RemoteAddress string
	RemotePort    uint16
	FirstSeen     string
	LastSeen      string
	Count         int
	InferredHTTP  bool
	Tool          string
}

// NewMonitor creates a Monitor instance for a single process.
func NewMonitor(pid uint32, path string, interval time.Duration, logger *slog.Logger, engines ...etwapi.Engine) *Monitor {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &Monitor{
		PID:      pid,
		Path:     path,
		Interval: interval,
		logger:   logger,
		engines:  engines,
		state: &ProcessState{
			PID:       pid,
			Path:      path,
			StartTime: time.Now(),
			TCP:       make(map[string]*TCPEndpoint),
			UDP:       make(map[string]*UDPEndpoint),
		},
	}
}

// GetState returns a snapshot of the process state.
func (m *Monitor) GetState() *ProcessState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ps := m.state
	pCopy := &ProcessState{
		PID:       ps.PID,
		Path:      ps.Path,
		StartTime: ps.StartTime,
		TCP:       make(map[string]*TCPEndpoint),
		UDP:       make(map[string]*UDPEndpoint),
	}
	for k, v := range ps.TCP {
		vCopy := *v
		if v.States != nil {
			vCopy.States = make(map[string]int)
			for sk, sv := range v.States {
				vCopy.States[sk] = sv
			}
		}
		pCopy.TCP[k] = &vCopy
	}
	for k, v := range ps.UDP {
		vCopy := *v
		pCopy.UDP[k] = &vCopy
	}
	return pCopy
}
