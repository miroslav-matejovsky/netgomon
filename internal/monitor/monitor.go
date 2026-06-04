//go:build windows

package monitor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
	"github.com/miroslav-matejovsky/netwinmon/internal/pid"
)

// Monitor monitors target executables' network activity.
type Monitor struct {
	TargetExes []string
	ReportPath string
	LogPath    string
	Interval   time.Duration
	NewOnly    bool // if true, only monitor newly started processes

	logger  *slog.Logger
	mu      sync.RWMutex
	engines []etwapi.Engine

	activeProcesses map[uint32]*ProcessState
}

// ProcessState represents the real-time state of a monitored process.
type ProcessState struct {
	PID       uint32                        `json:"pid"`
	Path      string                        `json:"path"`
	StartTime time.Time                     `json:"startTime"`
	TCP       map[string]*TCPEndpointRecord `json:"tcp"`
	UDP       map[string]*UDPEndpointRecord `json:"udp"`
}

// NewMonitor creates a Monitor instance. Accepts one or more target executables.
func NewMonitor(targetExes []string, reportPath, logPath string, interval time.Duration, engines ...etwapi.Engine) *Monitor {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &Monitor{
		TargetExes:      targetExes,
		ReportPath:      reportPath,
		LogPath:         logPath,
		Interval:        interval,
		engines:         engines,
		activeProcesses: make(map[uint32]*ProcessState),
	}
}

// GetState returns a snapshot of all active process states.
func (m *Monitor) GetState() map[uint32]*ProcessState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state := make(map[uint32]*ProcessState)
	for pid, ps := range m.activeProcesses {
		pCopy := &ProcessState{
			PID:       ps.PID,
			Path:      ps.Path,
			StartTime: ps.StartTime,
			TCP:       make(map[string]*TCPEndpointRecord),
			UDP:       make(map[string]*UDPEndpointRecord),
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
		state[pid] = pCopy
	}
	return state
}

// GetProcessState returns a snapshot of a single process state, or nil if not found.
func (m *Monitor) GetProcessState(pid uint32) *ProcessState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ps, ok := m.activeProcesses[pid]
	if !ok {
		return nil
	}

	pCopy := &ProcessState{
		PID:       ps.PID,
		Path:      ps.Path,
		StartTime: ps.StartTime,
		TCP:       make(map[string]*TCPEndpointRecord),
		UDP:       make(map[string]*UDPEndpointRecord),
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

// Run continuously scans for target processes and monitors them.
func (m *Monitor) Run(ctx context.Context) error {
	dir := filepath.Dir(m.LogPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	f, err := os.OpenFile(m.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = f.Close() }()

	m.logger = slog.New(slog.NewTextHandler(io.MultiWriter(os.Stdout, f), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	m.logger.Info("Netwinmon session started", "targets", m.TargetExes, "report", m.ReportPath, "log", m.LogPath)
	m.logger.Info("Checking administrative status...")

	// Determine initial known PIDs.
	var knownPIDs map[uint32]string
	if m.NewOnly {
		m.logger.Info("NewOnly mode: scanning running processes to exclude existing instances...")
		knownPIDs, err = pid.FindMatching(m.TargetExes)
		if err != nil {
			return fmt.Errorf("failed listing current processes: %w", err)
		}
		m.logger.Info("Excluding already running instances", "count", len(knownPIDs))
	} else {
		knownPIDs = make(map[uint32]string)
		m.logger.Info("Monitoring existing and new process instances.")
	}

	// Track which PIDs we've already started monitoring.
	monitoredPIDs := make(map[uint32]bool)
	for pid := range knownPIDs {
		monitoredPIDs[pid] = true
	}

	var wg sync.WaitGroup

	// Write initial empty report.
	if err := m.writeReport(); err != nil {
		m.logger.Warn("Failed to write initial report", "error", err)
	}

	m.logger.Info("Scanning for target processes... Press Ctrl+C to abort.")

	// Report writer goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(m.Interval):
				if err := m.writeReport(); err != nil {
					m.logger.Debug("Failed to write continuous report", "error", err)
				}
			}
		}
	}()

	// Main scanner loop.
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled by user (signal).")
			goto cleanup
		default:
		}

		current, err := pid.FindMatching(m.TargetExes)
		if err != nil {
			m.logger.Warn("Failed to scan processes", "error", err)
		} else {
			for pid, path := range current {
				if monitoredPIDs[pid] {
					continue
				}
				monitoredPIDs[pid] = true
				m.logger.Info("Found target process", "pid", pid, "path", path)

				wg.Add(1)
				go func(p uint32, pPath string) {
					defer wg.Done()
					m.monitorPID(ctx, p, pPath, m.logger)
				}(pid, path)
			}
		}

		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled by user (signal).")
			goto cleanup
		case <-time.After(m.Interval):
		}
	}

cleanup:
	// Wait for all monitoring goroutines to finish.
	wg.Wait()

	// Write final report.
	if err := m.writeReport(); err != nil {
		m.logger.Error("Failed to write final report", "error", err)
	} else {
		m.logger.Info("Final report written.")
	}

	return nil
}
