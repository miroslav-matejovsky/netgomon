//go:build windows

package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miroslav-matejovsky/netwinmon/internal/monitor"
	"github.com/miroslav-matejovsky/netwinmon/internal/pid"
	"github.com/miroslav-matejovsky/netwinmon/internal/report"
)

type Engine struct {
	TargetExes []string
	ReportPath string
	LogPath    string
	Interval   time.Duration
	NewOnly    bool

	logger   *slog.Logger
	mu       sync.RWMutex
	monitors map[uint32]*monitor.Monitor
}

func NewEngine(targetExes []string, reportPath, logPath string, interval time.Duration, newOnly bool) *Engine {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &Engine{
		TargetExes: targetExes,
		ReportPath: reportPath,
		LogPath:    logPath,
		Interval:   interval,
		NewOnly:    newOnly,
		monitors:   make(map[uint32]*monitor.Monitor),
	}
}

func (e *Engine) Run(ctx context.Context) error {
	dir := filepath.Dir(e.LogPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	f, err := os.OpenFile(e.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = f.Close() }()

	e.logger = slog.New(slog.NewTextHandler(io.MultiWriter(os.Stdout, f), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	e.logger.Info("Netwinmon session started", "targets", e.TargetExes, "report", e.ReportPath, "log", e.LogPath)

	var knownPIDs map[uint32]string
	if e.NewOnly {
		e.logger.Info("NewOnly mode: scanning running processes to exclude existing instances...")
		knownPIDs, err = pid.FindMatching(e.TargetExes)
		if err != nil {
			return fmt.Errorf("failed listing current processes: %w", err)
		}
		e.logger.Info("Excluding already running instances", "count", len(knownPIDs))
	} else {
		knownPIDs = make(map[uint32]string)
		e.logger.Info("Monitoring existing and new process instances.")
	}

	monitoredPIDs := make(map[uint32]bool)
	for p := range knownPIDs {
		monitoredPIDs[p] = true
	}

	var wg sync.WaitGroup

	if err := e.writeReport(); err != nil {
		e.logger.Warn("Failed to write initial report", "error", err)
	}

	e.logger.Info("Scanning for target processes... Press Ctrl+C to abort.")

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(e.Interval):
				if err := e.writeReport(); err != nil {
					e.logger.Debug("Failed to write continuous report", "error", err)
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("Engine cancelled by user (signal).")
			goto cleanup
		default:
		}

		current, err := pid.FindMatching(e.TargetExes)
		if err != nil {
			e.logger.Warn("Failed to scan processes", "error", err)
		} else {
			for p, path := range current {
				if monitoredPIDs[p] {
					continue
				}
				monitoredPIDs[p] = true
				e.logger.Info("Found target process", "pid", p, "path", path)

				mon := monitor.NewMonitor(p, path, e.Interval, e.logger)
				e.mu.Lock()
				e.monitors[p] = mon
				e.mu.Unlock()

				wg.Add(1)
				go func(m *monitor.Monitor, pID uint32) {
					defer wg.Done()
					_ = m.Run(ctx)
					e.mu.Lock()
					delete(e.monitors, pID)
					e.mu.Unlock()
				}(mon, p)
			}
		}

		select {
		case <-ctx.Done():
			e.logger.Info("Engine cancelled by user (signal).")
			goto cleanup
		case <-time.After(e.Interval):
		}
	}

cleanup:
	wg.Wait()

	if err := e.writeReport(); err != nil {
		e.logger.Error("Failed to write final report", "error", err)
	} else {
		e.logger.Info("Final report written.")
	}

	return nil
}

func (e *Engine) GetReport() report.Report {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var processes []report.ProcessReport
	for _, mon := range e.monitors {
		if pr := mapToProcessReport(mon.GetState()); pr != nil {
			processes = append(processes, *pr)
		}
	}

	return report.Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Processes:   processes,
	}
}

func (e *Engine) GetProcessReport(pid uint32) *report.ProcessReport {
	e.mu.RLock()
	mon, ok := e.monitors[pid]
	e.mu.RUnlock()

	if !ok {
		return nil
	}
	return mapToProcessReport(mon.GetState())
}

func mapToProcessReport(ps *monitor.ProcessState) *report.ProcessReport {
	if ps == nil {
		return nil
	}

	pr := report.ProcessReport{
		PID:       ps.PID,
		Path:      ps.Path,
		StartTime: ps.StartTime.UTC().Format(time.RFC3339),
		Tools:     make(map[string]report.ToolStats),
	}

	// Helper to get or create ToolStats
	getToolStats := func(toolName string) report.ToolStats {
		if ts, ok := pr.Tools[toolName]; ok {
			return ts
		}
		return report.ToolStats{
			TCPConnections: []report.TCPEndpointRecord{},
			UDPEndpoints:   []report.UDPEndpointRecord{},
		}
	}

	for _, rec := range ps.TCP {
		ts := getToolStats(rec.Tool)
		ts.TCPConnections = append(ts.TCPConnections, report.TCPEndpointRecord{
			RemoteAddress:     rec.RemoteAddress,
			RemotePort:        rec.RemotePort,
			FirstSeen:         rec.FirstSeen,
			LastSeen:          rec.LastSeen,
			Count:             rec.Count,
			InferredHTTP:      rec.InferredHTTP,
			States:            rec.States,
			Tool:              rec.Tool,
			FailedConnections: rec.FailedConnections,
			EventFrequency:    report.CalcFrequency(rec.FirstSeen, rec.LastSeen, rec.Count),
		})
		pr.Tools[rec.Tool] = ts
	}

	for _, rec := range ps.UDP {
		ts := getToolStats(rec.Tool)
		ts.UDPEndpoints = append(ts.UDPEndpoints, report.UDPEndpointRecord{
			RemoteAddress:  rec.RemoteAddress,
			RemotePort:     rec.RemotePort,
			FirstSeen:      rec.FirstSeen,
			LastSeen:       rec.LastSeen,
			Count:          rec.Count,
			InferredHTTP:   rec.InferredHTTP,
			Tool:           rec.Tool,
			EventFrequency: report.CalcFrequency(rec.FirstSeen, rec.LastSeen, rec.Count),
		})
		pr.Tools[rec.Tool] = ts
	}

	return &pr
}

func (e *Engine) writeReport() error {
	rep := e.GetReport()
	return report.Write(e.ReportPath, rep)
}
