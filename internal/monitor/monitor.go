//go:build windows

package monitor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
	"github.com/miroslav-matejovsky/netwinmon/internal/etw/goetw"
	"github.com/miroslav-matejovsky/netwinmon/internal/etw/rawsec"
	"github.com/miroslav-matejovsky/netwinmon/internal/iphelper"
	"golang.org/x/sys/windows"
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
		knownPIDs, err = m.findCurrentPIDs()
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

		current, err := m.findCurrentPIDs()
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

func (m *Monitor) findCurrentPIDs() (map[uint32]string, error) {
	pids := make(map[uint32]string)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	for {
		pHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if err == nil {
			var buf [1024]uint16
			size := uint32(len(buf))
			err = windows.QueryFullProcessImageName(pHandle, 0, &buf[0], &size)
			_ = windows.CloseHandle(pHandle)
			if err == nil {
				procPath := windows.UTF16ToString(buf[:size])
				if m.matchAny(procPath) {
					pids[entry.ProcessID] = procPath
				}
			}
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return pids, nil
}

func (m *Monitor) matchAny(procPath string) bool {
	for _, target := range m.TargetExes {
		if matchTarget(target, procPath) {
			return true
		}
	}
	return false
}

func matchTarget(target, procPath string) bool {
	absTarget, err := filepath.Abs(target)
	if err == nil {
		absTarget = filepath.Clean(absTarget)
		absProc := filepath.Clean(procPath)
		if strings.EqualFold(absProc, absTarget) {
			return true
		}
	}
	if !strings.ContainsAny(target, `/\`) {
		targetBase := filepath.Base(target)
		procBase := filepath.Base(procPath)
		if strings.EqualFold(procBase, targetBase) {
			return true
		}
	}
	return false
}

func (m *Monitor) monitorPID(ctx context.Context, pid uint32, path string, slogLogger *slog.Logger) {
	m.logger.Info("Opening handle to target", "pid", pid)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		m.logger.Warn("Failed to open process handle", "pid", pid, "error", err)
		return
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	var startTime time.Time
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		startTime = filetimeToTime(creationTime)
		m.logger.Info("Process creation time", "pid", pid, "time", startTime.UTC().Format(time.RFC3339))
	} else {
		startTime = time.Now()
		m.logger.Warn("Failed to get process times, using current time", "pid", pid, "error", err)
	}

	// Per-process aggregation maps.
	tcpMap := make(map[string]*TCPEndpointRecord)
	udpMap := make(map[string]*UDPEndpointRecord)

	m.mu.Lock()
	m.activeProcesses[pid] = &ProcessState{
		PID:       pid,
		Path:      path,
		StartTime: startTime,
		TCP:       tcpMap,
		UDP:       udpMap,
	}
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.activeProcesses, pid)
		m.mu.Unlock()
	}()

	// Start ETW engine for this PID (or use injected mock).
	var engines []etwapi.Engine
	var engineNames []string
	usePolling := false

	if len(m.engines) > 0 {
		engines = m.engines
		for _, eng := range engines {
			_ = eng.Start()
			engineNames = append(engineNames, "mock")
		}
		m.logger.Info("Using injected mock engines for testing", "pid", pid)
	} else {
		// Try goetw first (primary), fall back to rawsec if it fails.
		goetwEng := goetw.New(ctx, pid, slogLogger)
		if err := goetwEng.Start(); err == nil {
			engines = append(engines, goetwEng)
			engineNames = append(engineNames, "goetw")
			m.logger.Info("goetw ETW engine started", "pid", pid)
		} else {
			m.logger.Warn("goetw ETW engine failed, trying rawsec...", "pid", pid, "error", err)
			rawsecEng := rawsec.New(ctx, pid, slogLogger)
			if err := rawsecEng.Start(); err == nil {
				engines = append(engines, rawsecEng)
				engineNames = append(engineNames, "rawsec")
				m.logger.Info("rawsec ETW engine started", "pid", pid)
			} else {
				m.logger.Warn("rawsec ETW engine failed", "pid", pid, "error", err)
			}
		}
	}

	if len(engines) == 0 {
		usePolling = true
		engineNames = append(engineNames, "polling")
		m.logger.Info("No ETW engines, using polling fallback", "pid", pid)
	}

	// Fan-in from engine channels.
	var fanWg sync.WaitGroup
	for _, eng := range engines {
		fanWg.Add(1)
		go func(ch <-chan etwapi.NetworkEvent) {
			defer fanWg.Done()
			for ev := range ch {
				m.handleNetworkEvent(ev, tcpMap, udpMap)
			}
		}(eng.Events())
	}

	m.logger.Info("Monitoring network activity", "pid", pid, "engines", engineNames)

	// Polling snap helper.
	snap := func() {
		if !usePolling {
			return
		}
		nowStr := time.Now().UTC().Format(time.RFC3339)

		if tConns, err := iphelper.GetTCPConnections(); err == nil {
			matchCount := 0
			for _, conn := range tConns {
				if conn.PID == pid {
					matchCount++
					key := fmt.Sprintf("polling:%s:%d", conn.RemoteIP, conn.RemotePort)
					m.mu.Lock()
					if rec, ok := tcpMap[key]; ok {
						rec.LastSeen = nowStr
						rec.Count++
						rec.States[conn.State]++
					} else {
						tcpMap[key] = &TCPEndpointRecord{
							RemoteAddress: conn.RemoteIP.String(),
							RemotePort:    conn.RemotePort,
							FirstSeen:     nowStr,
							LastSeen:      nowStr,
							Count:         1,
							InferredHTTP:  inferHTTP(0, conn.RemotePort),
							States:        map[string]int{conn.State: 1},
							Tool:          "polling",
						}
					}
					m.mu.Unlock()
				}
			}
			m.logger.Debug("Polling TCP", "pid", pid, "total", len(tConns), "matched", matchCount)
		} else {
			m.logger.Error("Polling TCP error", "pid", pid, "error", err)
		}

		if uEps, err := iphelper.GetUDPEndpoints(); err == nil {
			matchCount := 0
			for _, ep := range uEps {
				if ep.PID == pid {
					matchCount++
					remoteIP := "0.0.0.0"
					if ep.LocalIP.To4() == nil {
						remoteIP = "::"
					}
					key := fmt.Sprintf("polling:%s:0", remoteIP)
					m.mu.Lock()
					if rec, ok := udpMap[key]; ok {
						rec.LastSeen = nowStr
						rec.Count++
					} else {
						udpMap[key] = &UDPEndpointRecord{
							RemoteAddress: remoteIP,
							RemotePort:    0,
							FirstSeen:     nowStr,
							LastSeen:      nowStr,
							Count:         1,
							InferredHTTP:  inferHTTP(0, 0),
							Tool:          "polling",
						}
					}
					m.mu.Unlock()
				}
			}
			m.logger.Debug("Polling UDP", "pid", pid, "total", len(uEps), "matched", matchCount)
		} else {
			m.logger.Error("Polling UDP error", "pid", pid, "error", err)
		}
	}

	// Wait for process to exit.
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled", "pid", pid)
			goto done
		default:
		}

		snap()

		event, err := windows.WaitForSingleObject(h, 0)
		if err == nil && event == windows.WAIT_OBJECT_0 {
			m.logger.Info("Process exit detected", "pid", pid)
			break
		}

		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled", "pid", pid)
			goto done
		case <-time.After(m.Interval):
		}
	}

done:
	// Final polling sweep.
	snap()

	// Give ETW a moment to flush.
	time.Sleep(500 * time.Millisecond)

	for _, eng := range engines {
		eng.Stop()
	}
	fanWg.Wait()

	m.mu.RLock()
	tcpCount := len(tcpMap)
	udpCount := len(udpMap)
	m.mu.RUnlock()
	m.logger.Info("Monitoring complete", "pid", pid, "tcp", tcpCount, "udp", udpCount)
}

// handleNetworkEvent aggregates a single ETW network event into the maps.
func (m *Monitor) handleNetworkEvent(ev etwapi.NetworkEvent, tcpMap map[string]*TCPEndpointRecord, udpMap map[string]*UDPEndpointRecord) {
	nowStr := ev.Timestamp.UTC().Format(time.RFC3339)
	key := fmt.Sprintf("%s:%s:%d", ev.Tool, ev.RemoteIP, ev.RemotePort)

	m.mu.Lock()
	defer m.mu.Unlock()

	if ev.IsUDP {
		if rec, ok := udpMap[key]; ok {
			rec.LastSeen = nowStr
			rec.Count++
		} else {
			udpMap[key] = &UDPEndpointRecord{
				RemoteAddress: ev.RemoteIP,
				RemotePort:    ev.RemotePort,
				FirstSeen:     nowStr,
				LastSeen:      nowStr,
				Count:         1,
				InferredHTTP:  inferHTTP(0, ev.RemotePort),
				Tool:          ev.Tool,
			}
		}
	} else {
		if rec, ok := tcpMap[key]; ok {
			rec.LastSeen = nowStr
			rec.Count++
			rec.States[ev.State]++
			if ev.State == "CONNECT_FAIL" {
				rec.FailedConnections++
			}
		} else {
			failed := 0
			if ev.State == "CONNECT_FAIL" {
				failed = 1
			}
			tcpMap[key] = &TCPEndpointRecord{
				RemoteAddress:     ev.RemoteIP,
				RemotePort:        ev.RemotePort,
				FirstSeen:         nowStr,
				LastSeen:          nowStr,
				Count:             1,
				InferredHTTP:      inferHTTP(0, ev.RemotePort),
				States:            map[string]int{ev.State: 1},
				Tool:              ev.Tool,
				FailedConnections: failed,
			}
		}
	}
}

func inferHTTP(localPort, remotePort uint16) bool {
	return localPort == 80 || localPort == 8080 || remotePort == 80 || remotePort == 8080
}

func filetimeToTime(ft windows.Filetime) time.Time {
	intervals := (int64(ft.HighDateTime) << 32) | int64(ft.LowDateTime)
	secs := intervals / 10000000
	nsecs := (intervals % 10000000) * 100
	unixSecs := secs - 11644473600
	return time.Unix(unixSecs, nsecs)
}
