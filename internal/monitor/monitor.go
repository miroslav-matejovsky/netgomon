//go:build windows

package monitor

import (
	"context"
	"fmt"
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
	"golang.org/x/sys/windows"
)

// Logger handles writing debug/info messages to the monitor log file using slog.
type Logger struct {
	file   *os.File
	logger *slog.Logger
}

// NewLogger initializes the log directory and file.
func NewLogger(path string) (*Logger, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}

	handler := slog.NewJSONHandler(f, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	return &Logger{
		file:   f,
		logger: logger,
	}, nil
}

// Info logs info level message.
func (l *Logger) Info(msg string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	formatted := formatMsg(msg, args...)
	l.logger.Info(formatted)
	fmt.Printf("[%s] INFO: %s\n", time.Now().Format("15:04:05.000"), formatted)
}

// Warn logs warn level message.
func (l *Logger) Warn(msg string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	formatted := formatMsg(msg, args...)
	l.logger.Warn(formatted)
	fmt.Printf("[%s] WARN: %s\n", time.Now().Format("15:04:05.000"), formatted)
}

// Error logs error level message.
func (l *Logger) Error(msg string, err error, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	formatted := formatMsg(msg, args...)
	l.logger.Error(formatted, "error", err)
	fmt.Printf("[%s] ERROR: %s (error: %v)\n", time.Now().Format("15:04:05.000"), formatted, err)
}

// Debug logs debug level message.
func (l *Logger) Debug(msg string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	formatted := formatMsg(msg, args...)
	l.logger.Debug(formatted)
}

func formatMsg(msg string, args ...any) string {
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

// Close closes the log file.
func (l *Logger) Close() {
	if l != nil && l.file != nil {
		_ = l.file.Close()
	}
}

// Monitor monitors target executables' network activity.
type Monitor struct {
	TargetExes []string
	ReportPath string
	LogPath    string
	Interval   time.Duration
	NewOnly    bool // if true, only monitor newly started processes

	logger  *Logger
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
	logger, err := NewLogger(m.LogPath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	m.logger = logger
	defer m.logger.Close()

	m.logger.Info("Netwinmon session started. Targets: %v, Report: %s, Log: %s", m.TargetExes, m.ReportPath, m.LogPath)
	m.logger.Info("Checking administrative status...")

	// Determine initial known PIDs.
	var knownPIDs map[uint32]string
	if m.NewOnly {
		m.logger.Info("NewOnly mode: scanning running processes to exclude existing instances...")
		knownPIDs, err = m.findCurrentPIDs()
		if err != nil {
			return fmt.Errorf("failed listing current processes: %w", err)
		}
		m.logger.Info("Excluding %d already running instances.", len(knownPIDs))
	} else {
		knownPIDs = make(map[uint32]string)
		m.logger.Info("Monitoring existing and new process instances.")
	}

	// slog logger for ETW engines.
	slogLogger := slog.New(slog.NewJSONHandler(m.logger.file, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Track which PIDs we've already started monitoring.
	monitoredPIDs := make(map[uint32]bool)
	for pid := range knownPIDs {
		monitoredPIDs[pid] = true
	}

	var wg sync.WaitGroup

	// Write initial empty report.
	if err := m.writeReport(); err != nil {
		m.logger.Warn("Failed to write initial report: %v", err)
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
					m.logger.Debug("Failed to write continuous report: %v", err)
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
			m.logger.Warn("Failed to scan processes: %v", err)
		} else {
			for pid, path := range current {
				if monitoredPIDs[pid] {
					continue
				}
				monitoredPIDs[pid] = true
				m.logger.Info("Found target process. PID: %d, Path: %s", pid, path)

				wg.Add(1)
				go func(p uint32, pPath string) {
					defer wg.Done()
					m.monitorPID(ctx, p, pPath, slogLogger)
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
		m.logger.Error("Failed to write final report", err)
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
	m.logger.Info("Opening handle to target PID %d...", pid)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		m.logger.Warn("Failed to open process handle for PID %d: %v", pid, err)
		return
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	var startTime time.Time
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		startTime = filetimeToTime(creationTime)
		m.logger.Info("PID %d creation time (UTC): %s", pid, startTime.UTC().Format(time.RFC3339))
	} else {
		startTime = time.Now()
		m.logger.Warn("Failed to get process times for PID %d: %v. Using current time.", pid, err)
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
		m.logger.Info("PID %d: Using injected mock engines for testing", pid)
	} else {
		// Try goetw first (primary), fall back to rawsec if it fails.
		goetwEng := goetw.New(pid, slogLogger)
		if err := goetwEng.Start(); err == nil {
			engines = append(engines, goetwEng)
			engineNames = append(engineNames, "goetw")
			m.logger.Info("PID %d: goetw ETW engine started", pid)
		} else {
			m.logger.Warn("PID %d: goetw ETW engine failed: %v. Trying rawsec...", pid, err)
			rawsecEng := rawsec.New(pid, slogLogger)
			if err := rawsecEng.Start(); err == nil {
				engines = append(engines, rawsecEng)
				engineNames = append(engineNames, "rawsec")
				m.logger.Info("PID %d: rawsec ETW engine started", pid)
			} else {
				m.logger.Warn("PID %d: rawsec ETW engine failed: %v", pid, err)
			}
		}
	}

	if len(engines) == 0 {
		usePolling = true
		engineNames = append(engineNames, "polling")
		m.logger.Info("PID %d: No ETW engines. Using polling fallback.", pid)
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

	m.logger.Info("PID %d: Monitoring network activity. Engines: %v", pid, engineNames)

	// Polling snap helper.
	snap := func() {
		if !usePolling {
			return
		}
		nowStr := time.Now().UTC().Format(time.RFC3339)

		if tConns, err := GetTCPConnections(); err == nil {
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
			m.logger.Debug("PID %d: Polling found %d TCP total, %d matched.", pid, len(tConns), matchCount)
		} else {
			m.logger.Error("PID %d: Polling TCP error", err)
		}

		if uEps, err := GetUDPEndpoints(); err == nil {
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
			m.logger.Debug("PID %d: Polling found %d UDP total, %d matched.", pid, len(uEps), matchCount)
		} else {
			m.logger.Error("PID %d: Polling UDP error", err)
		}
	}

	// Wait for process to exit.
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("PID %d: Monitor cancelled.", pid)
			goto done
		default:
		}

		snap()

		event, err := windows.WaitForSingleObject(h, 0)
		if err == nil && event == windows.WAIT_OBJECT_0 {
			m.logger.Info("PID %d: Process exit detected.", pid)
			break
		}

		select {
		case <-ctx.Done():
			m.logger.Info("PID %d: Monitor cancelled.", pid)
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
	m.logger.Info("PID %d: Monitoring complete. TCP endpoints: %d, UDP endpoints: %d", pid, tcpCount, udpCount)
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
