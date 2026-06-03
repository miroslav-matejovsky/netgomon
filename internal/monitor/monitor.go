//go:build windows

package monitor

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

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
	l.logger.Info(msg, args...)
	fmt.Printf("[%s] INFO: %s\n", time.Now().Format("15:04:05.000"), formatMsg(msg, args...))
}

// Warn logs warn level message.
func (l *Logger) Warn(msg string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Warn(msg, args...)
	fmt.Printf("[%s] WARN: %s\n", time.Now().Format("15:04:05.000"), formatMsg(msg, args...))
}

// Error logs error level message.
func (l *Logger) Error(msg string, err error, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	fullArgs := append([]any{"error", err}, args...)
	l.logger.Error(msg, fullArgs...)
	fmt.Printf("[%s] ERROR: %s (error: %v)\n", time.Now().Format("15:04:05.000"), formatMsg(msg, args...), err)
}

// Debug logs debug level message.
func (l *Logger) Debug(msg string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Debug(msg, args...)
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

// Monitor monitors the target executable's network activity.
type Monitor struct {
	TargetExe  string
	ReportPath string
	LogPath    string
	Interval   time.Duration
	logger     *Logger
}

// NewMonitor creates a Monitor instance.
func NewMonitor(targetExe, reportPath, logPath string, interval time.Duration) *Monitor {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &Monitor{
		TargetExe:  targetExe,
		ReportPath: reportPath,
		LogPath:    logPath,
		Interval:   interval,
	}
}

// Run waits for the next process instance and monitors it.
func (m *Monitor) Run() error {
	logger, err := NewLogger(m.LogPath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	m.logger = logger
	defer m.logger.Close()

	m.logger.Info("Netwinmon session started. Target: %s, Report: %s, Log: %s", m.TargetExe, m.ReportPath, m.LogPath)
	m.logger.Info("Checking administrative status...")
	if windows.GetCurrentProcessToken().IsElevated() {
		m.logger.Info("Running as Administrator.")
	} else {
		m.logger.Warn("Running without Administrator privileges. ETW engine will fail and fall back to polling.")
	}

	m.logger.Info("Scanning running processes to exclude existing instances...")
	knownPIDs, err := m.findCurrentPIDs()
	if err != nil {
		return fmt.Errorf("failed listing current processes: %w", err)
	}
	m.logger.Info("Excluding %d already running instances.", len(knownPIDs))

	m.logger.Info("Waiting for next instance of %s...", m.TargetExe)
	var pid uint32
	var path string
	for {
		current, err := m.findCurrentPIDs()
		if err != nil {
			return fmt.Errorf("failed listing current processes: %w", err)
		}
		for p, pPath := range current {
			if _, exists := knownPIDs[p]; !exists {
				pid = p
				path = pPath
				break
			}
		}
		if pid != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	m.logger.Info("Found next process instance. PID: %d, Path: %s", pid, path)
	return m.monitorPID(pid, path)
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
				if m.match(procPath) {
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

func (m *Monitor) match(procPath string) bool {
	absTarget, err := filepath.Abs(m.TargetExe)
	if err == nil {
		absTarget = filepath.Clean(absTarget)
		absProc := filepath.Clean(procPath)
		if strings.EqualFold(absProc, absTarget) {
			return true
		}
	}
	if !strings.ContainsAny(m.TargetExe, `/\`) {
		targetBase := filepath.Base(m.TargetExe)
		procBase := filepath.Base(procPath)
		if strings.EqualFold(procBase, targetBase) {
			return true
		}
	}
	return false
}

func (m *Monitor) monitorPID(pid uint32, path string) error {
	m.logger.Info("Opening handle to target PID %d...", pid)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("failed to open process handle: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	var startTime time.Time
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		startTime = filetimeToTime(creationTime)
		m.logger.Info("Target process creation time (UTC): %s", startTime.UTC().Format(time.RFC3339))
	} else {
		startTime = time.Now()
		m.logger.Warn("Failed to get process times: %v. Using current time.", err)
	}

	// Aggregation maps.
	tcpMap := make(map[string]*TCPEndpointRecord)
	udpMap := make(map[string]*UDPEndpointRecord)

	var etwEng *ETWEngine
	engineUsed := "polling"

	// Try starting ETW session first.
	m.logger.Info("Attempting to initialize ETW tracing engine...")
	etwEng = NewETWEngine(pid, tcpMap, udpMap, m.logger)
	if err := etwEng.Start(); err == nil {
		m.logger.Info("Successfully started ETW monitoring session: %s", etwEng.SessionName)
		engineUsed = "etw"
	} else {
		m.logger.Warn("Unable to start ETW trace session: %v.", err)
		m.logger.Info("Falling back to IP Helper table polling engine...")
		etwEng = nil
	}

	m.logger.Info("Monitoring network activity of PID %d... Press Ctrl+C to abort.", pid)

	// Helper to snap tables (only used if falling back to polling engine).
	snap := func() {
		if engineUsed != "polling" {
			return
		}
		nowStr := time.Now().UTC().Format(time.RFC3339)

		// Snap TCP.
		if tConns, err := GetTCPConnections(); err == nil {
			matchCount := 0
			for _, conn := range tConns {
				if conn.PID == pid {
					matchCount++
					key := fmt.Sprintf("%s:%d", conn.RemoteIP, conn.RemotePort)
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
						}
					}
				}
			}
			m.logger.Debug("Polling Snap: found %d total TCP connections. Matched %d to PID %d.", len(tConns), matchCount, pid)
		} else {
			m.logger.Error("Polling Error: failed to get TCP connections", err)
		}

		// Snap UDP.
		if uEps, err := GetUDPEndpoints(); err == nil {
			matchCount := 0
			for _, ep := range uEps {
				if ep.PID == pid {
					matchCount++
					remoteIP := "0.0.0.0"
					if ep.LocalIP.To4() == nil {
						remoteIP = "::"
					}
					key := fmt.Sprintf("%s:0", remoteIP)
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
						}
					}
				}
			}
			m.logger.Debug("Polling Snap: found %d total UDP endpoints. Matched %d to PID %d.", len(uEps), matchCount, pid)
		} else {
			m.logger.Error("Polling Error: failed to get UDP endpoints", err)
		}
	}

	// Main monitoring loop.
	for {
		snap()

		event, err := windows.WaitForSingleObject(h, 0)
		if err == nil && event == windows.WAIT_OBJECT_0 {
			m.logger.Info("Target process exit detected by WaitForSingleObject.")
			break
		}
		time.Sleep(m.Interval)
	}

	// Final sweep if polling.
	snap()

	// Stop ETW trace session if it was started.
	if etwEng != nil {
		m.logger.Info("Stopping ETW tracing session...")
		etwEng.Stop()
	}

	var endTime time.Time
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		endTime = filetimeToTime(exitTime)
		m.logger.Info("Target process exit time (UTC): %s", endTime.UTC().Format(time.RFC3339))
	} else {
		endTime = time.Now()
		m.logger.Warn("Failed to get process exit times: %v. Using current time.", err)
	}

	m.logger.Info("Process exited. Generating report...")

	// Convert maps to slices under lock protection (just in case).
	var tcpConns []TCPEndpointRecord
	var udpEps []UDPEndpointRecord

	if etwEng != nil {
		etwEng.mu.Lock()
	}
	for _, rec := range tcpMap {
		tcpConns = append(tcpConns, *rec)
	}
	for _, rec := range udpMap {
		udpEps = append(udpEps, *rec)
	}
	if etwEng != nil {
		etwEng.mu.Unlock()
	}

	report := Report{
		PID:            pid,
		Path:           path,
		StartTime:      startTime.UTC().Format(time.RFC3339),
		EndTime:        endTime.UTC().Format(time.RFC3339),
		Engine:         engineUsed,
		TCPConnections: tcpConns,
		UDPEndpoints:   udpEps,
	}

	// Write report.json
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize report: %w", err)
	}

	// Ensure report parent directory exists
	if dir := filepath.Dir(m.ReportPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			m.logger.Warn("Failed to create report directory %s: %v", dir, err)
		}
	}

	m.logger.Info("Writing report to %s...", m.ReportPath)
	err = os.WriteFile(m.ReportPath, reportBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report.json: %w", err)
	}

	m.logger.Info("Report written successfully. Total TCP remote endpoints: %d, UDP remote endpoints: %d.", len(tcpConns), len(udpEps))
	return nil
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
