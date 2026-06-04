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

// Monitor monitors the target executable's network activity.
type Monitor struct {
	TargetExe  string
	ReportPath string
	LogPath    string
	Interval   time.Duration

	logger  *Logger
	mu      sync.RWMutex
	engines []etwapi.Engine
}

// NewMonitor creates a Monitor instance.
func NewMonitor(targetExe, reportPath, logPath string, interval time.Duration, engines ...etwapi.Engine) *Monitor {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &Monitor{
		TargetExe:  targetExe,
		ReportPath: reportPath,
		LogPath:    logPath,
		Interval:   interval,
		engines:    engines,
	}
}

// Run waits for the next process instance and monitors it.
func (m *Monitor) Run(ctx context.Context) error {
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
		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled while waiting for process.")
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	m.logger.Info("Found next process instance. PID: %d, Path: %s", pid, path)
	return m.monitorPID(ctx, pid, path)
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

func (m *Monitor) monitorPID(ctx context.Context, pid uint32, path string) error {
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

	// Aggregation maps (keyed by "tool:remoteIP:remotePort").
	tcpMap := make(map[string]*TCPEndpointRecord)
	udpMap := make(map[string]*UDPEndpointRecord)

	// slog logger for ETW engines.
	slogLogger := slog.New(slog.NewJSONHandler(m.logger.file, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Start both ETW engines if none injected.
	var engines []etwapi.Engine
	var engineNames []string

	m.logger.Info("Attempting to initialize ETW tracing engines...")

	if len(m.engines) > 0 {
		engines = m.engines
		for _, eng := range engines {
			_ = eng.Start()
			engineNames = append(engineNames, "mock")
		}
		m.logger.Info("Using injected mock engines for testing")
	} else {
		rawsecEng := rawsec.New(pid, slogLogger)
		if err := rawsecEng.Start(); err == nil {
			engines = append(engines, rawsecEng)
			engineNames = append(engineNames, "rawsec")
			m.logger.Info("rawsec ETW engine started successfully")
		} else {
			m.logger.Warn("rawsec ETW engine failed: %v", err)
		}

		goetwEng := goetw.New(pid, slogLogger)
		if err := goetwEng.Start(); err == nil {
			engines = append(engines, goetwEng)
			engineNames = append(engineNames, "goetw")
			m.logger.Info("goetw ETW engine started successfully")
		} else {
			m.logger.Warn("goetw ETW engine failed: %v", err)
		}
	}

	usePolling := len(engines) == 0
	if usePolling {
		m.logger.Info("No ETW engines started. Falling back to IP Helper table polling engine...")
		engineNames = append(engineNames, "polling")
	}

	// Fan-in: merge events from all engines into aggregation maps.
	var wg sync.WaitGroup
	for _, eng := range engines {
		wg.Add(1)
		go func(ch <-chan etwapi.NetworkEvent) {
			defer wg.Done()
			for ev := range ch {
				m.handleNetworkEvent(ev, tcpMap, udpMap)
			}
		}(eng.Events())
	}

	// Write initial report.
	if err := m.writeReport(pid, path, startTime, startTime, engineNames, tcpMap, udpMap); err != nil {
		m.logger.Warn("Failed to write initial report: %v", err)
	}

	m.logger.Info("Monitoring network activity of PID %d... Press Ctrl+C to abort.", pid)

	// Helper to snap tables (only used if falling back to polling engine).
	snap := func() {
		if !usePolling {
			return
		}
		nowStr := time.Now().UTC().Format(time.RFC3339)

		// Snap TCP.
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
			m.logger.Debug("Polling Snap: found %d total UDP endpoints. Matched %d to PID %d.", len(uEps), matchCount, pid)
		} else {
			m.logger.Error("Polling Error: failed to get UDP endpoints", err)
		}
	}

	// Main monitoring loop.
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled by user (signal).")
			goto cleanup
		default:
		}

		snap()

		// Continuously update report.
		if err := m.writeReport(pid, path, startTime, time.Now(), engineNames, tcpMap, udpMap); err != nil {
			m.logger.Debug("Failed to write continuous report: %v", err)
		}

		event, err := windows.WaitForSingleObject(h, 0)
		if err == nil && event == windows.WAIT_OBJECT_0 {
			m.logger.Info("Target process exit detected by WaitForSingleObject.")
			break
		}

		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled by user (signal).")
			goto cleanup
		case <-time.After(m.Interval):
		}
	}

cleanup:

	// Final sweep if polling.
	snap()

	// Give ETW consumers a moment to process any final buffered flush events.
	time.Sleep(500 * time.Millisecond)

	// Stop all ETW engines.
	for _, eng := range engines {
		eng.Stop()
	}
	wg.Wait()

	var endTime time.Time
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		endTime = filetimeToTime(exitTime)
		m.logger.Info("Target process exit time (UTC): %s", endTime.UTC().Format(time.RFC3339))
	} else {
		endTime = time.Now()
		m.logger.Warn("Failed to get process exit times: %v. Using current time.", err)
	}

	m.logger.Info("Process exited. Generating final report...")

	// Write final report.
	if err := m.writeReport(pid, path, startTime, endTime, engineNames, tcpMap, udpMap); err != nil {
		m.logger.Error("Failed to write final report", err)
	} else {
		m.logger.Info("Report written successfully. Total TCP remote endpoints: %d, UDP remote endpoints: %d.", len(tcpMap), len(udpMap))
	}

	return nil
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
		} else {
			tcpMap[key] = &TCPEndpointRecord{
				RemoteAddress: ev.RemoteIP,
				RemotePort:    ev.RemotePort,
				FirstSeen:     nowStr,
				LastSeen:      nowStr,
				Count:         1,
				InferredHTTP:  inferHTTP(0, ev.RemotePort),
				States:        map[string]int{ev.State: 1},
				Tool:          ev.Tool,
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
