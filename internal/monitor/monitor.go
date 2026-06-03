//go:build windows

package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TCPRecord represents the aggregated record for a TCP connection.
type TCPRecord struct {
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    uint16 `json:"remote_port"`
	State         string `json:"state"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	Count         int    `json:"count"`
	InferredHTTP  bool   `json:"inferred_http"`
}

// UDPRecord represents the aggregated record for a UDP endpoint.
type UDPRecord struct {
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    uint16 `json:"remote_port"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	Count         int    `json:"count"`
	InferredHTTP  bool   `json:"inferred_http"`
}

// Report represents the final output JSON format.
type Report struct {
	PID            uint32      `json:"pid"`
	Path           string      `json:"path"`
	StartTime      string      `json:"start_time"`
	EndTime        string      `json:"end_time"`
	TCPConnections []TCPRecord `json:"tcp_connections"`
	UDPEndpoints   []UDPRecord `json:"udp_endpoints"`
}

// Monitor monitors the target executable's network activity.
type Monitor struct {
	TargetExe string
	Interval  time.Duration
}

// NewMonitor creates a Monitor instance.
func NewMonitor(targetExe string, interval time.Duration) *Monitor {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &Monitor{
		TargetExe: targetExe,
		Interval:  interval,
	}
}

// Run waits for the next process instance and monitors it.
func (m *Monitor) Run() error {
	fmt.Printf("Startup: scanning running processes to exclude existing instances...\n")
	knownPIDs, err := m.findCurrentPIDs()
	if err != nil {
		return fmt.Errorf("failed listing current processes: %w", err)
	}
	if len(knownPIDs) > 0 {
		fmt.Printf("Excluding %d already running instances.\n", len(knownPIDs))
	}

	fmt.Printf("Waiting for next instance of %s...\n", m.TargetExe)
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

	fmt.Printf("Found next process instance. PID: %d, Path: %s\n", pid, path)
	return m.monitorPID(pid, path)
}

func (m *Monitor) findCurrentPIDs() (map[uint32]string, error) {
	pids := make(map[uint32]string)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

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
			windows.CloseHandle(pHandle)
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
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("failed to open process handle: %w", err)
	}
	defer windows.CloseHandle(h)

	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	var startTime time.Time
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		startTime = filetimeToTime(creationTime)
	} else {
		startTime = time.Now()
	}

	fmt.Printf("Monitoring network activity of PID %d... Press Ctrl+C to abort.\n", pid)

	// Aggregation maps.
	tcpMap := make(map[string]*TCPRecord)
	udpMap := make(map[string]*UDPRecord)

	// Helper to snap tables.
	snap := func() {
		nowStr := time.Now().UTC().Format(time.RFC3339)

		// Snap TCP.
		if tConns, err := GetTCPConnections(); err == nil {
			for _, conn := range tConns {
				if conn.PID == pid {
					key := fmt.Sprintf("%s:%d-%s:%d-%s", conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort, conn.State)
					if rec, ok := tcpMap[key]; ok {
						rec.LastSeen = nowStr
						rec.Count++
					} else {
						tcpMap[key] = &TCPRecord{
							LocalAddress:  conn.LocalIP.String(),
							LocalPort:     conn.LocalPort,
							RemoteAddress: conn.RemoteIP.String(),
							RemotePort:    conn.RemotePort,
							State:         conn.State,
							FirstSeen:     nowStr,
							LastSeen:      nowStr,
							Count:         1,
							InferredHTTP:  inferHTTP(conn.LocalPort, conn.RemotePort),
						}
					}
				}
			}
		}

		// Snap UDP.
		if uEps, err := GetUDPEndpoints(); err == nil {
			for _, ep := range uEps {
				if ep.PID == pid {
					// UDP is connectionless. Remote address/port from tables is wildcard.
					remoteIP := "0.0.0.0"
					if ep.LocalIP.To4() == nil {
						remoteIP = "::"
					}
					key := fmt.Sprintf("%s:%d-%s:0", ep.LocalIP, ep.LocalPort, remoteIP)
					if rec, ok := udpMap[key]; ok {
						rec.LastSeen = nowStr
						rec.Count++
					} else {
						udpMap[key] = &UDPRecord{
							LocalAddress:  ep.LocalIP.String(),
							LocalPort:     ep.LocalPort,
							RemoteAddress: remoteIP,
							RemotePort:    0,
							FirstSeen:     nowStr,
							LastSeen:      nowStr,
							Count:         1,
							InferredHTTP:  inferHTTP(ep.LocalPort, 0),
						}
					}
				}
			}
		}
	}

	// Main monitoring loop.
	for {
		snap()

		event, err := windows.WaitForSingleObject(h, 0)
		if err == nil && event == windows.WAIT_OBJECT_0 {
			break
		}
		time.Sleep(m.Interval)
	}

	// Final sweep.
	snap()

	var endTime time.Time
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		endTime = filetimeToTime(exitTime)
	} else {
		endTime = time.Now()
	}

	fmt.Printf("Process exited. Generating report...\n")

	// Convert maps to slices.
	var tcpConns []TCPRecord
	for _, rec := range tcpMap {
		tcpConns = append(tcpConns, *rec)
	}
	var udpEps []UDPRecord
	for _, rec := range udpMap {
		udpEps = append(udpEps, *rec)
	}

	report := Report{
		PID:            pid,
		Path:           path,
		StartTime:      startTime.UTC().Format(time.RFC3339),
		EndTime:        endTime.UTC().Format(time.RFC3339),
		TCPConnections: tcpConns,
		UDPEndpoints:   udpEps,
	}

	// Write report.json
	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize report: %w", err)
	}

	err = os.WriteFile("report.json", reportBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report.json: %w", err)
	}

	fmt.Printf("Report written to report.json successfully.\n")
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
