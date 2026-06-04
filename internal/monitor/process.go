//go:build windows

package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
	"github.com/miroslav-matejovsky/netwinmon/internal/etw/goetw"
	"github.com/miroslav-matejovsky/netwinmon/internal/etw/rawsec"
	"github.com/miroslav-matejovsky/netwinmon/internal/iphelper"
	"golang.org/x/sys/windows"
)

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

func filetimeToTime(ft windows.Filetime) time.Time {
	intervals := (int64(ft.HighDateTime) << 32) | int64(ft.LowDateTime)
	secs := intervals / 10000000
	nsecs := (intervals % 10000000) * 100
	unixSecs := secs - 11644473600
	return time.Unix(unixSecs, nsecs)
}
