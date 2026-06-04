//go:build windows

package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
	"github.com/miroslav-matejovsky/netwinmon/internal/etw/goetw"
	"github.com/miroslav-matejovsky/netwinmon/internal/etw/rawsec"
	"github.com/miroslav-matejovsky/netwinmon/internal/iphelper"
	"golang.org/x/sys/windows"
)

func (m *Monitor) Run(ctx context.Context) error {
	m.logger.Info("Opening handle to target", "pid", m.PID)
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, m.PID)
	if err != nil {
		m.logger.Warn("Failed to open process handle", "pid", m.PID, "error", err)
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
		m.state.StartTime = filetimeToTime(creationTime)
		m.logger.Info("Process creation time", "pid", m.PID, "time", m.state.StartTime.UTC().Format(time.RFC3339))
	} else {
		m.state.StartTime = time.Now()
		m.logger.Warn("Failed to get process times, using current time", "pid", m.PID, "error", err)
	}

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
		m.logger.Info("Using injected mock engines for testing", "pid", m.PID)
	} else {
		// Try goetw first (primary), fall back to rawsec if it fails.
		goetwEng := goetw.New(ctx, m.PID, m.logger)
		if err := goetwEng.Start(); err == nil {
			engines = append(engines, goetwEng)
			engineNames = append(engineNames, "goetw")
			m.logger.Info("goetw ETW engine started", "pid", m.PID)
		} else {
			m.logger.Warn("goetw ETW engine failed, trying rawsec...", "pid", m.PID, "error", err)
			rawsecEng := rawsec.New(ctx, m.PID, m.logger)
			if err := rawsecEng.Start(); err == nil {
				engines = append(engines, rawsecEng)
				engineNames = append(engineNames, "rawsec")
				m.logger.Info("rawsec ETW engine started", "pid", m.PID)
			} else {
				m.logger.Warn("rawsec ETW engine failed", "pid", m.PID, "error", err)
			}
		}
	}

	if len(engines) == 0 {
		usePolling = true
		engineNames = append(engineNames, "polling")
		m.logger.Info("No ETW engines, using polling fallback", "pid", m.PID)
	}

	// Fan-in from engine channels.
	var fanWg sync.WaitGroup
	for _, eng := range engines {
		fanWg.Add(1)
		go func(ch <-chan etwapi.NetworkEvent) {
			defer fanWg.Done()
			for ev := range ch {
				m.handleNetworkEvent(ev)
			}
		}(eng.Events())
	}

	m.logger.Info("Monitoring network activity", "pid", m.PID, "engines", engineNames)

	// Polling snap helper.
	snap := func() {
		if !usePolling {
			return
		}
		nowStr := time.Now().UTC().Format(time.RFC3339)

		if tConns, err := iphelper.GetTCPConnections(); err == nil {
			matchCount := 0
			for _, conn := range tConns {
				if conn.PID == m.PID {
					matchCount++
					key := fmt.Sprintf("polling:%s:%d", conn.RemoteIP, conn.RemotePort)
					m.mu.Lock()
					if rec, ok := m.state.TCP[key]; ok {
						rec.LastSeen = nowStr
						rec.Count++
						rec.States[conn.State]++
					} else {
						m.state.TCP[key] = &TCPEndpoint{
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
			m.logger.Debug("Polling TCP", "pid", m.PID, "total", len(tConns), "matched", matchCount)
		} else {
			m.logger.Error("Polling TCP error", "pid", m.PID, "error", err)
		}

		if uEps, err := iphelper.GetUDPEndpoints(); err == nil {
			matchCount := 0
			for _, ep := range uEps {
				if ep.PID == m.PID {
					matchCount++
					remoteIP := "0.0.0.0"
					if ep.LocalIP.To4() == nil {
						remoteIP = "::"
					}
					key := fmt.Sprintf("polling:%s:0", remoteIP)
					m.mu.Lock()
					if rec, ok := m.state.UDP[key]; ok {
						rec.LastSeen = nowStr
						rec.Count++
					} else {
						m.state.UDP[key] = &UDPEndpoint{
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
			m.logger.Debug("Polling UDP", "pid", m.PID, "total", len(uEps), "matched", matchCount)
		} else {
			m.logger.Error("Polling UDP error", "pid", m.PID, "error", err)
		}
	}

	// Wait for process to exit.
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled", "pid", m.PID)
			goto done
		default:
		}

		snap()

		event, err := windows.WaitForSingleObject(h, 0)
		if err == nil && event == windows.WAIT_OBJECT_0 {
			m.logger.Info("Process exit detected", "pid", m.PID)
			break
		}

		select {
		case <-ctx.Done():
			m.logger.Info("Monitor cancelled", "pid", m.PID)
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
	tcpCount := len(m.state.TCP)
	udpCount := len(m.state.UDP)
	m.mu.RUnlock()
	m.logger.Info("Monitoring complete", "pid", m.PID, "tcp", tcpCount, "udp", udpCount)
	return nil
}

func filetimeToTime(ft windows.Filetime) time.Time {
	intervals := (int64(ft.HighDateTime) << 32) | int64(ft.LowDateTime)
	secs := intervals / 10000000
	nsecs := (intervals % 10000000) * 100
	unixSecs := secs - 11644473600
	return time.Unix(unixSecs, nsecs)
}
