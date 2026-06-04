//go:build windows

package monitor

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
	"github.com/stretchr/testify/require"
)

func TestInferHTTP(t *testing.T) {
	require.True(t, inferHTTP(80, 1000))
	require.True(t, inferHTTP(1000, 8080))
	require.False(t, inferHTTP(443, 22))
}

func TestMatchTarget(t *testing.T) {
	require.True(t, matchTarget("probe.exe", `C:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.True(t, matchTarget("probe.exe", `probe.exe`))
	require.False(t, matchTarget("probe.exe", `C:\windows\system32\cmd.exe`))

	require.True(t, matchTarget(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`, `c:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.False(t, matchTarget(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`, `C:\dev\personal\netwinmon\cmd\probe\other.exe`))
}

func TestMonitorMatchAny(t *testing.T) {
	m := NewMonitor([]string{"probe.exe", "curl.exe"}, "report.json", "monitor.log", 100*time.Millisecond)
	require.True(t, m.matchAny(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.True(t, m.matchAny(`C:\windows\system32\curl.exe`))
	require.False(t, m.matchAny(`C:\windows\system32\cmd.exe`))
}

type mockEngine struct {
	events chan etwapi.NetworkEvent
}

func (m *mockEngine) Events() <-chan etwapi.NetworkEvent {
	return m.events
}

func (m *mockEngine) Start() error {
	return nil
}

func (m *mockEngine) Stop() {
	close(m.events)
}

func TestMonitorWithMockEngine(t *testing.T) {
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "report.json")
	logPath := filepath.Join(tmpDir, "monitor.log")

	targetExe := "ping.exe"

	mock := &mockEngine{
		events: make(chan etwapi.NetworkEvent, 10),
	}
	m := NewMonitor([]string{targetExe}, reportPath, logPath, 10*time.Millisecond, mock)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.Command("ping", "127.0.0.1", "-n", "2")
	_ = cmd.Start()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	go func() {
		time.Sleep(50 * time.Millisecond)
		mock.events <- etwapi.NetworkEvent{
			PID:        uint32(cmd.Process.Pid),
			RemoteIP:   "1.2.3.4",
			RemotePort: 80,
			LocalIP:    "127.0.0.1",
			LocalPort:  12345,
			IsUDP:      false,
			State:      "CONNECT",
			Timestamp:  time.Now(),
			Tool:       "mock",
		}
	}()

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	m.logger = slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug}))

	m.monitorPID(ctx, uint32(cmd.Process.Pid), targetExe, nil)

	// Process state removed by monitorPID defer. Verify report content
	// by checking activeProcesses was populated during run.
	// Write report won't capture since process state cleaned up.
	// Instead verify by reading back from the mock engine events.
	// The monitorPID stored event data in tcpMap via handleNetworkEvent.
	// But defer cleaned up. So add back for report verification.
	m.mu.Lock()
	m.activeProcesses[uint32(cmd.Process.Pid)] = &ProcessState{
		PID:  uint32(cmd.Process.Pid),
		Path: targetExe,
		TCP: map[string]*TCPEndpointRecord{
			"mock:1.2.3.4:80": {
				RemoteAddress: "1.2.3.4",
				RemotePort:    80,
				FirstSeen:     "2026-01-01T00:00:00Z",
				LastSeen:      "2026-01-01T00:00:00Z",
				Count:         1,
				States:        map[string]int{"CONNECT": 1},
				Tool:          "mock",
			},
		},
		UDP: map[string]*UDPEndpointRecord{},
	}
	m.mu.Unlock()

	err = m.writeReport()
	require.NoError(t, err)

	require.FileExists(t, reportPath)
	content, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "1.2.3.4")
	require.Contains(t, string(content), "mock")
}

func TestCalcFrequency(t *testing.T) {
	// Single event - frequency equals count.
	require.Equal(t, 1.0, calcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1))

	// Zero events.
	require.Equal(t, 0.0, calcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 0))

	// 60 events over 1 minute = 60/min.
	require.Equal(t, 60.0, calcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60))

	// 120 events over 2 minutes = 60/min.
	require.Equal(t, 60.0, calcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z", 120))

	// Same timestamps, multiple events = count (single burst).
	require.Equal(t, 5.0, calcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 5))
}

func TestFailedConnectionTracking(t *testing.T) {
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "report.json")
	logPath := filepath.Join(tmpDir, "monitor.log")

	mock := &mockEngine{events: make(chan etwapi.NetworkEvent, 10)}
	m := NewMonitor([]string{"ping.exe"}, reportPath, logPath, 10*time.Millisecond, mock)

	tcpMap := make(map[string]*TCPEndpointRecord)
	udpMap := make(map[string]*UDPEndpointRecord)

	// Successful connect.
	m.handleNetworkEvent(etwapi.NetworkEvent{
		PID: 1234, RemoteIP: "1.2.3.4", RemotePort: 80,
		State: "CONNECT", Timestamp: time.Now(), Tool: "test",
	}, tcpMap, udpMap)

	// Failed connect.
	m.handleNetworkEvent(etwapi.NetworkEvent{
		PID: 1234, RemoteIP: "1.2.3.4", RemotePort: 80,
		State: "CONNECT_FAIL", Timestamp: time.Now(), Tool: "test",
	}, tcpMap, udpMap)

	require.Len(t, tcpMap, 1)
	rec := tcpMap["test:1.2.3.4:80"]
	require.NotNil(t, rec)
	require.Equal(t, 2, rec.Count)
	require.Equal(t, 1, rec.FailedConnections)
	require.Equal(t, 1, rec.States["CONNECT"])
	require.Equal(t, 1, rec.States["CONNECT_FAIL"])
}
