//go:build windows

package monitor

import (
	"context"
	"encoding/binary"
	"net"
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

func TestMonitorMatch(t *testing.T) {
	m := NewMonitor("probe.exe", "report.json", "monitor.log", 100*time.Millisecond)
	require.True(t, m.match(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.True(t, m.match(`probe.exe`))
	require.False(t, m.match(`C:\windows\system32\cmd.exe`))

	mFull := NewMonitor(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`, "report.json", "monitor.log", 100*time.Millisecond)
	require.True(t, mFull.match(`c:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.False(t, mFull.match(`C:\dev\personal\netwinmon\cmd\probe\other.exe`))
}

func TestParseTCPV4Table(t *testing.T) {
	buf := make([]byte, 4+24)
	binary.LittleEndian.PutUint32(buf[0:4], 1) // numEntries

	rowOffset := 4
	binary.LittleEndian.PutUint32(buf[rowOffset:rowOffset+4], mibTcpStateEstab) // DwState

	localIP := net.ParseIP("127.0.0.1").To4()
	copy(buf[rowOffset+4:rowOffset+8], localIP)

	binary.LittleEndian.PutUint32(buf[rowOffset+8:rowOffset+12], 0x5000)

	remoteIP := net.ParseIP("8.8.8.8").To4()
	copy(buf[rowOffset+12:rowOffset+16], remoteIP)

	binary.LittleEndian.PutUint32(buf[rowOffset+16:rowOffset+20], 0xBB01)

	binary.LittleEndian.PutUint32(buf[rowOffset+20:rowOffset+24], 1234)

	conns, err := parseTCPV4Table(buf)
	require.NoError(t, err)
	require.Len(t, conns, 1)

	c := conns[0]
	require.Equal(t, "127.0.0.1", c.LocalIP.String())
	require.Equal(t, uint16(80), c.LocalPort)
	require.Equal(t, "8.8.8.8", c.RemoteIP.String())
	require.Equal(t, uint16(443), c.RemotePort)
	require.Equal(t, "ESTABLISHED", c.State)
	require.Equal(t, uint32(1234), c.PID)
}

func TestParseUDPV4Table(t *testing.T) {
	buf := make([]byte, 4+12)
	binary.LittleEndian.PutUint32(buf[0:4], 1) // numEntries

	rowOffset := 4
	localIP := net.ParseIP("192.168.1.50").To4()
	copy(buf[rowOffset:rowOffset+4], localIP)

	binary.LittleEndian.PutUint32(buf[rowOffset+4:rowOffset+8], 0x3500)

	binary.LittleEndian.PutUint32(buf[rowOffset+8:rowOffset+12], 5678)

	eps, err := parseUDPV4Table(buf)
	require.NoError(t, err)
	require.Len(t, eps, 1)

	ep := eps[0]
	require.Equal(t, "192.168.1.50", ep.LocalIP.String())
	require.Equal(t, uint16(53), ep.LocalPort)
	require.Equal(t, uint32(5678), ep.PID)
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

	// Use ping.exe as target
	targetExe := "ping.exe"

	mock := &mockEngine{
		events: make(chan etwapi.NetworkEvent, 10),
	}
	m := NewMonitor(targetExe, reportPath, logPath, 10*time.Millisecond, mock)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go func() {
		// Spawn a process so the monitor can find it
		time.Sleep(50 * time.Millisecond)
		cmd := exec.Command("ping", "127.0.0.1", "-n", "2")
		_ = cmd.Start()
		defer func() {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}()

		time.Sleep(50 * time.Millisecond)
		mock.events <- etwapi.NetworkEvent{
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

	err := m.Run(ctx)
	if err != nil {
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}

	require.FileExists(t, reportPath)
	content, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "1.2.3.4")
	require.Contains(t, string(content), "mock")
}
