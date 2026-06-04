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
	logPath := filepath.Join(tmpDir, "monitor.log")

	targetExe := "ping.exe"

	mock := &mockEngine{
		events: make(chan etwapi.NetworkEvent, 10),
	}

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
	m := NewMonitor(uint32(cmd.Process.Pid), targetExe, 10*time.Millisecond, slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug})), mock)

	go func() {
		_ = m.Run(ctx)
	}()

	// Wait briefly to allow processing.
	time.Sleep(100 * time.Millisecond)

	// Since we mocked ETW, let's verify GetState has it.
	state := m.GetState()
	require.NotNil(t, state)
	require.Contains(t, state.TCP, "mock:1.2.3.4:80")
}
