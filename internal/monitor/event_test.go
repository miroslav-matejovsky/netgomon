//go:build windows

package monitor

import (
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

func TestFailedConnectionTracking(t *testing.T) {
	mock := &mockEngine{events: make(chan etwapi.NetworkEvent, 10)}
	m := NewMonitor(1234, "ping.exe", 10*time.Millisecond, nil, mock)

	// Successful connect.
	m.handleNetworkEvent(etwapi.NetworkEvent{
		PID: 1234, RemoteIP: "1.2.3.4", RemotePort: 80,
		State: "CONNECT", Timestamp: time.Now(), Tool: "test",
	})

	// Failed connect.
	m.handleNetworkEvent(etwapi.NetworkEvent{
		PID: 1234, RemoteIP: "1.2.3.4", RemotePort: 80,
		State: "CONNECT_FAIL", Timestamp: time.Now(), Tool: "test",
	})

	state := m.GetState()
	require.NotNil(t, state)
	require.Len(t, state.TCP, 1)
	rec := state.TCP["test:1.2.3.4:80"]
	require.NotNil(t, rec)
	require.Equal(t, 2, rec.Count)
	require.Equal(t, 1, rec.FailedConnections)
	require.Equal(t, 1, rec.States["CONNECT"])
	require.Equal(t, 1, rec.States["CONNECT_FAIL"])
}
