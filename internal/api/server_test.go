package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miroslav-matejovsky/netwinmon/internal/monitor"
	"github.com/stretchr/testify/require"
)

func TestAPIState(t *testing.T) {
	// Setup monitor with empty engines so it doesn't try to use ETW.
	m := monitor.NewMonitor("dummy.exe", "dummy_report.json", "dummy.log", 100*time.Millisecond)

	// We can't easily populate monitor's internal activeProcesses map from outside
	// without starting a run loop or mocking it, but we can verify the endpoint
	// returns a valid empty state or starts up properly.
	srv := NewServer(":0", m) // Port 0 for random port if used via Start()

	// But we can directly test the handler using httptest
	req := httptest.NewRequest(http.MethodGet, "/state", nil)
	w := httptest.NewRecorder()

	srv.handleState(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	require.Equal(t, http.StatusOK, res.StatusCode)

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	var state map[uint32]*monitor.ProcessState
	err = json.Unmarshal(body, &state)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Empty(t, state)
}

func TestAPIStartStop(t *testing.T) {
	m := monitor.NewMonitor("dummy.exe", "dummy_report.json", "dummy.log", 100*time.Millisecond)
	srv := NewServer("127.0.0.1:0", m)

	err := srv.Start()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = srv.Stop(ctx)
	require.NoError(t, err)
}
