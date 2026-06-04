package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miroslav-matejovsky/netwinmon/internal/engine"
	"github.com/miroslav-matejovsky/netwinmon/internal/report"
	"github.com/stretchr/testify/require"
)

func TestAPIState(t *testing.T) {
	// Setup monitor with empty engines so it doesn't try to use ETW.
	m := engine.NewEngine([]string{"dummy.exe"}, "dummy_report.json", "dummy.log", 100*time.Millisecond, false)

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

	var state report.Report
	err = json.Unmarshal(body, &state)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Empty(t, state.Processes)
}

func TestAPIStatePID(t *testing.T) {
	m := engine.NewEngine([]string{"dummy.exe"}, "dummy_report.json", "dummy.log", 100*time.Millisecond, false)
	srv := NewServer(":0", m)

	// Non-existent PID returns 404.
	req := httptest.NewRequest(http.MethodGet, "/state/9999", nil)
	w := httptest.NewRecorder()
	srv.handleStatePID(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)

	// Invalid PID returns 400.
	req2 := httptest.NewRequest(http.MethodGet, "/state/abc", nil)
	w2 := httptest.NewRecorder()
	srv.handleStatePID(w2, req2)
	require.Equal(t, http.StatusBadRequest, w2.Code)

	// Wrong method returns 405.
	req3 := httptest.NewRequest(http.MethodPost, "/state/1234", nil)
	w3 := httptest.NewRecorder()
	srv.handleStatePID(w3, req3)
	require.Equal(t, http.StatusMethodNotAllowed, w3.Code)
}

func TestAPIStartStop(t *testing.T) {
	m := engine.NewEngine([]string{"dummy.exe"}, "dummy_report.json", "dummy.log", 100*time.Millisecond, false)
	srv := NewServer("127.0.0.1:0", m)

	err := srv.Start()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = srv.Stop(ctx)
	require.NoError(t, err)
}
