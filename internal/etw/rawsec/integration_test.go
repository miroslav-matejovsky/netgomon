//go:build windows

package rawsec

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIntegrationRawsecWithProbe starts the rawsec engine, then launches probe.exe to generate
// network traffic, and verifies that ETW events are captured for the probe PID.
// Requires admin privileges for ETW session. Skips if unavailable.
func TestIntegrationRawsecWithProbe(t *testing.T) {
	logFile := setupTestLog(t, "rawsec_integration")
	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug}))

	probePath := buildProbe(t, logger)
	logger.Info("probe path resolved", "path", probePath)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Start probe to get a PID. Engine needs PID to filter events.
	cmd := exec.CommandContext(ctx, probePath, "fast")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err := cmd.Start()
	require.NoError(t, err, "failed to start probe.exe")
	pid := uint32(cmd.Process.Pid)
	logger.Info("probe started", "pid", pid)

	defer func() {
		cancel()
		_ = cmd.Wait()
		logger.Info("probe stopped")
	}()

	// Create and start engine IMMEDIATELY so it captures probe's network calls.
	logger.Info("creating rawsec engine", "target_pid", pid)
	eng := New(ctx, pid, logger)
	err = eng.Start()
	if err != nil {
		logger.Warn("rawsec engine start failed - likely not admin, skipping", "error", err)
		t.Skipf("Skipping: rawsec engine requires admin: %v", err)
	}
	logger.Info("rawsec engine started successfully")

	defer func() {
		eng.Stop()
		logger.Info("rawsec engine stopped after test",
			"total_events", eng.stats.totalEvents.Load(),
			"pid_matches", eng.stats.pidMatches.Load(),
			"mapped_events", eng.stats.mappedEvents.Load(),
			"parse_failures", eng.stats.parseFailures.Load())
	}()

	// Give engine a moment to fully initialize consumer.
	time.Sleep(500 * time.Millisecond)
	logger.Info("engine init wait done, probe should be generating traffic now")

	// Collect events for up to 15 seconds.
	deadline := time.After(15 * time.Second)
	var collected []string
	channelClosed := false
	logger.Info("collecting events...")

	for {
		select {
		case ev, ok := <-eng.Events():
			if !ok {
				channelClosed = true
				logger.Warn("event channel closed before deadline - consumer.Start() may have returned immediately")
				t.Log("WARNING: event channel closed before deadline - rawsec consumer may not be blocking")
				goto done
			}
			desc := fmt.Sprintf("pid=%d remote=%s:%d local=%s:%d udp=%v state=%s tool=%s ts=%s",
				ev.PID, ev.RemoteIP, ev.RemotePort, ev.LocalIP, ev.LocalPort,
				ev.IsUDP, ev.State, ev.Tool, ev.Timestamp.Format(time.RFC3339))
			logger.Info("captured event", "event", desc)
			collected = append(collected, desc)
		case <-deadline:
			logger.Info("collection deadline reached")
			goto done
		}
	}

done:
	// Log engine stats.
	totalEvents := eng.stats.totalEvents.Load()
	pidMatches := eng.stats.pidMatches.Load()
	mappedEvents := eng.stats.mappedEvents.Load()
	parseFailures := eng.stats.parseFailures.Load()

	logger.Info("collection finished",
		"total_captured", len(collected),
		"channel_closed_early", channelClosed,
		"engine_total_events", totalEvents,
		"engine_pid_matches", pidMatches,
		"engine_mapped_events", mappedEvents,
		"engine_parse_failures", parseFailures)

	for i, ev := range collected {
		logger.Info("event summary", "index", i, "event", ev)
		t.Logf("Event[%d]: %s", i, ev)
	}

	// Diagnostic: log event ID distribution.
	eng.stats.eventIDCounts.Range(func(key, value interface{}) bool {
		id := key.(uint16)
		count := value.(*atomic.Uint64)
		logger.Info("event ID distribution", "event_id", id, "count", count.Load())
		t.Logf("EventID %d: count=%d", id, count.Load())
		return true
	})

	t.Logf("Engine stats: total=%d pid_matches=%d mapped=%d failures=%d channel_closed=%v",
		totalEvents, pidMatches, mappedEvents, parseFailures, channelClosed)

	if channelClosed {
		logger.Error("rawsec consumer closed channel immediately - consumer.Start() did not block as expected")
	}
	if totalEvents == 0 {
		logger.Error("rawsec received 0 total events - EventCallback was never invoked")
	}

	// Assertions.
	require.False(t, channelClosed,
		"event channel should not close before deadline - consumer.Start() returned immediately instead of blocking")
	require.Greater(t, totalEvents, uint64(0),
		"rawsec engine should receive at least some ETW events from the system")
	require.Greater(t, len(collected), 0,
		"should capture at least one network event from probe PID %d", pid)

	t.Logf("SUCCESS: captured %d events from probe PID %d", len(collected), pid)
}

// setupTestLog creates a log file in .test-results/ for this test run.
func setupTestLog(t *testing.T, prefix string) *os.File {
	t.Helper()
	outDir := filepath.Join("..", "..", "..", ".test-results")
	err := os.MkdirAll(outDir, 0755)
	require.NoError(t, err, "failed to create .test-results dir")

	ts := time.Now().Format("20060102-150405")
	logPath := filepath.Join(outDir, fmt.Sprintf("%s-%s.log", prefix, ts))
	f, err := os.Create(logPath)
	require.NoError(t, err, "failed to create log file")
	t.Cleanup(func() { _ = f.Close() })

	t.Logf("Test log: %s", logPath)
	return f
}

// buildProbe compiles the probe command into a temporary directory.
func buildProbe(t *testing.T, logger *slog.Logger) string {
	t.Helper()

	tmpDir := t.TempDir()
	probePath := filepath.Join(tmpDir, "probe_rawsec.exe")
	
	logger.Info("building probe", "output_path", probePath)
	cmd := exec.Command("go", "build", "-o", probePath, "github.com/miroslav-matejovsky/netwinmon/cmd/probe")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build probe: %s", string(out))
	
	return probePath
}
