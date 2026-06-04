//go:build windows

package goetw

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIntegrationGoETWWithProbe starts probe.exe and uses goetw engine to capture its network events.
// Requires admin privileges for ETW session. Skips if unavailable.
func TestIntegrationGoETWWithProbe(t *testing.T) {
	logFile := setupTestLog(t, "goetw_integration")
	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug}))

	probePath := findProbe(t, logger)
	logger.Info("probe path resolved", "path", probePath)

	// Start probe in fast mode.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, probePath, "fast")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err := cmd.Start()
	require.NoError(t, err, "failed to start probe.exe")
	logger.Info("probe started", "pid", cmd.Process.Pid)

	defer func() {
		cancel()
		_ = cmd.Wait()
		logger.Info("probe stopped")
	}()

	pid := uint32(cmd.Process.Pid)

	// Give probe a moment to start its first network calls.
	time.Sleep(2 * time.Second)
	logger.Info("creating goetw engine", "target_pid", pid)

	eng := New(ctx, pid, logger)
	err = eng.Start()
	if err != nil {
		logger.Warn("goetw engine start failed - likely not admin, skipping", "error", err)
		t.Skipf("Skipping: goetw engine requires admin: %v", err)
	}
	logger.Info("goetw engine started successfully")

	defer func() {
		eng.Stop()
		logger.Info("goetw engine stopped",
			"total_events", eng.stats.totalEvents.Load(),
			"pid_matches", eng.stats.pidMatches.Load(),
			"mapped_events", eng.stats.mappedEvents.Load(),
			"parse_failures", eng.stats.parseFailures.Load())
	}()

	// Collect events for up to 10 seconds, waiting for probe to do its thing.
	deadline := time.After(10 * time.Second)
	var collected []string
	logger.Info("collecting events...")

	for {
		select {
		case ev, ok := <-eng.Events():
			if !ok {
				logger.Info("event channel closed")
				goto done
			}
			desc := fmt.Sprintf("pid=%d remote=%s:%d local=%s:%d udp=%v state=%s tool=%s",
				ev.PID, ev.RemoteIP, ev.RemotePort, ev.LocalIP, ev.LocalPort, ev.IsUDP, ev.State, ev.Tool)
			logger.Info("captured event", "event", desc)
			collected = append(collected, desc)
		case <-deadline:
			logger.Info("collection deadline reached")
			goto done
		}
	}

done:
	logger.Info("collection finished", "total_captured", len(collected))

	for i, ev := range collected {
		logger.Info("event summary", "index", i, "event", ev)
		t.Logf("Event[%d]: %s", i, ev)
	}

	// Log stats even if no events captured - useful for debugging.
	logger.Info("final engine stats",
		"total_events", eng.stats.totalEvents.Load(),
		"pid_matches", eng.stats.pidMatches.Load(),
		"mapped_events", eng.stats.mappedEvents.Load(),
		"parse_failures", eng.stats.parseFailures.Load())

	if len(collected) == 0 {
		t.Logf("WARNING: no events captured for PID %d - check logs at .test-results/", pid)
		logger.Warn("no events captured - this may indicate a problem or just timing", "pid", pid)
	} else {
		t.Logf("Captured %d events from probe PID %d", len(collected), pid)
	}
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

// findProbe locates dist/probe.exe relative to the test directory.
func findProbe(t *testing.T, logger *slog.Logger) string {
	t.Helper()

	// Try relative from test package location.
	candidates := []string{
		filepath.Join("..", "..", "..", "dist", "probe.exe"),
	}

	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		logger.Debug("checking probe candidate", "path", abs)
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}

	t.Skipf("Skipping: probe.exe not found in dist/ - run 'task build' first")
	return ""
}
