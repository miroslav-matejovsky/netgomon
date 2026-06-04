//go:build windows

package iphelper

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIntegrationIPHelperWithProbe starts probe.exe and uses IP Helper API to find its connections.
// Does not require admin. Polls TCP/UDP tables and looks for probe PID entries.
func TestIntegrationIPHelperWithProbe(t *testing.T) {
	logFile := setupTestLog(t, "iphelper_integration")
	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug}))

	probePath := findProbe(t, logger)
	logger.Info("probe path resolved", "path", probePath)

	// Start probe in fast mode.
	cmd := exec.Command(probePath, "fast")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err := cmd.Start()
	require.NoError(t, err, "failed to start probe.exe")
	logger.Info("probe started", "pid", cmd.Process.Pid)

	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		logger.Info("probe stopped")
	}()

	pid := uint32(cmd.Process.Pid)

	// Give probe time to establish connections.
	logger.Info("waiting for probe to establish connections...")
	time.Sleep(3 * time.Second)

	// Poll TCP table multiple times to catch connections.
	var totalTCPMatches int
	var totalUDPMatches int
	pollRounds := 5
	pollInterval := 2 * time.Second

	for round := 1; round <= pollRounds; round++ {
		logger.Info("polling round", "round", round, "of", pollRounds)

		// TCP
		tcpConns, err := GetTCPConnections()
		if err != nil {
			logger.Error("GetTCPConnections failed", "round", round, "error", err)
			t.Logf("Round %d: GetTCPConnections error: %v", round, err)
		} else {
			logger.Info("TCP table retrieved", "round", round, "total_entries", len(tcpConns))
			roundMatches := 0
			for _, conn := range tcpConns {
				if conn.PID == pid {
					roundMatches++
					totalTCPMatches++
					desc := fmt.Sprintf("local=%s:%d remote=%s:%d state=%s",
						conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort, conn.State)
					logger.Info("TCP match for probe",
						"round", round,
						"pid", conn.PID,
						"local_ip", conn.LocalIP.String(),
						"local_port", conn.LocalPort,
						"remote_ip", conn.RemoteIP.String(),
						"remote_port", conn.RemotePort,
						"state", conn.State)
					t.Logf("Round %d TCP: %s", round, desc)
				}
			}
			logger.Info("TCP round summary", "round", round, "matches", roundMatches, "total_entries", len(tcpConns))
		}

		// UDP
		udpEps, err := GetUDPEndpoints()
		if err != nil {
			logger.Error("GetUDPEndpoints failed", "round", round, "error", err)
			t.Logf("Round %d: GetUDPEndpoints error: %v", round, err)
		} else {
			logger.Info("UDP table retrieved", "round", round, "total_entries", len(udpEps))
			roundMatches := 0
			for _, ep := range udpEps {
				if ep.PID == pid {
					roundMatches++
					totalUDPMatches++
					desc := fmt.Sprintf("local=%s:%d", ep.LocalIP, ep.LocalPort)
					logger.Info("UDP match for probe",
						"round", round,
						"pid", ep.PID,
						"local_ip", ep.LocalIP.String(),
						"local_port", ep.LocalPort)
					t.Logf("Round %d UDP: %s", round, desc)
				}
			}
			logger.Info("UDP round summary", "round", round, "matches", roundMatches, "total_entries", len(udpEps))
		}

		if round < pollRounds {
			logger.Info("sleeping before next poll", "interval", pollInterval)
			time.Sleep(pollInterval)
		}
	}

	logger.Info("polling complete",
		"total_tcp_matches", totalTCPMatches,
		"total_udp_matches", totalUDPMatches,
		"poll_rounds", pollRounds)

	t.Logf("Total TCP matches: %d, UDP matches: %d across %d rounds", totalTCPMatches, totalUDPMatches, pollRounds)

	if totalTCPMatches == 0 && totalUDPMatches == 0 {
		logger.Warn("no connections found for probe - connections may be too short-lived for polling to catch")
		t.Logf("WARNING: no connections found for probe PID %d - check logs at .test-results/", pid)
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
