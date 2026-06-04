//go:build windows

package monitor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMonitor(t *testing.T) {
	m := NewMonitor([]string{"test.exe"}, "report.json", "monitor.log", 100*time.Millisecond)
	require.NotNil(t, m)
	require.Equal(t, []string{"test.exe"}, m.TargetExes)
	require.Equal(t, "report.json", m.ReportPath)
	require.Equal(t, "monitor.log", m.LogPath)
	require.Equal(t, 100*time.Millisecond, m.Interval)
}
