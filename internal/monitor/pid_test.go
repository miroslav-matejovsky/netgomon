//go:build windows

package monitor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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
