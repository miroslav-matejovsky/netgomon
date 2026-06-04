//go:build windows

package pid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchTarget(t *testing.T) {
	require.True(t, MatchTarget("probe.exe", `C:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.True(t, MatchTarget("probe.exe", `probe.exe`))
	require.False(t, MatchTarget("probe.exe", `C:\windows\system32\cmd.exe`))

	require.True(t, MatchTarget(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`, `c:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.False(t, MatchTarget(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`, `C:\dev\personal\netwinmon\cmd\probe\other.exe`))
}

func TestMatchAny(t *testing.T) {
	targets := []string{"probe.exe", "curl.exe"}
	require.True(t, MatchAny(targets, `C:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.True(t, MatchAny(targets, `C:\windows\system32\curl.exe`))
	require.False(t, MatchAny(targets, `C:\windows\system32\cmd.exe`))
}
