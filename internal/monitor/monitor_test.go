//go:build windows

package monitor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMonitor(t *testing.T) {
	m := NewMonitor(1234, "test.exe", 100*time.Millisecond, nil)
	require.NotNil(t, m)
	require.Equal(t, uint32(1234), m.PID)
	require.Equal(t, "test.exe", m.Path)
	require.Equal(t, 100*time.Millisecond, m.Interval)
}
