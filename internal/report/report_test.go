//go:build windows

package report

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalcFrequency(t *testing.T) {
	// Single event - frequency equals count.
	require.Equal(t, 1.0, CalcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1))

	// Zero events.
	require.Equal(t, 0.0, CalcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 0))

	// 60 events over 1 minute = 60/min.
	require.Equal(t, 60.0, CalcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", 60))

	// 120 events over 2 minutes = 60/min.
	require.Equal(t, 60.0, CalcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z", 120))

	// Same timestamps, multiple events = count (single burst).
	require.Equal(t, 5.0, CalcFrequency("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 5))
}
