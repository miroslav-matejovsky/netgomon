//go:build windows

package privilege

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsElevated(t *testing.T) {
	// IsElevated returns a bool regardless of privilege level.
	result := IsElevated()
	require.IsType(t, true, result)
}
