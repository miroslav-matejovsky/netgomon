//go:build windows

package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringsContainsSeparator(t *testing.T) {
	require.True(t, stringsContainsSeparator(`C:\path\to\exe`))
	require.True(t, stringsContainsSeparator(`path/to/exe`))
	require.False(t, stringsContainsSeparator(`exe`))
}
