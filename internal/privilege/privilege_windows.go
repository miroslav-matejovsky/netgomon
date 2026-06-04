//go:build windows

package privilege

import "golang.org/x/sys/windows"

// IsElevated returns true if the current process is running with Administrator privileges.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
