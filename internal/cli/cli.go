//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/miroslav-matejovsky/netwinmon/internal/monitor"
	"golang.org/x/sys/windows"
)

// Run parses arguments and starts the monitor.
func Run() error {
	if !isAdmin() {
		return errors.New("administrator privileges are required to run this tool")
	}

	if len(os.Args) < 2 {
		printUsage()
		return errors.New("missing arguments")
	}

	firstArg := os.Args[1]
	if firstArg == "-h" || firstArg == "--help" || firstArg == "help" {
		printUsage()
		return nil
	}

	if len(os.Args) < 4 {
		printUsage()
		return errors.New("missing arguments: path to target exe, report json path, and monitor log path are required")
	}

	target := os.Args[1]
	reportPath := os.Args[2]
	logPath := os.Args[3]

	// Verify target is valid.
	if stringsContainsSeparator(target) {
		absPath, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
		target = absPath
	}

	m := monitor.NewMonitor(target, reportPath, logPath, 100*time.Millisecond)
	return m.Run()
}

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func printUsage() {
	fmt.Println("Usage: netwinmon.exe <path-to-target-executable> <path-to-report-json> <path-to-monitor-log>")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  netwinmon.exe probe.exe report.json monitor.log")
}

func stringsContainsSeparator(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' || s[i] == '\\' {
			return true
		}
	}
	return false
}
