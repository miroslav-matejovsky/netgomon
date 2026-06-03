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
		return errors.New("target executable path not provided")
	}

	target := os.Args[1]
	if target == "-h" || target == "--help" || target == "help" {
		printUsage()
		return nil
	}

	// Verify target is valid.
	if stringsContainsSeparator(target) {
		absPath, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}
		// Note: The file doesn't have to exist *yet* because the tool waits for the next process instance.
		// But checking if directory exists is nice. For simplicity, we just pass the path.
		target = absPath
	}

	m := monitor.NewMonitor(target, 100*time.Millisecond)
	return m.Run()
}

func isAdmin() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func printUsage() {
	fmt.Println("Usage: netwinmon.exe <path-to-target-executable>")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -h, --help    Show help message")
	fmt.Println()
	fmt.Println("Example:")
	fmt.Println("  netwinmon.exe C:\\dev\\personal\\netwinmon\\cmd\\probe\\probe.exe")
	fmt.Println("  netwinmon.exe probe.exe")
}

func stringsContainsSeparator(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' || s[i] == '\\' {
			return true
		}
	}
	return false
}
