//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/miroslav-matejovsky/netwinmon/internal/api"
	"github.com/miroslav-matejovsky/netwinmon/internal/engine"
)

// Run parses arguments and starts the monitor.
func Run(ctx context.Context) error {
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

	eng := engine.NewEngine([]string{target}, reportPath, logPath, 100*time.Millisecond, false)

	apiSrv := api.NewServer("127.0.0.1:8080", eng)
	if err := apiSrv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to start API server: %v\n", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = apiSrv.Stop(stopCtx)
	}()

	return eng.Run(ctx)
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
