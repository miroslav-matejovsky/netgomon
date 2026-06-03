// Package cli implements the command-line interface for the netwinmon utility.
//
// Domain Concepts:
// - Argument Validation: Ensures a target executable path is provided and exists.
// - Administrator Check: Validates that the tool runs with elevated privileges required for process inspection and table snapping.
// - Execution Flow: Instantiates the monitor and starts monitoring.
package cli
