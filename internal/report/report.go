package report

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"time"
)

// TCPEndpointRecord represents the aggregated record for a TCP remote endpoint.
type TCPEndpointRecord struct {
	RemoteAddress     string         `json:"remote_address"`
	RemotePort        uint16         `json:"remote_port"`
	FirstSeen         string         `json:"first_seen"`
	LastSeen          string         `json:"last_seen"`
	Count             int            `json:"count"`
	InferredHTTP      bool           `json:"inferred_http"`
	States            map[string]int `json:"states"`
	Tool              string         `json:"tool"`
	FailedConnections int            `json:"failed_connections"`
	EventFrequency    float64        `json:"event_frequency_per_min"`
}

// UDPEndpointRecord represents the aggregated record for a UDP remote endpoint.
type UDPEndpointRecord struct {
	RemoteAddress  string  `json:"remote_address"`
	RemotePort     uint16  `json:"remote_port"`
	FirstSeen      string  `json:"first_seen"`
	LastSeen       string  `json:"last_seen"`
	Count          int     `json:"count"`
	InferredHTTP   bool    `json:"inferred_http"`
	Tool           string  `json:"tool"`
	EventFrequency float64 `json:"event_frequency_per_min"`
}

// ProcessReport represents a single monitored process in the report.
type ProcessReport struct {
	PID            uint32              `json:"pid"`
	Path           string              `json:"path"`
	StartTime      string              `json:"start_time"`
	TCPConnections []TCPEndpointRecord `json:"tcp_connections"`
	UDPEndpoints   []UDPEndpointRecord `json:"udp_endpoints"`
}

// Report represents the final output JSON format (multi-process).
type Report struct {
	GeneratedAt string          `json:"generated_at"`
	Processes   []ProcessReport `json:"processes"`
}

// CalcFrequency computes events per minute from first/last seen timestamps and count.
func CalcFrequency(firstSeen, lastSeen string, count int) float64 {
	if count <= 1 {
		return float64(count)
	}
	t1, err1 := time.Parse(time.RFC3339, firstSeen)
	t2, err2 := time.Parse(time.RFC3339, lastSeen)
	if err1 != nil || err2 != nil {
		return 0
	}
	durationMin := t2.Sub(t1).Minutes()
	if durationMin <= 0 {
		return float64(count) // single burst
	}
	return math.Round(float64(count)/durationMin*100) / 100
}

// Write serializes the report to JSON and writes it to the specified path.
func Write(path string, rep Report) error {
	reportBytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return os.WriteFile(path, reportBytes, 0644)
}
