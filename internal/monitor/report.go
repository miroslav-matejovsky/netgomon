package monitor

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

// calcFrequency computes events per minute from first/last seen timestamps and count.
func calcFrequency(firstSeen, lastSeen string, count int) float64 {
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

func (m *Monitor) writeReport() error {
	m.mu.RLock()

	var processes []ProcessReport
	for _, ps := range m.activeProcesses {
		pr := ProcessReport{
			PID:       ps.PID,
			Path:      ps.Path,
			StartTime: ps.StartTime.UTC().Format(time.RFC3339),
		}

		tcpConns := make([]TCPEndpointRecord, 0, len(ps.TCP))
		for _, rec := range ps.TCP {
			r := *rec
			r.EventFrequency = calcFrequency(r.FirstSeen, r.LastSeen, r.Count)
			tcpConns = append(tcpConns, r)
		}
		pr.TCPConnections = tcpConns

		udpEps := make([]UDPEndpointRecord, 0, len(ps.UDP))
		for _, rec := range ps.UDP {
			r := *rec
			r.EventFrequency = calcFrequency(r.FirstSeen, r.LastSeen, r.Count)
			udpEps = append(udpEps, r)
		}
		pr.UDPEndpoints = udpEps

		processes = append(processes, pr)
	}
	m.mu.RUnlock()

	report := Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Processes:   processes,
	}

	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Ensure report parent directory exists.
	if dir := filepath.Dir(m.ReportPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return os.WriteFile(m.ReportPath, reportBytes, 0644)
}
