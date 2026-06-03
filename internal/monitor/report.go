package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// TCPEndpointRecord represents the aggregated record for a TCP remote endpoint.
type TCPEndpointRecord struct {
	RemoteAddress string         `json:"remote_address"`
	RemotePort    uint16         `json:"remote_port"`
	FirstSeen     string         `json:"first_seen"`
	LastSeen      string         `json:"last_seen"`
	Count         int            `json:"count"`
	InferredHTTP  bool           `json:"inferred_http"`
	States        map[string]int `json:"states"`
}

// UDPEndpointRecord represents the aggregated record for a UDP remote endpoint.
type UDPEndpointRecord struct {
	RemoteAddress string `json:"remote_address"`
	RemotePort    uint16 `json:"remote_port"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
	Count         int    `json:"count"`
	InferredHTTP  bool   `json:"inferred_http"`
}

// Report represents the final output JSON format.
type Report struct {
	PID            uint32              `json:"pid"`
	Path           string              `json:"path"`
	StartTime      string              `json:"start_time"`
	EndTime        string              `json:"end_time"`
	Engine         string              `json:"engine"`
	TCPConnections []TCPEndpointRecord `json:"tcp_connections"`
	UDPEndpoints   []UDPEndpointRecord `json:"udp_endpoints"`
}

func (m *Monitor) writeReport(pid uint32, path string, startTime, endTime time.Time, engine string, tcpMap map[string]*TCPEndpointRecord, udpMap map[string]*UDPEndpointRecord, etwEng *ETWEngine) error {
	var tcpConns []TCPEndpointRecord
	var udpEps []UDPEndpointRecord

	if etwEng != nil {
		etwEng.mu.Lock()
	}
	for _, rec := range tcpMap {
		tcpConns = append(tcpConns, *rec)
	}
	for _, rec := range udpMap {
		udpEps = append(udpEps, *rec)
	}
	if etwEng != nil {
		etwEng.mu.Unlock()
	}

	report := Report{
		PID:            pid,
		Path:           path,
		StartTime:      startTime.UTC().Format(time.RFC3339),
		EndTime:        endTime.UTC().Format(time.RFC3339),
		Engine:         engine,
		TCPConnections: tcpConns,
		UDPEndpoints:   udpEps,
	}

	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Ensure report parent directory exists
	if dir := filepath.Dir(m.ReportPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return os.WriteFile(m.ReportPath, reportBytes, 0644)
}
