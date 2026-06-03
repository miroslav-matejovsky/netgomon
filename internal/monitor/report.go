package monitor

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
