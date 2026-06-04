//go:build windows

package monitor

import (
	"fmt"
	"time"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
)

// handleNetworkEvent aggregates a single ETW network event into the maps.
func (m *Monitor) handleNetworkEvent(ev etwapi.NetworkEvent, tcpMap map[string]*TCPEndpointRecord, udpMap map[string]*UDPEndpointRecord) {
	nowStr := ev.Timestamp.UTC().Format(time.RFC3339)
	key := fmt.Sprintf("%s:%s:%d", ev.Tool, ev.RemoteIP, ev.RemotePort)

	m.mu.Lock()
	defer m.mu.Unlock()

	if ev.IsUDP {
		if rec, ok := udpMap[key]; ok {
			rec.LastSeen = nowStr
			rec.Count++
		} else {
			udpMap[key] = &UDPEndpointRecord{
				RemoteAddress: ev.RemoteIP,
				RemotePort:    ev.RemotePort,
				FirstSeen:     nowStr,
				LastSeen:      nowStr,
				Count:         1,
				InferredHTTP:  inferHTTP(0, ev.RemotePort),
				Tool:          ev.Tool,
			}
		}
	} else {
		if rec, ok := tcpMap[key]; ok {
			rec.LastSeen = nowStr
			rec.Count++
			rec.States[ev.State]++
			if ev.State == "CONNECT_FAIL" {
				rec.FailedConnections++
			}
		} else {
			failed := 0
			if ev.State == "CONNECT_FAIL" {
				failed = 1
			}
			tcpMap[key] = &TCPEndpointRecord{
				RemoteAddress:     ev.RemoteIP,
				RemotePort:        ev.RemotePort,
				FirstSeen:         nowStr,
				LastSeen:          nowStr,
				Count:             1,
				InferredHTTP:      inferHTTP(0, ev.RemotePort),
				States:            map[string]int{ev.State: 1},
				Tool:              ev.Tool,
				FailedConnections: failed,
			}
		}
	}
}

func inferHTTP(localPort, remotePort uint16) bool {
	return localPort == 80 || localPort == 8080 || remotePort == 80 || remotePort == 8080
}
