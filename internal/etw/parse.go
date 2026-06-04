//go:build windows

package etw

import (
	"fmt"
	"net"
	"strings"
)

// ParseIP extracts an IP address string from various ETW EventData value types.
func ParseIP(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case net.IP:
		return v.String()
	case []byte:
		if len(v) >= 16 {
			return net.IP(v[:16]).String()
		}
		if len(v) >= 4 {
			return net.IP(v[:4]).String()
		}
	case uint32:
		ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
		return ip.String()
	}
	return fmt.Sprintf("%v", val)
}

// ParsePort extracts a port number from various ETW EventData value types.
func ParsePort(val interface{}) uint16 {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case uint16:
		return v
	case int:
		return uint16(v)
	case uint32:
		return uint16(v)
	case float64:
		return uint16(v)
	}
	var p uint16
	_, _ = fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &p)
	return p
}

// ParsePID extracts a process ID from an ETW EventData value type.
func ParsePID(val interface{}) uint32 {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case uint32:
		return v
	case int:
		return uint32(v)
	case int32:
		return uint32(v)
	case int64:
		return uint32(v)
	case uint64:
		return uint32(v)
	case float64:
		return uint32(v)
	}
	var p uint32
	_, _ = fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &p)
	return p
}

// pidFieldNames lists recognized PID field names in ETW EventData (lowercase for comparison).
var pidFieldNames = []string{"pid", "processid"}

// FindPIDInMap searches a map of ETW EventData fields for a PID value.
// Uses case-insensitive matching on known PID field names.
// Returns 0 if no PID field found.
func FindPIDInMap(fields map[string]interface{}) uint32 {
	for k, v := range fields {
		if isPIDKey(k) {
			return ParsePID(v)
		}
	}
	return 0
}

// FindPIDInSlice searches a slice of key-value pairs for a PID value.
// Each pair must have Name and Value fields (satisfied by goetw Properties).
// Uses case-insensitive matching on known PID field names.
// Returns 0 if no PID field found.
func FindPIDInSlice(pairs []NamedValue) uint32 {
	for _, p := range pairs {
		if isPIDKey(p.Name) {
			return ParsePID(p.Value)
		}
	}
	return 0
}

// NamedValue is a name-value pair used for ETW event properties.
type NamedValue struct {
	Name  string
	Value interface{}
}

func isPIDKey(key string) bool {
	lower := strings.ToLower(key)
	for _, name := range pidFieldNames {
		if lower == name {
			return true
		}
	}
	return false
}

// EventMapping holds the parsed result of mapping an ETW Event ID to network tuple fields.
type EventMapping struct {
	RemoteIPKey   string
	RemotePortKey string
	LocalIPKey    string
	LocalPortKey  string
	IsUDP         bool
	State         string
}

// MapEventID maps a Microsoft-Windows-Kernel-Network Event ID to field keys and state.
// Returns nil if the event ID is not a recognized network event.
func MapEventID(id uint16) *EventMapping {
	switch id {
	case 10, 20: // TCP Recv (IPv4, IPv6)
		return &EventMapping{
			RemoteIPKey: "saddr", RemotePortKey: "sport",
			LocalIPKey: "daddr", LocalPortKey: "dport",
			State: "RECEIVE",
		}
	case 11, 21: // TCP Send (IPv4, IPv6)
		return &EventMapping{
			RemoteIPKey: "daddr", RemotePortKey: "dport",
			LocalIPKey: "saddr", LocalPortKey: "sport",
			State: "SEND",
		}
	case 12, 16, 24: // TCP Connect (IPv4, IPv4 Retransmit, IPv6)
		return &EventMapping{
			RemoteIPKey: "daddr", RemotePortKey: "dport",
			LocalIPKey: "saddr", LocalPortKey: "sport",
			State: "CONNECT",
		}
	case 13, 22, 25: // TCP Disconnect (IPv4, IPv6, IPv6)
		return &EventMapping{
			RemoteIPKey: "daddr", RemotePortKey: "dport",
			LocalIPKey: "saddr", LocalPortKey: "sport",
			State: "DISCONNECT",
		}
	case 14, 23: // TCP Reconnect (IPv4, IPv6)
		return &EventMapping{
			RemoteIPKey: "daddr", RemotePortKey: "dport",
			LocalIPKey: "saddr", LocalPortKey: "sport",
			State: "RECONNECT",
		}
	case 15, 18: // TCP Accept (IPv4, IPv4)
		return &EventMapping{
			RemoteIPKey: "saddr", RemotePortKey: "sport",
			LocalIPKey: "daddr", LocalPortKey: "dport",
			State: "ACCEPT",
		}
	case 17: // TCP Connect Fail
		return &EventMapping{
			RemoteIPKey: "daddr", RemotePortKey: "dport",
			LocalIPKey: "saddr", LocalPortKey: "sport",
			State: "CONNECT_FAIL",
		}
	case 26, 28, 43: // UDP Recv
		return &EventMapping{
			RemoteIPKey: "saddr", RemotePortKey: "sport",
			LocalIPKey: "daddr", LocalPortKey: "dport",
			IsUDP: true, State: "RECEIVE",
		}
	case 27, 29, 42: // UDP Send
		return &EventMapping{
			RemoteIPKey: "daddr", RemotePortKey: "dport",
			LocalIPKey: "saddr", LocalPortKey: "sport",
			IsUDP: true, State: "SEND",
		}
	}
	return nil
}
