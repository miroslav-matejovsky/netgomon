//go:build windows

package etw

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIP(t *testing.T) {
	// nil
	require.Equal(t, "", ParseIP(nil))
	// string
	require.Equal(t, "1.2.3.4", ParseIP("1.2.3.4"))
	// net.IP
	require.Equal(t, "10.0.0.1", ParseIP(net.ParseIP("10.0.0.1")))
	// []byte
	require.Equal(t, "127.0.0.1", ParseIP([]byte{127, 0, 0, 1}))
	// uint32 (network/host byte order)
	require.Equal(t, "127.0.0.1", ParseIP(uint32(0x0100007f)))
}

func TestParsePID(t *testing.T) {
	require.Equal(t, uint32(0), ParsePID(nil))
	require.Equal(t, uint32(1234), ParsePID(uint32(1234)))
	require.Equal(t, uint32(5678), ParsePID(int(5678)))
	require.Equal(t, uint32(9012), ParsePID(uint64(9012)))
	require.Equal(t, uint32(3456), ParsePID(float64(3456.0)))
	require.Equal(t, uint32(7890), ParsePID("7890"))
	require.Equal(t, uint32(1111), ParsePID(int64(1111)))
	require.Equal(t, uint32(2222), ParsePID(int32(2222)))
}

func TestFindPIDInMap(t *testing.T) {
	// Exact "PID" key
	require.Equal(t, uint32(100), FindPIDInMap(map[string]interface{}{"PID": uint32(100)}))
	// Case-insensitive "pid"
	require.Equal(t, uint32(200), FindPIDInMap(map[string]interface{}{"pid": uint32(200)}))
	// "ProcessId" key
	require.Equal(t, uint32(300), FindPIDInMap(map[string]interface{}{"ProcessId": uint32(300)}))
	// "ProcessID" key
	require.Equal(t, uint32(400), FindPIDInMap(map[string]interface{}{"ProcessID": uint32(400)}))
	// "processid" lowercase
	require.Equal(t, uint32(500), FindPIDInMap(map[string]interface{}{"processid": uint32(500)}))
	// No PID field
	require.Equal(t, uint32(0), FindPIDInMap(map[string]interface{}{"saddr": "1.2.3.4"}))
	// Empty map
	require.Equal(t, uint32(0), FindPIDInMap(map[string]interface{}{}))
	// Nil map
	require.Equal(t, uint32(0), FindPIDInMap(nil))
}

func TestFindPIDInSlice(t *testing.T) {
	pairs := []NamedValue{
		{Name: "saddr", Value: "1.2.3.4"},
		{Name: "PID", Value: uint32(999)},
		{Name: "dport", Value: uint16(80)},
	}
	require.Equal(t, uint32(999), FindPIDInSlice(pairs))

	// Case-insensitive
	pairs2 := []NamedValue{
		{Name: "processId", Value: uint32(888)},
	}
	require.Equal(t, uint32(888), FindPIDInSlice(pairs2))

	// No PID
	pairs3 := []NamedValue{
		{Name: "saddr", Value: "1.2.3.4"},
	}
	require.Equal(t, uint32(0), FindPIDInSlice(pairs3))

	// Empty
	require.Equal(t, uint32(0), FindPIDInSlice(nil))
}

func TestParsePort(t *testing.T) {
	require.Equal(t, uint16(0), ParsePort(nil))
	require.Equal(t, uint16(80), ParsePort(uint16(80)))
	require.Equal(t, uint16(443), ParsePort(int(443)))
	require.Equal(t, uint16(8080), ParsePort(uint32(8080)))
	require.Equal(t, uint16(53), ParsePort(float64(53.0)))
	require.Equal(t, uint16(22), ParsePort("22"))
}

func TestMapEventID(t *testing.T) {
	// TCP Send (Event 11)
	m := MapEventID(11)
	require.NotNil(t, m)
	require.Equal(t, "SEND", m.State)
	require.False(t, m.IsUDP)
	require.Equal(t, "daddr", m.RemoteIPKey)
	require.Equal(t, "dport", m.RemotePortKey)

	// TCP Recv (Event 10)
	m = MapEventID(10)
	require.NotNil(t, m)
	require.Equal(t, "RECEIVE", m.State)
	require.Equal(t, "saddr", m.RemoteIPKey)

	// TCP Connect IPv6 (Event 24)
	m = MapEventID(24)
	require.NotNil(t, m)
	require.Equal(t, "CONNECT", m.State)

	// TCP Disconnect IPv6 (Event 25)
	m = MapEventID(25)
	require.NotNil(t, m)
	require.Equal(t, "DISCONNECT", m.State)

	// UDP Send (Event 27)
	m = MapEventID(27)
	require.NotNil(t, m)
	require.Equal(t, "SEND", m.State)
	require.True(t, m.IsUDP)

	// UDP Send (Event 42)
	m = MapEventID(42)
	require.NotNil(t, m)
	require.Equal(t, "SEND", m.State)
	require.True(t, m.IsUDP)

	// UDP Recv (Event 43)
	m = MapEventID(43)
	require.NotNil(t, m)
	require.Equal(t, "RECEIVE", m.State)
	require.True(t, m.IsUDP)

	// Unmapped
	require.Nil(t, MapEventID(999))
}

func TestMapEventIDWithParsing(t *testing.T) {
	// Simulate full event parsing like the old parseEventNetworkTuple test
	eventData := map[string]interface{}{
		"saddr": uint32(0x0100007f), // 127.0.0.1
		"sport": uint16(12345),
		"daddr": "8.8.8.8",
		"dport": "53",
	}

	// TCP Send (Event 11)
	m := MapEventID(11)
	require.NotNil(t, m)
	remoteIP := ParseIP(eventData[m.RemoteIPKey])
	remotePort := ParsePort(eventData[m.RemotePortKey])
	localIP := ParseIP(eventData[m.LocalIPKey])
	localPort := ParsePort(eventData[m.LocalPortKey])

	require.Equal(t, "8.8.8.8", remoteIP)
	require.Equal(t, uint16(53), remotePort)
	require.Equal(t, "127.0.0.1", localIP)
	require.Equal(t, uint16(12345), localPort)
	require.False(t, m.IsUDP)
	require.Equal(t, "SEND", m.State)

	// TCP Recv (Event 10)
	m = MapEventID(10)
	remoteIP = ParseIP(eventData[m.RemoteIPKey])
	remotePort = ParsePort(eventData[m.RemotePortKey])
	localIP = ParseIP(eventData[m.LocalIPKey])
	localPort = ParsePort(eventData[m.LocalPortKey])

	require.Equal(t, "127.0.0.1", remoteIP)
	require.Equal(t, uint16(12345), remotePort)
	require.Equal(t, "8.8.8.8", localIP)
	require.Equal(t, uint16(53), localPort)
	require.Equal(t, "RECEIVE", m.State)

	// UDP Send (Event 27)
	m = MapEventID(27)
	remoteIP = ParseIP(eventData[m.RemoteIPKey])
	remotePort = ParsePort(eventData[m.RemotePortKey])
	require.Equal(t, "8.8.8.8", remoteIP)
	require.Equal(t, uint16(53), remotePort)
	require.True(t, m.IsUDP)
	require.Equal(t, "SEND", m.State)
}
