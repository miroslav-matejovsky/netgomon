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
