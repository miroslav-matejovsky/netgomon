//go:build windows

package monitor

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/stretchr/testify/require"
)

func TestInferHTTP(t *testing.T) {
	require.True(t, inferHTTP(80, 1000))
	require.True(t, inferHTTP(1000, 8080))
	require.False(t, inferHTTP(443, 22))
}

func TestMonitorMatch(t *testing.T) {
	m := NewMonitor("probe.exe", "report.json", "monitor.log", 100*time.Millisecond)
	require.True(t, m.match(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.True(t, m.match(`probe.exe`))
	require.False(t, m.match(`C:\windows\system32\cmd.exe`))

	mFull := NewMonitor(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`, "report.json", "monitor.log", 100*time.Millisecond)
	require.True(t, mFull.match(`c:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.False(t, mFull.match(`C:\dev\personal\netwinmon\cmd\probe\other.exe`))
}

func TestParseIP(t *testing.T) {
	// nil
	require.Equal(t, "", parseIP(nil))
	// string
	require.Equal(t, "1.2.3.4", parseIP("1.2.3.4"))
	// net.IP
	require.Equal(t, "10.0.0.1", parseIP(net.ParseIP("10.0.0.1")))
	// []byte
	require.Equal(t, "127.0.0.1", parseIP([]byte{127, 0, 0, 1}))
	// uint32 (network/host byte order)
	// 0x0100007f is 127.0.0.1 in some representations, let's verify parseIP treats byte shift correctly.
	require.Equal(t, "127.0.0.1", parseIP(uint32(0x0100007f)))
}

func TestParsePort(t *testing.T) {
	require.Equal(t, uint16(0), parsePort(nil))
	require.Equal(t, uint16(80), parsePort(uint16(80)))
	require.Equal(t, uint16(443), parsePort(int(443)))
	require.Equal(t, uint16(8080), parsePort(uint32(8080)))
	require.Equal(t, uint16(53), parsePort(float64(53.0)))
	require.Equal(t, uint16(22), parsePort("22"))
}

func TestParseEventNetworkTuple(t *testing.T) {
	e := &etw.Event{
		EventData: map[string]interface{}{
			"saddr": uint32(0x0100007f), // 127.0.0.1
			"sport": uint16(12345),
			"daddr": "8.8.8.8",
			"dport": "53",
		},
	}

	// Case 1: TCP Send (Event 11)
	e.System.EventID = 11
	remoteIP, remotePort, localIP, localPort, isUDP, state := parseEventNetworkTuple(e)
	require.Equal(t, "8.8.8.8", remoteIP)
	require.Equal(t, uint16(53), remotePort)
	require.Equal(t, "127.0.0.1", localIP)
	require.Equal(t, uint16(12345), localPort)
	require.False(t, isUDP)
	require.Equal(t, "SEND", state)

	// Case 2: TCP Recv (Event 10)
	e.System.EventID = 10
	remoteIP, remotePort, localIP, localPort, isUDP, state = parseEventNetworkTuple(e)
	require.Equal(t, "127.0.0.1", remoteIP)
	require.Equal(t, uint16(12345), remotePort)
	require.Equal(t, "8.8.8.8", localIP)
	require.Equal(t, uint16(53), localPort)
	require.False(t, isUDP)
	require.Equal(t, "RECEIVE", state)

	// Case 3: UDP Send (Event 27)
	e.System.EventID = 27
	remoteIP, remotePort, _, _, isUDP, state = parseEventNetworkTuple(e)
	require.Equal(t, "8.8.8.8", remoteIP)
	require.Equal(t, uint16(53), remotePort)
	require.True(t, isUDP)
	require.Equal(t, "SEND", state)
}

func TestParseTCPV4Table(t *testing.T) {
	buf := make([]byte, 4+24)
	binary.LittleEndian.PutUint32(buf[0:4], 1) // numEntries

	rowOffset := 4
	binary.LittleEndian.PutUint32(buf[rowOffset:rowOffset+4], mibTcpStateEstab) // DwState

	localIP := net.ParseIP("127.0.0.1").To4()
	copy(buf[rowOffset+4:rowOffset+8], localIP)

	binary.LittleEndian.PutUint32(buf[rowOffset+8:rowOffset+12], 0x5000)

	remoteIP := net.ParseIP("8.8.8.8").To4()
	copy(buf[rowOffset+12:rowOffset+16], remoteIP)

	binary.LittleEndian.PutUint32(buf[rowOffset+16:rowOffset+20], 0xBB01)

	binary.LittleEndian.PutUint32(buf[rowOffset+20:rowOffset+24], 1234)

	conns, err := parseTCPV4Table(buf)
	require.NoError(t, err)
	require.Len(t, conns, 1)

	c := conns[0]
	require.Equal(t, "127.0.0.1", c.LocalIP.String())
	require.Equal(t, uint16(80), c.LocalPort)
	require.Equal(t, "8.8.8.8", c.RemoteIP.String())
	require.Equal(t, uint16(443), c.RemotePort)
	require.Equal(t, "ESTABLISHED", c.State)
	require.Equal(t, uint32(1234), c.PID)
}

func TestParseUDPV4Table(t *testing.T) {
	buf := make([]byte, 4+12)
	binary.LittleEndian.PutUint32(buf[0:4], 1) // numEntries

	rowOffset := 4
	localIP := net.ParseIP("192.168.1.50").To4()
	copy(buf[rowOffset:rowOffset+4], localIP)

	binary.LittleEndian.PutUint32(buf[rowOffset+4:rowOffset+8], 0x3500)

	binary.LittleEndian.PutUint32(buf[rowOffset+8:rowOffset+12], 5678)

	eps, err := parseUDPV4Table(buf)
	require.NoError(t, err)
	require.Len(t, eps, 1)

	ep := eps[0]
	require.Equal(t, "192.168.1.50", ep.LocalIP.String())
	require.Equal(t, uint16(53), ep.LocalPort)
	require.Equal(t, uint32(5678), ep.PID)
}
