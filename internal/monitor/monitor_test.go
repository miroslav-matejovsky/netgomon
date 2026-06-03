//go:build windows

package monitor

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInferHTTP(t *testing.T) {
	require.True(t, inferHTTP(80, 1000))
	require.True(t, inferHTTP(1000, 8080))
	require.False(t, inferHTTP(443, 22))
}

func TestMonitorMatch(t *testing.T) {
	m := NewMonitor("probe.exe", 100*time.Millisecond)
	require.True(t, m.match(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.True(t, m.match(`probe.exe`))
	require.False(t, m.match(`C:\windows\system32\cmd.exe`))

	mFull := NewMonitor(`C:\dev\personal\netwinmon\cmd\probe\probe.exe`, 100*time.Millisecond)
	require.True(t, mFull.match(`c:\dev\personal\netwinmon\cmd\probe\probe.exe`))
	require.False(t, mFull.match(`C:\dev\personal\netwinmon\cmd\probe\other.exe`))
}

func TestParseTCPV4Table(t *testing.T) {
	// Let's build a mock binary buffer for MIB_TCPTABLE_OWNER_PID.
	// Header: 1 entry (4 bytes)
	// Entry: dwState (4), dwLocalAddr (4), dwLocalPort (4), dwRemoteAddr (4), dwRemotePort (4), dwOwningPid (4)
	buf := make([]byte, 4+24)
	binary.LittleEndian.PutUint32(buf[0:4], 1) // numEntries

	rowOffset := 4
	binary.LittleEndian.PutUint32(buf[rowOffset:rowOffset+4], mibTcpStateEstab) // DwState

	// Local IP: 127.0.0.1
	localIP := net.ParseIP("127.0.0.1").To4()
	copy(buf[rowOffset+4:rowOffset+8], localIP)

	// Local Port: 80 (in network byte order: 0x0050)
	// So in memory as a uint32: the lower 16 bits have the bytes in big-endian order (0x00, 0x50).
	// Because Windows API packs it in network byte order in the lower 16 bits:
	// Mem layout: [0x00, 0x50, 0x00, 0x00] which is 0x5000 in little endian.
	binary.LittleEndian.PutUint32(buf[rowOffset+8:rowOffset+12], 0x5000)

	// Remote IP: 8.8.8.8
	remoteIP := net.ParseIP("8.8.8.8").To4()
	copy(buf[rowOffset+12:rowOffset+16], remoteIP)

	// Remote Port: 443 (in network byte order: 0x01BB)
	// Mem layout: [0x01, 0xBB, 0x00, 0x00] which is 0xBB01 in little endian.
	binary.LittleEndian.PutUint32(buf[rowOffset+16:rowOffset+20], 0xBB01)

	// Owning PID: 1234
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
	// Header: 1 entry (4 bytes)
	// Entry: dwLocalAddr (4), dwLocalPort (4), dwOwningPid (4)
	buf := make([]byte, 4+12)
	binary.LittleEndian.PutUint32(buf[0:4], 1) // numEntries

	rowOffset := 4
	localIP := net.ParseIP("192.168.1.50").To4()
	copy(buf[rowOffset:rowOffset+4], localIP)

	// Local Port: 53 (network byte order: 0x0035, so memory little-endian is 0x3500)
	binary.LittleEndian.PutUint32(buf[rowOffset+4:rowOffset+8], 0x3500)

	// PID: 5678
	binary.LittleEndian.PutUint32(buf[rowOffset+8:rowOffset+12], 5678)

	eps, err := parseUDPV4Table(buf)
	require.NoError(t, err)
	require.Len(t, eps, 1)

	ep := eps[0]
	require.Equal(t, "192.168.1.50", ep.LocalIP.String())
	require.Equal(t, uint16(53), ep.LocalPort)
	require.Equal(t, uint32(5678), ep.PID)
}
