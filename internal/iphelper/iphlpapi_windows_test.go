//go:build windows

package iphelper

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

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
