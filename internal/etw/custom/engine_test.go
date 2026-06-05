//go:build windows

package custom

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestIsIPv6Event(t *testing.T) {
	ipv4Events := []uint16{10, 11, 12, 13, 14, 15, 16, 17, 18, 26, 27}
	for _, id := range ipv4Events {
		require.False(t, isIPv6Event(id), "event %d should be IPv4", id)
	}

	ipv6Events := []uint16{20, 21, 22, 23, 24, 25, 28, 29, 42, 43}
	for _, id := range ipv6Events {
		require.True(t, isIPv6Event(id), "event %d should be IPv6", id)
	}
}

func TestParseIPv4Data(t *testing.T) {
	// Build a minimal IPv4 event payload.
	// Layout: PID(4) + size(4) + daddr(4) + saddr(4) + dport(2) + sport(2) = 20 bytes
	data := make([]byte, 20)

	// PID = 1234 (little-endian)
	binary.LittleEndian.PutUint32(data[0:4], 1234)

	// size = 100
	binary.LittleEndian.PutUint32(data[4:8], 100)

	// daddr = 8.8.8.8
	data[8] = 8
	data[9] = 8
	data[10] = 8
	data[11] = 8

	// saddr = 192.168.1.10
	data[12] = 192
	data[13] = 168
	data[14] = 1
	data[15] = 10

	// dport = 443 (network byte order = big-endian)
	binary.BigEndian.PutUint16(data[16:18], 443)

	// sport = 54321 (network byte order)
	binary.BigEndian.PutUint16(data[18:20], 54321)

	result := parseIPv4Data(unsafe.Pointer(&data[0]), uint16(len(data)))
	require.NotNil(t, result)

	require.Equal(t, uint32(1234), result.PID)
	require.Equal(t, uint32(100), result.Size)
	require.Equal(t, "8.8.8.8", result.DstAddr.To4().String())
	require.Equal(t, "192.168.1.10", result.SrcAddr.To4().String())
	require.Equal(t, uint16(443), result.DstPort)
	require.Equal(t, uint16(54321), result.SrcPort)
}

func TestParseIPv4DataTooShort(t *testing.T) {
	data := make([]byte, 10) // too short
	result := parseIPv4Data(unsafe.Pointer(&data[0]), uint16(len(data)))
	require.Nil(t, result)
}

func TestParseIPv6Data(t *testing.T) {
	// Layout: PID(4) + size(4) + daddr(16) + saddr(16) + dport(2) + sport(2) = 44 bytes
	data := make([]byte, 44)

	// PID = 5678
	binary.LittleEndian.PutUint32(data[0:4], 5678)

	// size = 200
	binary.LittleEndian.PutUint32(data[4:8], 200)

	// daddr = ::1 (loopback)
	dstIP := net.ParseIP("::1")
	copy(data[8:24], dstIP.To16())

	// saddr = fe80::1
	srcIP := net.ParseIP("fe80::1")
	copy(data[24:40], srcIP.To16())

	// dport = 80
	binary.BigEndian.PutUint16(data[40:42], 80)

	// sport = 12345
	binary.BigEndian.PutUint16(data[42:44], 12345)

	result := parseIPv6Data(unsafe.Pointer(&data[0]), uint16(len(data)))
	require.NotNil(t, result)

	require.Equal(t, uint32(5678), result.PID)
	require.Equal(t, uint32(200), result.Size)
	require.Equal(t, "::1", result.DstAddr.String())
	require.Equal(t, "fe80::1", result.SrcAddr.String())
	require.Equal(t, uint16(80), result.DstPort)
	require.Equal(t, uint16(12345), result.SrcPort)
}

func TestParseIPv6DataTooShort(t *testing.T) {
	data := make([]byte, 30) // too short
	result := parseIPv6Data(unsafe.Pointer(&data[0]), uint16(len(data)))
	require.Nil(t, result)
}

func TestParseEventDataNilPtr(t *testing.T) {
	result := parseEventData(10, nil, 20)
	require.Nil(t, result)
}

func TestParseEventDataZeroLen(t *testing.T) {
	data := make([]byte, 20)
	result := parseEventData(10, unsafe.Pointer(&data[0]), 0)
	require.Nil(t, result)
}

func TestParseEventDataIPv4VsIPv6(t *testing.T) {
	// IPv4 event (ID 11 = TCP Send IPv4)
	ipv4Data := make([]byte, 20)
	binary.LittleEndian.PutUint32(ipv4Data[0:4], 100)
	binary.LittleEndian.PutUint32(ipv4Data[4:8], 50)
	ipv4Data[8], ipv4Data[9], ipv4Data[10], ipv4Data[11] = 1, 2, 3, 4
	ipv4Data[12], ipv4Data[13], ipv4Data[14], ipv4Data[15] = 10, 0, 0, 1
	binary.BigEndian.PutUint16(ipv4Data[16:18], 80)
	binary.BigEndian.PutUint16(ipv4Data[18:20], 5000)

	result := parseEventData(11, unsafe.Pointer(&ipv4Data[0]), uint16(len(ipv4Data)))
	require.NotNil(t, result)
	require.Equal(t, "1.2.3.4", result.DstAddr.To4().String())

	// IPv6 event (ID 21 = TCP Send IPv6) - needs 44 bytes
	ipv6Data := make([]byte, 44)
	binary.LittleEndian.PutUint32(ipv6Data[0:4], 200)
	dstV6 := net.ParseIP("2001:db8::1")
	copy(ipv6Data[8:24], dstV6.To16())
	srcV6 := net.ParseIP("::1")
	copy(ipv6Data[24:40], srcV6.To16())
	binary.BigEndian.PutUint16(ipv6Data[40:42], 443)
	binary.BigEndian.PutUint16(ipv6Data[42:44], 6000)

	result = parseEventData(21, unsafe.Pointer(&ipv6Data[0]), uint16(len(ipv6Data)))
	require.NotNil(t, result)
	require.Equal(t, "2001:db8::1", result.DstAddr.String())
}

func TestStructSizes(t *testing.T) {
	// Verify critical struct sizes match Windows layout.
	require.Equal(t, 16, int(unsafe.Sizeof(eventDescriptor{})), "eventDescriptor")
	require.Equal(t, 48, int(unsafe.Sizeof(wnodeHeader{})), "wnodeHeader")
	require.Equal(t, 48, int(unsafe.Sizeof(eventTraceHeader{})), "eventTraceHeader")
	require.Equal(t, 88, int(unsafe.Sizeof(eventTrace{})), "eventTrace")
	require.Equal(t, 4, int(unsafe.Sizeof(etwBufferContext{})), "etwBufferContext")
}

func TestEventTraceLogfileOffsets(t *testing.T) {
	// Verify field offsets of eventTraceLogfileW match Windows EVENT_TRACE_LOGFILEW layout.
	// Incorrect offsets mean OpenTraceW reads callback pointers from wrong memory.
	var logfile eventTraceLogfileW
	require.Equal(t, uintptr(0), unsafe.Offsetof(logfile.LogFileName), "LogFileName")
	require.Equal(t, uintptr(8), unsafe.Offsetof(logfile.LoggerName), "LoggerName")
	require.Equal(t, uintptr(16), unsafe.Offsetof(logfile.CurrentTime), "CurrentTime")
	require.Equal(t, uintptr(24), unsafe.Offsetof(logfile.BuffersRead), "BuffersRead")
	require.Equal(t, uintptr(28), unsafe.Offsetof(logfile.Union1), "Union1")
	require.Equal(t, uintptr(32), unsafe.Offsetof(logfile.CurrentEvent), "CurrentEvent")
	require.Equal(t, uintptr(120), unsafe.Offsetof(logfile.LogfileHeader), "LogfileHeader")
	require.Equal(t, uintptr(400), unsafe.Offsetof(logfile.BufferCallback), "BufferCallback")
	require.Equal(t, uintptr(408), unsafe.Offsetof(logfile.BufferSize), "BufferSize")
	require.Equal(t, uintptr(412), unsafe.Offsetof(logfile.Filled), "Filled")
	require.Equal(t, uintptr(416), unsafe.Offsetof(logfile.EventsLost), "EventsLost")
	require.Equal(t, uintptr(424), unsafe.Offsetof(logfile.EventRecordCallback), "EventRecordCallback")
	require.Equal(t, uintptr(432), unsafe.Offsetof(logfile.IsKernelTrace), "IsKernelTrace")
	require.Equal(t, uintptr(440), unsafe.Offsetof(logfile.Context), "Context")
	require.Equal(t, uintptr(448), unsafe.Sizeof(logfile), "total size")
}

func TestKernelNetworkProviderGUID(t *testing.T) {
	// Verify GUID is {7DD42A49-5329-4832-8DFD-43D979153A88}.
	require.Equal(t, uint32(0x7DD42A49), kernelNetworkProviderGUID.Data1)
	require.Equal(t, uint16(0x5329), kernelNetworkProviderGUID.Data2)
	require.Equal(t, uint16(0x4832), kernelNetworkProviderGUID.Data3)
	require.Equal(t, [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}, kernelNetworkProviderGUID.Data4)
}
