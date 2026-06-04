//go:build windows

package iphelper

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IP Helper API Constants.
const (
	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1

	errInsufficientBuffer = 122
)

// TCP States.
const (
	mibTcpStateClosed    = 1
	mibTcpStateListen    = 2
	mibTcpStateSynSent   = 3
	mibTcpStateSynRcvd   = 4
	mibTcpStateEstab     = 5
	mibTcpStateFinWait1  = 6
	mibTcpStateFinWait2  = 7
	mibTcpStateCloseWait = 8
	mibTcpStateClosing   = 9
	mibTcpStateLastAck   = 10
	mibTcpStateTimeWait  = 11
	mibTcpStateDeleteTcb = 12
)

var (
	modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

// MIB_TCPROW_OWNER_PID matches Windows API struct.
type MIB_TCPROW_OWNER_PID struct {
	DwState      uint32
	DwLocalAddr  uint32
	DwLocalPort  uint32
	DwRemoteAddr uint32
	DwRemotePort uint32
	DwOwningPid  uint32
}

// MIB_TCP6ROW_OWNER_PID matches Windows API struct.
type MIB_TCP6ROW_OWNER_PID struct {
	UcLocalAddr     [16]byte
	DwLocalScopeId  uint32
	DwLocalPort     uint32
	UcRemoteAddr    [16]byte
	DwRemoteScopeId uint32
	DwRemotePort    uint32
	DwState         uint32
	DwOwningPid     uint32
}

// MIB_UDPROW_OWNER_PID matches Windows API struct.
type MIB_UDPROW_OWNER_PID struct {
	DwLocalAddr uint32
	DwLocalPort uint32
	DwOwningPid uint32
}

// MIB_UDP6ROW_OWNER_PID matches Windows API struct.
type MIB_UDP6ROW_OWNER_PID struct {
	UcLocalAddr    [16]byte
	DwLocalScopeId uint32
	DwLocalPort    uint32
	DwOwningPid    uint32
}

// TCPConn represents parsed TCP connection.
type TCPConn struct {
	LocalIP    net.IP
	LocalPort  uint16
	RemoteIP   net.IP
	RemotePort uint16
	State      string
	PID        uint32
}

// UDPEndpoint represents parsed UDP endpoint.
type UDPEndpoint struct {
	LocalIP   net.IP
	LocalPort uint16
	PID       uint32
}

// Resolve TCP state code to string.
func resolveTCPState(state uint32) string {
	switch state {
	case mibTcpStateClosed:
		return "CLOSED"
	case mibTcpStateListen:
		return "LISTEN"
	case mibTcpStateSynSent:
		return "SYN_SENT"
	case mibTcpStateSynRcvd:
		return "SYN_RCVD"
	case mibTcpStateEstab:
		return "ESTABLISHED"
	case mibTcpStateFinWait1:
		return "FIN_WAIT1"
	case mibTcpStateFinWait2:
		return "FIN_WAIT2"
	case mibTcpStateCloseWait:
		return "CLOSE_WAIT"
	case mibTcpStateClosing:
		return "CLOSING"
	case mibTcpStateLastAck:
		return "LAST_ACK"
	case mibTcpStateTimeWait:
		return "TIME_WAIT"
	case mibTcpStateDeleteTcb:
		return "DELETE_TCB"
	default:
		return "UNKNOWN"
	}
}

// GetTCPConnections retrieves all active TCP connections.
func GetTCPConnections() ([]TCPConn, error) {
	var conns []TCPConn

	// IPv4 TCP Table.
	v4Buf, err := getTable(procGetExtendedTcpTable, afInet, tcpTableOwnerPidAll)
	if err == nil {
		c, err := parseTCPV4Table(v4Buf)
		if err == nil {
			conns = append(conns, c...)
		}
	}

	// IPv6 TCP Table.
	v6Buf, err := getTable(procGetExtendedTcpTable, afInet6, tcpTableOwnerPidAll)
	if err == nil {
		c, err := parseTCPV6Table(v6Buf)
		if err == nil {
			conns = append(conns, c...)
		}
	}

	return conns, nil
}

// GetUDPEndpoints retrieves all bound UDP endpoints.
func GetUDPEndpoints() ([]UDPEndpoint, error) {
	var eps []UDPEndpoint

	// IPv4 UDP Table.
	v4Buf, err := getTable(procGetExtendedUdpTable, afInet, udpTableOwnerPid)
	if err == nil {
		e, err := parseUDPV4Table(v4Buf)
		if err == nil {
			eps = append(eps, e...)
		}
	}

	// IPv6 UDP Table.
	v6Buf, err := getTable(procGetExtendedUdpTable, afInet6, udpTableOwnerPid)
	if err == nil {
		e, err := parseUDPV6Table(v6Buf)
		if err == nil {
			eps = append(eps, e...)
		}
	}

	return eps, nil
}

func getTable(proc *syscall.LazyProc, af uint32, class uint32) ([]byte, error) {
	var size uint32
	r1, _, _ := proc.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(af),
		uintptr(class),
		0,
	)
	if r1 != 0 && r1 != errInsufficientBuffer {
		return nil, fmt.Errorf("iphlpapi call failed: error %d", r1)
	}

	for {
		buf := make([]byte, size)
		r1, _, _ := proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1,
			uintptr(af),
			uintptr(class),
			0,
		)
		if r1 == 0 {
			return buf, nil
		}
		if r1 == errInsufficientBuffer {
			continue
		}
		return nil, fmt.Errorf("iphlpapi call failed: error %d", r1)
	}
}

func parseTCPV4Table(buf []byte) ([]TCPConn, error) {
	if len(buf) < 4 {
		return nil, fmt.Errorf("buffer too small")
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := int(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))
	expectedMinSize := 4 + int(numEntries)*rowSize
	if len(buf) < expectedMinSize {
		return nil, fmt.Errorf("buffer size mismatch")
	}

	conns := make([]TCPConn, 0, numEntries)
	for i := 0; i < int(numEntries); i++ {
		offset := 4 + i*rowSize
		row := *(*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		// Decode IP.
		localIP := net.IPv4(byte(row.DwLocalAddr), byte(row.DwLocalAddr>>8), byte(row.DwLocalAddr>>16), byte(row.DwLocalAddr>>24))
		remoteIP := net.IPv4(byte(row.DwRemoteAddr), byte(row.DwRemoteAddr>>8), byte(row.DwRemoteAddr>>16), byte(row.DwRemoteAddr>>24))

		// Decode Port (network byte order).
		localPort := uint16(windows.Ntohs(uint16(row.DwLocalPort)))
		remotePort := uint16(windows.Ntohs(uint16(row.DwRemotePort)))

		conns = append(conns, TCPConn{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      resolveTCPState(row.DwState),
			PID:        row.DwOwningPid,
		})
	}
	return conns, nil
}

func parseTCPV6Table(buf []byte) ([]TCPConn, error) {
	if len(buf) < 4 {
		return nil, fmt.Errorf("buffer too small")
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := int(unsafe.Sizeof(MIB_TCP6ROW_OWNER_PID{}))
	expectedMinSize := 4 + int(numEntries)*rowSize
	if len(buf) < expectedMinSize {
		return nil, fmt.Errorf("buffer size mismatch")
	}

	conns := make([]TCPConn, 0, numEntries)
	for i := 0; i < int(numEntries); i++ {
		offset := 4 + i*rowSize
		row := *(*MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		localIP := make(net.IP, 16)
		copy(localIP, row.UcLocalAddr[:])
		remoteIP := make(net.IP, 16)
		copy(remoteIP, row.UcRemoteAddr[:])

		localPort := uint16(windows.Ntohs(uint16(row.DwLocalPort)))
		remotePort := uint16(windows.Ntohs(uint16(row.DwRemotePort)))

		conns = append(conns, TCPConn{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      resolveTCPState(row.DwState),
			PID:        row.DwOwningPid,
		})
	}
	return conns, nil
}

func parseUDPV4Table(buf []byte) ([]UDPEndpoint, error) {
	if len(buf) < 4 {
		return nil, fmt.Errorf("buffer too small")
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := int(unsafe.Sizeof(MIB_UDPROW_OWNER_PID{}))
	expectedMinSize := 4 + int(numEntries)*rowSize
	if len(buf) < expectedMinSize {
		return nil, fmt.Errorf("buffer size mismatch")
	}

	eps := make([]UDPEndpoint, 0, numEntries)
	for i := 0; i < int(numEntries); i++ {
		offset := 4 + i*rowSize
		row := *(*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		localIP := net.IPv4(byte(row.DwLocalAddr), byte(row.DwLocalAddr>>8), byte(row.DwLocalAddr>>16), byte(row.DwLocalAddr>>24))
		localPort := uint16(windows.Ntohs(uint16(row.DwLocalPort)))

		eps = append(eps, UDPEndpoint{
			LocalIP:   localIP,
			LocalPort: localPort,
			PID:       row.DwOwningPid,
		})
	}
	return eps, nil
}

func parseUDPV6Table(buf []byte) ([]UDPEndpoint, error) {
	if len(buf) < 4 {
		return nil, fmt.Errorf("buffer too small")
	}
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := int(unsafe.Sizeof(MIB_UDP6ROW_OWNER_PID{}))
	expectedMinSize := 4 + int(numEntries)*rowSize
	if len(buf) < expectedMinSize {
		return nil, fmt.Errorf("buffer size mismatch")
	}

	eps := make([]UDPEndpoint, 0, numEntries)
	for i := 0; i < int(numEntries); i++ {
		offset := 4 + i*rowSize
		row := *(*MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		localIP := make(net.IP, 16)
		copy(localIP, row.UcLocalAddr[:])
		localPort := uint16(windows.Ntohs(uint16(row.DwLocalPort)))

		eps = append(eps, UDPEndpoint{
			LocalIP:   localIP,
			LocalPort: localPort,
			PID:       row.DwOwningPid,
		})
	}
	return eps, nil
}
