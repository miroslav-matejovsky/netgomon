//go:build windows

package custom

import (
	"encoding/binary"
	"net"
	"unsafe"
)

// networkEventData holds parsed fields from raw EVENT_RECORD.UserData.
type networkEventData struct {
	PID     uint32
	Size    uint32
	SrcAddr net.IP
	DstAddr net.IP
	SrcPort uint16
	DstPort uint16
}

// isIPv6Event returns true if the event ID corresponds to an IPv6 event.
func isIPv6Event(eventID uint16) bool {
	switch eventID {
	case 20, 21, 22, 23, 24, 25, 28, 29, 42, 43:
		return true
	}
	return false
}

// minIPv4DataLen is the minimum UserData length for IPv4 Kernel-Network events.
// Layout: PID(4) + size(4) + daddr(4) + saddr(4) + dport(2) + sport(2) = 20 bytes
const minIPv4DataLen = 20

// minIPv6DataLen is the minimum UserData length for IPv6 Kernel-Network events.
// Layout: PID(4) + size(4) + daddr(16) + saddr(16) + dport(2) + sport(2) = 44 bytes
const minIPv6DataLen = 44

// parseEventData extracts network tuple from raw EVENT_RECORD UserData.
// Returns nil if data is too short or event ID is not recognized.
func parseEventData(eventID uint16, userData unsafe.Pointer, userDataLen uint16) *networkEventData {
	if userData == nil || userDataLen == 0 {
		return nil
	}

	ipv6 := isIPv6Event(eventID)

	if ipv6 {
		return parseIPv6Data(userData, userDataLen)
	}
	return parseIPv4Data(userData, userDataLen)
}

// parseIPv4Data parses IPv4 Kernel-Network event UserData.
func parseIPv4Data(userData unsafe.Pointer, length uint16) *networkEventData {
	if length < minIPv4DataLen {
		return nil
	}

	data := unsafe.Slice((*byte)(userData), length)

	result := &networkEventData{
		PID:  binary.LittleEndian.Uint32(data[0:4]),
		Size: binary.LittleEndian.Uint32(data[4:8]),
	}

	// daddr at offset 8, 4 bytes (network byte order for IP)
	result.DstAddr = net.IPv4(data[8], data[9], data[10], data[11])

	// saddr at offset 12, 4 bytes
	result.SrcAddr = net.IPv4(data[12], data[13], data[14], data[15])

	// dport at offset 16, 2 bytes (network byte order)
	result.DstPort = binary.BigEndian.Uint16(data[16:18])

	// sport at offset 18, 2 bytes (network byte order)
	result.SrcPort = binary.BigEndian.Uint16(data[18:20])

	return result
}

// parseIPv6Data parses IPv6 Kernel-Network event UserData.
func parseIPv6Data(userData unsafe.Pointer, length uint16) *networkEventData {
	if length < minIPv6DataLen {
		return nil
	}

	data := unsafe.Slice((*byte)(userData), length)

	result := &networkEventData{
		PID:  binary.LittleEndian.Uint32(data[0:4]),
		Size: binary.LittleEndian.Uint32(data[4:8]),
	}

	// daddr at offset 8, 16 bytes
	dstIP := make(net.IP, 16)
	copy(dstIP, data[8:24])
	result.DstAddr = dstIP

	// saddr at offset 24, 16 bytes
	srcIP := make(net.IP, 16)
	copy(srcIP, data[24:40])
	result.SrcAddr = srcIP

	// dport at offset 40, 2 bytes (network byte order)
	result.DstPort = binary.BigEndian.Uint16(data[40:42])

	// sport at offset 42, 2 bytes (network byte order)
	result.SrcPort = binary.BigEndian.Uint16(data[42:44])

	return result
}
