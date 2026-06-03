package main

import (
	"net"
	"time"
)

// UDP:
//   8.8.8.8:53
//   - simple DNS query (widely reachable)

func testUDP() {
	target := "8.8.8.8:53"
	log("UDP: sending to " + target)

	conn, err := net.Dial("udp", target)
	if err != nil {
		log("UDP ERROR: " + err.Error())
		return
	}
	defer func() { _ = conn.Close() }()

	// minimal DNS query (not complete protocol, but enough to generate traffic)
	payload := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags
		0x00, 0x01, // questions
		0x00, 0x00, // answers
		0x00, 0x00, // authority
		0x00, 0x00, // additional
		// query: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // type A
		0x00, 0x01, // class IN
	}

	_, err = conn.Write(payload)
	if err != nil {
		log("UDP SEND ERROR: " + err.Error())
		return
	}

	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	if err != nil {
		log("UDP RECV (expected timeout or partial): " + err.Error())
	} else {
		log("UDP SUCCESS: received response")
	}
}
