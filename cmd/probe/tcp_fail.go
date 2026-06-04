package main

import (
	"net"
	"time"
)

// TCP Fail:
//   192.0.2.1:12345 (TEST-NET-1, RFC 5737)
//   - guaranteed unreachable, reserved for documentation
//   - will generate CONNECT_FAIL ETW event

func testFailedTCP() {
	target := "192.0.2.1:12345"
	log("TCP-FAIL: dialing " + target + " (expected to fail)")

	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		log("TCP-FAIL EXPECTED: " + err.Error())
		return
	}
	defer func() { _ = conn.Close() }()
	log("TCP-FAIL UNEXPECTED: connection succeeded")
}
