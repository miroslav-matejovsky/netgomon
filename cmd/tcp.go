package main

import (
	"net"
	"time"
)

// TCP:
//   google.com:80
//   - raw TCP connect without HTTP

func testTCP() {
	target := "google.com:80"
	log("TCP: dialing " + target)

	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log("TCP ERROR: " + err.Error())
		return
	}
	defer conn.Close()

	log("TCP SUCCESS: connected")

	// send small data
	conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
}
