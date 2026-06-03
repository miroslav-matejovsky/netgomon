package main

import (
	"fmt"
	"net/http"
)

// HTTP:
//   http://example.com
//   - stable, no TLS complexity
//   - predictable outbound TCP 80

func testHTTP() {
	url := "http://example.com"
	log("HTTP: GET " + url)

	resp, err := http.Get(url)
	if err != nil {
		log("HTTP ERROR: " + err.Error())
		return
	}
	defer resp.Body.Close()

	log(fmt.Sprintf("HTTP SUCCESS: status=%s", resp.Status))
}
