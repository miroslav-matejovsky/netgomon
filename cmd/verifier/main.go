package main

import (
	"fmt"
	"time"
)

func log(msg string) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

func main() {
	log("Starting network verifier")
}
