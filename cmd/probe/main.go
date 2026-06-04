package main

import (
	"fmt"
	"os"
	"time"
)

func log(msg string) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
}

func main() {
	log("Starting network test client")

	interval := 3 * time.Second
	arg := "normal"
	if len(os.Args) > 1 {
		arg = os.Args[1]
	}
	switch arg {
	case "fast":
		log("Running in FAST mode (1s interval)")
		interval = 1 * time.Second
	case "slow":
		log("Running in SLOW mode (10s interval)")
		interval = 10 * time.Second
	default:
		log("Running in NORMAL mode (3s interval)")
	}

	i := 1
	for {
		log("----- iteration " + fmt.Sprint(i) + " -----")

		testHTTP()
		testTCP()
		testFailedTCP()
		testUDP()
		i++
		log("sleeping... (next in " + interval.String() + ") use ctrl+c to stop")
		time.Sleep(interval)
	}
}
