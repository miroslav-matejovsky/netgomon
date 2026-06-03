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

	interval := 10 * time.Second
	if len(os.Args) > 1 && os.Args[1] == "fast" {
		interval = 3 * time.Second
	}

	i := 1
	for {
		log("----- iteration " + fmt.Sprint(i) + " -----")

		testHTTP()
		testTCP()
		testUDP()
		i++
		log("sleeping... (next in " + interval.String() + ") use ctrl+c to stop")
		time.Sleep(interval)
	}
}
