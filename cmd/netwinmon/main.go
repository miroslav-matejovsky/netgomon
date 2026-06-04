package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/miroslav-matejovsky/netwinmon/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := cli.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
