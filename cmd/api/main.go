// Command api is the only entrypoint for this service.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jabbar-hafizh/go-api-starter/internal/app"
)

func main() {
	// os.Exit skips defers, so anything with a defer lives in run().
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return app.Run(ctx, os.Getenv, os.Stdout)
}
