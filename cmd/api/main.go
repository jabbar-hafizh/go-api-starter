// Command api is the only entrypoint for this service.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

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
	// The runtime image has no shell, so the container healthcheck runs this
	// binary against itself. Without it `docker compose up --wait` reports a
	// crash-looping container as healthy, which is worse than no check at all.
	health := flag.Bool("health", false, "probe this process and exit")
	flag.Parse()

	if *health {
		return probe()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return app.Run(ctx, os.Getenv, os.Stdout)
}

func probe() error {
	// Parsed rather than interpolated, so the only thing the environment can
	// influence is a port number on the loopback address.
	port := 8080
	if raw := os.Getenv("HTTP_PORT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 65535 {
			return fmt.Errorf("probe: HTTP_PORT %q is not a port", raw)
		}
		port = parsed
	}

	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/healthz"

	resp, err := client.Get(url) //nolint:noctx,gosec // loopback only, port validated above
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe: status %d", resp.StatusCode)
	}
	return nil
}
