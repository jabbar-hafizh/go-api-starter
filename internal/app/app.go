// Package app wires every dependency together and runs the server.
//
// All wiring happens in one function here. No DI container, no reflection:
// the whole dependency graph reads top to bottom and breaks at compile time.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/jabbar-hafizh/go-api-starter/internal/config"
	"github.com/jabbar-hafizh/go-api-starter/internal/db"
	"github.com/jabbar-hafizh/go-api-starter/internal/health"
	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

// Server satisfies openapi.StrictServerInterface by embedding each feature's
// handler. Method promotion gives it every operation without one struct
// knowing about everything.
type Server struct {
	*health.Handler
}

var _ openapi.StrictServerInterface = (*Server)(nil)

// Run starts the service and returns once ctx is cancelled and the server has
// shut down.
func Run(ctx context.Context, getenv func(string) string, stdout io.Writer) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}

	logger := newLogger(stdout, cfg.App)
	slog.SetDefault(logger)
	logger.Info("starting service",
		slog.String("env", string(cfg.App.Env)),
		slog.String("port", cfg.HTTP.Port),
	)

	pool, err := db.Connect(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()
	logger.Info("postgres connected")

	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	logger.Info("migrations applied")

	srv := &Server{
		Handler: health.NewHandler(pool),
	}
	httpSrv := newHTTPServer(cfg.HTTP, srv)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", slog.String("addr", httpSrv.Addr))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	// Detached from ctx on purpose: ctx is already cancelled, so deriving from
	// it would make Shutdown give up immediately and cut off live requests.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil { //nolint:contextcheck // see above
		return fmt.Errorf("shutdown http server: %w", err)
	}
	logger.Info("stopped cleanly")
	return nil
}

func newHTTPServer(cfg config.HTTP, srv openapi.StrictServerInterface) *http.Server {
	handler := openapi.NewStrictHandlerWithOptions(srv, nil, openapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  httperr.Request,
		ResponseErrorHandlerFunc: httperr.Response,
	})

	mux := http.NewServeMux()
	openapi.HandlerFromMux(handler, mux)

	return &http.Server{
		Addr:              net.JoinHostPort("", cfg.Port),
		Handler:           mux,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
}

func newLogger(w io.Writer, cfg config.App) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.Env == config.EnvLocal {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
