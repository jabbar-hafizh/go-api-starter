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

	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
	"github.com/jabbar-hafizh/go-api-starter/internal/calculator"
	"github.com/jabbar-hafizh/go-api-starter/internal/config"
	"github.com/jabbar-hafizh/go-api-starter/internal/db"
	"github.com/jabbar-hafizh/go-api-starter/internal/health"
	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/mailer"
	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

// publicPaths need no access token. Everything else does: Authenticate fails
// closed, so adding a route here is the only way to open it.
var publicPaths = map[string]struct{}{
	"/healthz":              {},
	"/readyz":               {},
	"/v1/auth/register":     {},
	"/v1/auth/login":        {},
	"/v1/auth/verify-email": {},
}

// Each feature names its handler Handler, which is right inside that package
// but means two of them cannot be embedded side by side. Wrapping them here
// gives distinct field names without bending the feature packages out of shape.
type healthAPI struct{ *health.Handler }

type authAPI struct{ *auth.Handler }

type calculatorAPI struct{ *calculator.Handler }

// Server satisfies openapi.StrictServerInterface by embedding every feature's
// handler. Method promotion gives it all the operations without one struct
// knowing about everything.
type Server struct {
	healthAPI
	authAPI
	calculatorAPI
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

	signer := token.NewHS256([]byte(cfg.Auth.JWTSecret), cfg.Auth.JWTKeyID, cfg.Auth.AccessTokenTTL)

	authSvc := auth.NewService(
		auth.NewPostgresStore(pool),
		signer,
		mailer.NewLog(),
		cfg.Auth.EmailTokenTTL,
	)

	srv := &Server{
		healthAPI:     healthAPI{health.NewHandler(pool)},
		authAPI:       authAPI{auth.NewHandler(authSvc)},
		calculatorAPI: calculatorAPI{calculator.NewHandler()},
	}
	httpSrv := newHTTPServer(cfg.HTTP, srv, signer)

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

func newHTTPServer(cfg config.HTTP, srv openapi.StrictServerInterface, verifier token.Verifier) *http.Server {
	handler := openapi.NewStrictHandlerWithOptions(srv, nil, openapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  httperr.Request,
		ResponseErrorHandlerFunc: httperr.Response,
	})

	mux := http.NewServeMux()
	openapi.HandlerFromMux(handler, mux)

	return &http.Server{
		Addr:              net.JoinHostPort("", cfg.Port),
		Handler:           middleware.Authenticate(verifier, publicPaths)(mux),
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
