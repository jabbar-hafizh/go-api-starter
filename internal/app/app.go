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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jabbar-hafizh/go-api-starter/internal/apidocs"
	"github.com/jabbar-hafizh/go-api-starter/internal/appversion"
	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
	"github.com/jabbar-hafizh/go-api-starter/internal/calculator"
	"github.com/jabbar-hafizh/go-api-starter/internal/config"
	"github.com/jabbar-hafizh/go-api-starter/internal/db"
	"github.com/jabbar-hafizh/go-api-starter/internal/health"
	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/mailer"
	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
	"github.com/jabbar-hafizh/go-api-starter/internal/ratelimit"
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
	// These two authenticate with the refresh token, not the access token, so
	// they must not require a bearer: the whole point is that the access token
	// has already expired.
	"/v1/auth/refresh":   {},
	"/v1/auth/logout":    {},
	"/v1/auth/providers": {},
	"/v1/app/config":     {},
	// Served on purpose outside the contract: a document cannot describe
	// how it is itself served.
	apidocs.SpecPath: {},
	apidocs.UIPath:   {},
}

// publicPatterns covers the routes that carry a path parameter. Written as the
// routes are, so a {provider} matches one segment and nothing else: adding an
// authenticated route under /v1/auth/ stays protected.
var publicPatterns = []string{
	"/v1/auth/{provider}/start",
	"/v1/auth/{provider}/callback",
	"/v1/auth/{provider}/token",
}

// Each feature names its handler Handler, which is right inside that package
// but means two of them cannot be embedded side by side. Wrapping them here
// gives distinct field names without bending the feature packages out of shape.
type healthAPI struct{ *health.Handler }

type authAPI struct{ *auth.Handler }

type calculatorAPI struct{ *calculator.Handler }

type appVersionAPI struct{ *appversion.Handler }

// Server satisfies openapi.StrictServerInterface by embedding every feature's
// handler. Method promotion gives it all the operations without one struct
// knowing about everything.
type Server struct {
	healthAPI
	authAPI
	calculatorAPI
	appVersionAPI
}

var _ openapi.StrictServerInterface = (*Server)(nil)

// sweepInterval is how often aged-out records are deleted. Nothing depends on
// it being prompt; it only has to run often enough that the tables do not grow
// without bound.
const sweepInterval = 15 * time.Minute

// components is what buildServer assembles. A struct rather than a growing
// list of return values.
type components struct {
	server *Server
	signer *token.HS256
	auth   *auth.Service
}

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

	c, err := buildServer(ctx, cfg, pool, logger)
	if err != nil {
		return err
	}
	startSweeper(ctx, c.auth, logger)

	httpSrv := newHTTPServer(cfg, c.server, c.signer)

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

// buildServer assembles every feature. Kept apart from Run so that one reads
// as the service lifecycle and this one reads as the dependency graph.
func buildServer(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (components, error) {
	signer := token.NewHS256([]byte(cfg.Auth.JWTSecret), cfg.Auth.JWTKeyID, cfg.Auth.AccessTokenTTL)

	sender, err := newMailer(cfg, logger)
	if err != nil {
		return components{}, err
	}

	authSvc := auth.NewService(
		auth.NewPostgresStore(pool),
		signer,
		sender,
		auth.Config{
			EmailTokenTTL:    cfg.Auth.EmailTokenTTL,
			RefreshTTLWeb:    cfg.Auth.RefreshTokenTTLWeb,
			RefreshTTLMobile: cfg.Auth.RefreshTokenTTLMobile,
		},
		auth.WithLoginLimiter(loginLimiter(cfg.RateLimit)),
	)

	if cfg.Google.Configured() {
		// Discovery talks to the network, which is why it happens at startup
		// rather than inside a request.
		google, err := auth.NewGoogle(ctx,
			cfg.Google.ClientID, cfg.Google.ClientSecret,
			cfg.Google.RedirectURL, cfg.Google.AllowedAudiences)
		if err != nil {
			return components{}, err
		}
		authSvc.RegisterProvider(google)
		logger.Info("google sso enabled")
	} else {
		logger.Warn("google sso not configured, its endpoints will answer 501")
	}

	// Browsers drop Secure cookies over plain HTTP, so local development would
	// silently never receive one.
	secureCookies := cfg.App.Env != config.EnvLocal

	gate := appversion.NewGate(
		cfg.Client.MinVersionIOS, cfg.Client.MinVersionAndroid, cfg.Client.UpgradeMessage)

	return components{
		server: &Server{
			healthAPI:     healthAPI{health.NewHandler(pool)},
			authAPI:       authAPI{auth.NewHandler(authSvc, cfg.App.BaseURL, secureCookies)},
			calculatorAPI: calculatorAPI{calculator.NewHandler()},
			appVersionAPI: appVersionAPI{appversion.NewHandler(gate)},
		},
		signer: signer,
		auth:   authSvc,
	}, nil
}

// startSweeper deletes aged-out records until ctx is cancelled.
//
// A failed sweep is logged and the loop continues: the tables growing for one
// interval is not worth taking anything down over.
func startSweeper(ctx context.Context, svc *auth.Service, logger *slog.Logger) {
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()

		for {
			// Run first, then wait, so a restart clears whatever accumulated
			// while the process was down.
			if err := svc.SweepExpired(ctx); err != nil && ctx.Err() == nil {
				logger.Error("sweep failed", slog.Any("err", err))
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// newMailer returns a real sender when SMTP is configured and a logging one
// otherwise, so the project still runs for someone who has not set up mail.
func newMailer(cfg config.Config, logger *slog.Logger) (auth.Mailer, error) {
	if !cfg.SMTP.Configured() {
		logger.Warn("smtp not configured, verification tokens go to the log instead")
		return mailer.NewLog(), nil
	}

	sender, err := mailer.NewSMTP(mailer.SMTPConfig{
		Host:     cfg.SMTP.Host,
		Port:     int(cfg.SMTP.Port),
		Username: cfg.SMTP.Username,
		Password: cfg.SMTP.Password,
		From:     cfg.SMTP.From,
		FromName: cfg.SMTP.FromName,
		BaseURL:  cfg.App.BaseURL,
		LinkTTL:  cfg.Auth.EmailTokenTTL,
	})
	if err != nil {
		return nil, err
	}

	logger.Info("smtp configured",
		slog.String("host", cfg.SMTP.Host),
		slog.String("from", cfg.SMTP.From),
	)
	return sender, nil
}

// loginLimiter bounds sign-in attempts per email. Disabled means no ceiling at
// all, which is only ever right for tests and local work.
func loginLimiter(cfg config.RateLimit) ratelimit.Limiter {
	if !cfg.Enabled {
		return ratelimit.Allowed{}
	}
	return ratelimit.NewMemory(cfg.LoginPerMinute/60, cfg.LoginBurst, time.Hour)
}

func newHTTPServer(cfg config.Config, srv openapi.StrictServerInterface, verifier token.Verifier) *http.Server {
	handler := openapi.NewStrictHandlerWithOptions(srv, nil, openapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  httperr.Request,
		ResponseErrorHandlerFunc: httperr.Response,
	})

	mux := http.NewServeMux()
	openapi.HandlerFromMux(handler, mux)

	spec, err := openapi.GetSpec()
	if err != nil {
		// The document is embedded at build time, so failing to parse it means
		// the binary itself is broken.
		panic(err)
	}
	apidocs.Register(mux, spec)

	// Order matters and reads outermost first: an id exists before anything is
	// logged, a panic anywhere inside is caught, the body is capped before it
	// is read, and authentication runs last so rate limiting protects it too.
	middlewares := []func(http.Handler) http.Handler{
		middleware.RequestID,
		// Probes are called every few seconds forever; logging them buries
		// everything else.
		middleware.RequestLog("/healthz", "/readyz"),
		middleware.Recover,
		middleware.SecurityHeaders,
		middleware.CORS(cfg.HTTP.AllowedOrigins),
		middleware.BodyLimit(cfg.HTTP.MaxBodyBytes),
	}
	if cfg.App.ValidateSpec {
		// Placed after the body limit and before authentication, so it sees the
		// request as the handler will.
		middlewares = append(middlewares,
			middleware.ValidateSpec(spec, apidocs.SpecPath, apidocs.UIPath))
	}
	if cfg.RateLimit.Enabled {
		middlewares = append(middlewares,
			middleware.RateLimit(
				ratelimit.NewMemory(cfg.RateLimit.IPPerSecond, cfg.RateLimit.IPBurst, time.Hour),
				cfg.HTTP.TrustedProxyHops))
	}
	middlewares = append(middlewares, middleware.Authenticate(verifier, publicPaths, publicPatterns))

	return &http.Server{
		Addr:              net.JoinHostPort("", cfg.HTTP.Port),
		Handler:           middleware.Chain(mux, middlewares...),
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
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
