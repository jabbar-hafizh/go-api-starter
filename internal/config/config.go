// Package config reads configuration from the environment once at boot,
// validates it, and fails fast.
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Env is the environment the process runs in.
type Env string

// Known environments. Anything else is rejected at boot.
const (
	EnvLocal      Env = "local"
	EnvStaging    Env = "staging"
	EnvProduction Env = "production"
)

// Config is the whole service configuration.
type Config struct {
	App       App
	HTTP      HTTP
	Postgres  Postgres
	Auth      Auth
	Google    Google
	RateLimit RateLimit
	Client    Client
	SMTP      SMTP
}

// SMTP sends the transactional email. Leaving Host empty is allowed: the
// mailer then writes to the log instead, which is what local development uses
// when nobody wants to wire up a provider.
type SMTP struct {
	Host     string
	Port     int32
	Username string
	Password string
	// From is what recipients see. Providers reject a From they have not
	// verified, and Gmail rewrites it to the authenticated account anyway.
	From     string
	FromName string
}

// Configured reports whether real email can be sent.
func (s SMTP) Configured() bool { return s.Host != "" }

// RateLimit bounds how often a caller may act. In-process today, so limits are
// per replica: two replicas means twice the real ceiling.
type RateLimit struct {
	Enabled     bool
	IPPerSecond float64
	IPBurst     int
	// Login limits are per email address rather than per address, so rotating
	// IPs does not buy an attacker more guesses at one account.
	LoginPerMinute float64
	LoginBurst     int
	// Resend sends mail to an address the caller names, so it is tighter.
	ResendPerHour float64
	ResendBurst   int
}

// Client is what the app is told about itself.
type Client struct {
	MinVersionIOS     string
	MinVersionAndroid string
	UpgradeMessage    string
}

// App holds settings not tied to a single dependency.
type App struct {
	Env      Env
	LogLevel string
	// BaseURL is where the browser is sent after a provider sign-in. Only a
	// path is ever appended to it, never a caller-supplied URL.
	BaseURL string
	// ValidateSpec checks every request and response against the OpenAPI
	// spec. Expensive, so dev and test only.
	ValidateSpec bool
}

// HTTP holds the HTTP server settings.
type HTTP struct {
	Port string
	// Go ships no default timeouts, so one slow client can hold a connection
	// forever. All three are required.
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	// MaxBodyBytes caps a single request, so one caller cannot make the
	// server read an unbounded amount into memory.
	MaxBodyBytes int64
	// AllowedOrigins is an exact allowlist. Reflecting whatever Origin arrives
	// would let any site make authenticated calls for a signed-in user.
	AllowedOrigins []string
	// TrustedProxyHops is how many proxies sit in front. Zero means
	// X-Forwarded-For is ignored, because trusting it unguarded lets anyone
	// rotate their apparent address past the rate limits.
	TrustedProxyHops int
}

// Postgres holds the database connection settings.
type Postgres struct {
	DSN      string
	MaxConns int32
	MinConns int32
}

// Auth holds token signing and lifetime settings.
type Auth struct {
	JWTSecret string
	// JWTKeyID goes in the token header from the very first token. It costs
	// nothing now and is what makes moving to RS256 later a 15 minute
	// dual-verification window instead of a forced logout.
	JWTKeyID       string
	AccessTokenTTL time.Duration
	// EmailTokenTTL covers verification and password reset links.
	EmailTokenTTL time.Duration
	// Refresh lifetimes differ by client: a phone user will not accept signing
	// in again every week, a browser session should not last a month.
	RefreshTokenTTLWeb    time.Duration
	RefreshTokenTTLMobile time.Duration
}

// Google holds the OAuth client for Google SSO. Leaving it empty is allowed:
// the Google endpoints then answer 501 and everything else still works, so a
// new contributor can run the project without setting up a Google project.
type Google struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// AllowedAudiences is the set of aud values accepted in an ID token.
	// Defaults to ClientID, which is what Google puts there on every platform
	// when a native app passes the web client id as its server client id.
	AllowedAudiences []string
}

// Configured reports whether Google SSO can be served.
func (g Google) Configured() bool { return g.ClientID != "" }

// minJWTSecretLen matches the HMAC-SHA256 block size. A shorter secret is
// padded internally, so it buys less entropy than its length suggests.
const minJWTSecretLen = 32

// Load takes getenv as an argument so tests never touch the process environment.
func Load(getenv func(string) string) (Config, error) {
	var p parser

	cfg := Config{
		App: App{
			Env:          Env(p.str(getenv, "APP_ENV", "local")),
			LogLevel:     p.str(getenv, "APP_LOG_LEVEL", "info"),
			BaseURL:      p.str(getenv, "APP_BASE_URL", "http://localhost:3000"),
			ValidateSpec: p.boolean(getenv, "VALIDATE_SPEC", false),
		},
		HTTP: HTTP{
			Port:             p.str(getenv, "HTTP_PORT", "8080"),
			ReadTimeout:      p.duration(getenv, "HTTP_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:     p.duration(getenv, "HTTP_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:      p.duration(getenv, "HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout:  p.duration(getenv, "HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
			MaxBodyBytes:     int64(p.int32(getenv, "HTTP_MAX_BODY_BYTES", 1<<20)),
			AllowedOrigins:   p.list(getenv, "HTTP_ALLOWED_ORIGINS"),
			TrustedProxyHops: int(p.int32NonNegative(getenv, "HTTP_TRUSTED_PROXY_HOPS", 0)),
		},
		Postgres: Postgres{
			DSN:      p.required(getenv, "POSTGRES_DSN"),
			MaxConns: p.int32(getenv, "POSTGRES_MAX_CONNS", 10),
			MinConns: p.int32(getenv, "POSTGRES_MIN_CONNS", 2),
		},
		Auth: Auth{
			JWTSecret:      p.required(getenv, "JWT_SECRET"),
			JWTKeyID:       p.str(getenv, "JWT_KEY_ID", "k1"),
			AccessTokenTTL: p.duration(getenv, "ACCESS_TOKEN_TTL", 15*time.Minute),
			EmailTokenTTL:  p.duration(getenv, "EMAIL_TOKEN_TTL", 24*time.Hour),

			RefreshTokenTTLWeb:    p.duration(getenv, "REFRESH_TOKEN_TTL_WEB", 7*24*time.Hour),
			RefreshTokenTTLMobile: p.duration(getenv, "REFRESH_TOKEN_TTL_MOBILE", 30*24*time.Hour),
		},
		RateLimit: RateLimit{
			Enabled:        p.boolean(getenv, "RATE_LIMIT_ENABLED", true),
			IPPerSecond:    p.float(getenv, "RATE_LIMIT_IP_PER_SECOND", 20),
			IPBurst:        int(p.int32(getenv, "RATE_LIMIT_IP_BURST", 40)),
			LoginPerMinute: p.float(getenv, "RATE_LIMIT_LOGIN_PER_MINUTE", 5),
			LoginBurst:     int(p.int32(getenv, "RATE_LIMIT_LOGIN_BURST", 5)),
			ResendPerHour:  p.float(getenv, "RATE_LIMIT_RESEND_PER_HOUR", 3),
			ResendBurst:    int(p.int32(getenv, "RATE_LIMIT_RESEND_BURST", 3)),
		},
		Client: Client{
			MinVersionIOS:     p.str(getenv, "MIN_CLIENT_VERSION_IOS", ""),
			MinVersionAndroid: p.str(getenv, "MIN_CLIENT_VERSION_ANDROID", ""),
			UpgradeMessage:    p.str(getenv, "CLIENT_UPGRADE_MESSAGE", "Please update the app to continue."),
		},
		SMTP: SMTP{
			Host:     p.str(getenv, "SMTP_HOST", ""),
			Port:     p.int32(getenv, "SMTP_PORT", 587),
			Username: p.str(getenv, "SMTP_USERNAME", ""),
			Password: p.str(getenv, "SMTP_PASSWORD", ""),
			From:     p.str(getenv, "SMTP_FROM", ""),
			FromName: p.str(getenv, "SMTP_FROM_NAME", "go-api-starter"),
		},
		Google: Google{
			ClientID:         p.str(getenv, "GOOGLE_CLIENT_ID", ""),
			ClientSecret:     p.str(getenv, "GOOGLE_CLIENT_SECRET", ""),
			RedirectURL:      p.str(getenv, "GOOGLE_REDIRECT_URL", ""),
			AllowedAudiences: p.list(getenv, "GOOGLE_ALLOWED_AUDIENCES"),
		},
	}

	if cfg.Google.Configured() && len(cfg.Google.AllowedAudiences) == 0 {
		cfg.Google.AllowedAudiences = []string{cfg.Google.ClientID}
	}

	cfg.validate(&p)

	if err := p.err(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate(p *parser) {
	switch c.App.Env {
	case EnvLocal, EnvStaging, EnvProduction:
	default:
		p.add(fmt.Errorf("APP_ENV: %q is not local, staging or production", c.App.Env))
	}

	if c.App.ValidateSpec && c.App.Env == EnvProduction {
		p.add(errors.New("VALIDATE_SPEC must be off in production"))
	}

	if c.Auth.JWTSecret != "" && len(c.Auth.JWTSecret) < minJWTSecretLen {
		p.add(fmt.Errorf("JWT_SECRET: %d characters, need at least %d",
			len(c.Auth.JWTSecret), minJWTSecretLen))
	}

	// Half-configured is worse than not configured: it looks like mail works
	// until the first person registers and never receives anything.
	if c.SMTP.Host != "" {
		if c.SMTP.Username == "" {
			p.add(errors.New("SMTP_USERNAME: required when SMTP_HOST is set"))
		}
		if c.SMTP.Password == "" {
			p.add(errors.New("SMTP_PASSWORD: required when SMTP_HOST is set"))
		}
		if c.SMTP.From == "" {
			p.add(errors.New("SMTP_FROM: required when SMTP_HOST is set"))
		}
	}

	// Half-configured is worse than not configured: it looks like SSO works
	// until the first person tries it.
	if c.Google.ClientID != "" {
		if c.Google.ClientSecret == "" {
			p.add(errors.New("GOOGLE_CLIENT_SECRET: required when GOOGLE_CLIENT_ID is set"))
		}
		if c.Google.RedirectURL == "" {
			p.add(errors.New("GOOGLE_REDIRECT_URL: required when GOOGLE_CLIENT_ID is set"))
		}
	}

	if c.Postgres.MinConns > c.Postgres.MaxConns {
		p.add(fmt.Errorf("POSTGRES_MIN_CONNS (%d) exceeds POSTGRES_MAX_CONNS (%d)",
			c.Postgres.MinConns, c.Postgres.MaxConns))
	}
}

// parser collects every problem instead of stopping at the first, so a broken
// env is fixed in one pass rather than one deploy per mistake.
type parser struct{ errs []error }

func (p *parser) add(err error) { p.errs = append(p.errs, err) }

func (p *parser) err() error {
	if len(p.errs) == 0 {
		return nil
	}
	msgs := make([]string, len(p.errs))
	for i, e := range p.errs {
		msgs[i] = "  - " + e.Error()
	}
	return fmt.Errorf("invalid config (%d problems):\n%s", len(p.errs), strings.Join(msgs, "\n"))
}

func (p *parser) str(getenv func(string) string, key, def string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return def
}

func (p *parser) required(getenv func(string) string, key string) string {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		p.add(fmt.Errorf("%s: required", key))
	}
	return v
}

// int32 parses and range-checks. An unchecked int -> int32 conversion truncates
// silently, so a fat-fingered value can turn negative.
func (p *parser) int32(getenv func(string) string, key string, def int32) int32 {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		p.add(fmt.Errorf("%s: %q is not a valid 32-bit integer", key, raw))
		return def
	}
	if v <= 0 {
		p.add(fmt.Errorf("%s: %d must be greater than zero", key, v))
		return def
	}
	return int32(v)
}

// list reads a comma separated value, dropping blanks.
func (p *parser) list(getenv func(string) string, key string) []string {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return nil
	}

	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// int32NonNegative allows zero, which int32 rejects.
func (p *parser) int32NonNegative(getenv func(string) string, key string, def int32) int32 {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || v < 0 {
		p.add(fmt.Errorf("%s: %q must be a non-negative 32-bit integer", key, raw))
		return def
	}
	return int32(v)
}

func (p *parser) float(getenv func(string) string, key string, def float64) float64 {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v <= 0 {
		p.add(fmt.Errorf("%s: %q must be a number greater than zero", key, raw))
		return def
	}
	return v
}

func (p *parser) boolean(getenv func(string) string, key string, def bool) bool {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		p.add(fmt.Errorf("%s: %q is not a boolean", key, raw))
		return def
	}
	return v
}

func (p *parser) duration(getenv func(string) string, key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return def
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		p.add(fmt.Errorf("%s: %q is not a valid duration (e.g. 10s, 1m)", key, raw))
		return def
	}
	return v
}
