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
	App      App
	HTTP     HTTP
	Postgres Postgres
	Auth     Auth
}

// App holds settings not tied to a single dependency.
type App struct {
	Env      Env
	LogLevel string
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
}

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
			ValidateSpec: p.boolean(getenv, "VALIDATE_SPEC", false),
		},
		HTTP: HTTP{
			Port:            p.str(getenv, "HTTP_PORT", "8080"),
			ReadTimeout:     p.duration(getenv, "HTTP_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:    p.duration(getenv, "HTTP_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:     p.duration(getenv, "HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: p.duration(getenv, "HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
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
		},
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
