package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/config"
)

// env builds getenv from a map so tests never touch the process environment
// and can run in parallel.
func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func minimalEnv() map[string]string {
	return map[string]string{
		"POSTGRES_DSN": "postgres://app:app@localhost:5432/app?sslmode=disable",
		"JWT_SECRET":   strings.Repeat("s", 32),
	}
}

func TestLoad_DefaultsWhenEnvEmpty(t *testing.T) {
	t.Parallel()

	cfg, err := config.Load(env(minimalEnv()))
	require.NoError(t, err)

	require.Equal(t, config.EnvLocal, cfg.App.Env)
	require.Equal(t, "info", cfg.App.LogLevel)
	require.False(t, cfg.App.ValidateSpec)
	require.Equal(t, "8080", cfg.HTTP.Port)
	require.Equal(t, 10*time.Second, cfg.HTTP.ReadTimeout)
	require.Equal(t, int32(10), cfg.Postgres.MaxConns)
	require.Equal(t, int32(2), cfg.Postgres.MinConns)
	require.Equal(t, "k1", cfg.Auth.JWTKeyID)
	require.Equal(t, 15*time.Minute, cfg.Auth.AccessTokenTTL)
	require.Equal(t, 24*time.Hour, cfg.Auth.EmailTokenTTL)
}

func TestLoad_EnvOverridesDefaults(t *testing.T) {
	t.Parallel()

	kv := minimalEnv()
	kv["APP_ENV"] = "production"
	kv["HTTP_PORT"] = "9090"
	kv["HTTP_READ_TIMEOUT"] = "3s"
	kv["POSTGRES_MAX_CONNS"] = "42"

	cfg, err := config.Load(env(kv))
	require.NoError(t, err)

	require.Equal(t, config.EnvProduction, cfg.App.Env)
	require.Equal(t, "9090", cfg.HTTP.Port)
	require.Equal(t, 3*time.Second, cfg.HTTP.ReadTimeout)
	require.Equal(t, int32(42), cfg.Postgres.MaxConns)
}

func TestLoad_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantMsg string
	}{
		{
			name:    "DSN is required",
			mutate:  func(kv map[string]string) { delete(kv, "POSTGRES_DSN") },
			wantMsg: "POSTGRES_DSN: required",
		},
		{
			name:    "APP_ENV not in the known list",
			mutate:  func(kv map[string]string) { kv["APP_ENV"] = "uat" },
			wantMsg: "APP_ENV",
		},
		{
			name:    "invalid duration",
			mutate:  func(kv map[string]string) { kv["HTTP_READ_TIMEOUT"] = "sebentar" },
			wantMsg: "HTTP_READ_TIMEOUT",
		},
		{
			name:    "not a number",
			mutate:  func(kv map[string]string) { kv["POSTGRES_MAX_CONNS"] = "banyak" },
			wantMsg: "POSTGRES_MAX_CONNS",
		},
		{
			// Without the range check this truncates silently and goes negative.
			name:    "out of int32 range",
			mutate:  func(kv map[string]string) { kv["POSTGRES_MAX_CONNS"] = "99999999999" },
			wantMsg: "POSTGRES_MAX_CONNS",
		},
		{
			name:    "JWT_SECRET is required",
			mutate:  func(kv map[string]string) { delete(kv, "JWT_SECRET") },
			wantMsg: "JWT_SECRET: required",
		},
		{
			name:    "JWT_SECRET too short",
			mutate:  func(kv map[string]string) { kv["JWT_SECRET"] = "short" },
			wantMsg: "JWT_SECRET: 5 characters",
		},
		{
			name:    "min exceeds max",
			mutate:  func(kv map[string]string) { kv["POSTGRES_MIN_CONNS"] = "50" },
			wantMsg: "exceeds",
		},
		{
			name: "spec validation on in production",
			mutate: func(kv map[string]string) {
				kv["APP_ENV"] = "production"
				kv["VALIDATE_SPEC"] = "true"
			},
			wantMsg: "VALIDATE_SPEC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kv := minimalEnv()
			tt.mutate(kv)

			_, err := config.Load(env(kv))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

// Every problem at once, so a broken env is fixed in one pass.
func TestLoad_ReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()

	kv := map[string]string{
		"APP_ENV":            "uat",
		"HTTP_READ_TIMEOUT":  "not-a-duration",
		"POSTGRES_MAX_CONNS": "lots",
	}

	_, err := config.Load(env(kv))
	require.Error(t, err)

	msg := err.Error()
	require.Contains(t, msg, "POSTGRES_DSN")
	require.Contains(t, msg, "JWT_SECRET")
	require.Contains(t, msg, "APP_ENV")
	require.Contains(t, msg, "HTTP_READ_TIMEOUT")
	require.Contains(t, msg, "POSTGRES_MAX_CONNS")
	require.Equal(t, 5, strings.Count(msg, "\n  - "), "should report 5 problems")
}
