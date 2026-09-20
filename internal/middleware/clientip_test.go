package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
	"github.com/jabbar-hafizh/go-api-starter/internal/ratelimit"
)

func TestClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		hops       int
		want       string
	}{
		{
			// With no proxy in front, the header is ignored entirely.
			// Trusting it here would let anyone rotate their apparent address
			// and walk straight through the rate limits.
			name: "header ignored without a proxy", remoteAddr: "192.0.2.1:54321",
			forwarded: "1.2.3.4", hops: 0, want: "192.0.2.1",
		},
		{
			name: "one proxy takes the last entry", remoteAddr: "10.0.0.1:443",
			forwarded: "1.2.3.4, 203.0.113.9", hops: 1, want: "203.0.113.9",
		},
		{
			name: "two proxies step one further left", remoteAddr: "10.0.0.1:443",
			forwarded: "1.2.3.4, 203.0.113.9, 10.0.0.2", hops: 2, want: "203.0.113.9",
		},
		{
			// Caller-supplied entries sit to the left of what the proxy wrote,
			// so spoofing more entries does not move the answer.
			name: "spoofed entries do not shift the result", remoteAddr: "10.0.0.1:443",
			forwarded: "9.9.9.9, 8.8.8.8, 203.0.113.9", hops: 1, want: "203.0.113.9",
		},
		{
			name: "falls back when the header is missing", remoteAddr: "192.0.2.7:1234",
			forwarded: "", hops: 1, want: "192.0.2.7",
		},
		{
			name: "falls back when hops exceed the header", remoteAddr: "192.0.2.7:1234",
			forwarded: "203.0.113.9", hops: 5, want: "192.0.2.7",
		},
		{
			name: "remote address without a port", remoteAddr: "192.0.2.7",
			forwarded: "", hops: 0, want: "192.0.2.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.forwarded != "" {
				req.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			require.Equal(t, tt.want, middleware.ClientIP(req, tt.hops))
		})
	}
}

func TestRateLimitReturns429(t *testing.T) {
	t.Parallel()

	handler := middleware.RateLimit(ratelimit.NewMemory(1, 1, time.Hour), 0)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.RemoteAddr = "192.0.2.1:1111"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_RATE_LIMITED")
}

// One address being limited must not affect another.
func TestRateLimitIsPerAddress(t *testing.T) {
	t.Parallel()

	handler := middleware.RateLimit(ratelimit.NewMemory(1, 1, time.Hour), 0)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, addr := range []string{"192.0.2.1:1", "192.0.2.1:2", "198.51.100.5:1"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
		req.RemoteAddr = addr

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// The first two share an address, so the second is limited.
		if addr == "192.0.2.1:2" {
			require.Equal(t, http.StatusTooManyRequests, rec.Code)
			continue
		}
		require.Equal(t, http.StatusOK, rec.Code)
	}
}

// A limiter outage must not take the API down with it.
func TestRateLimitAllowsWhenTheLimiterFails(t *testing.T) {
	t.Parallel()

	handler := middleware.RateLimit(brokenLimiter{}, 0)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}

type brokenLimiter struct{}

func (brokenLimiter) Allow(context.Context, string) (bool, error) {
	return false, errors.New("limiter is down")
}
