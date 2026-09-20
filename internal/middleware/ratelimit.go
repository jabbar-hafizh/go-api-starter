package middleware

import (
	"log/slog"
	"net/http"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/ratelimit"
)

type tooManyRequestsError struct{}

func (tooManyRequestsError) Error() string   { return "too many requests" }
func (tooManyRequestsError) HTTPStatus() int { return http.StatusTooManyRequests }
func (tooManyRequestsError) Code() string    { return "ERR_RATE_LIMITED" }

// RateLimit bounds requests per client address.
//
// A limiter failure lets the request through rather than blocking it: an
// outage in the limiter should not take the whole API down with it. It is
// logged, because silently unlimited is its own problem.
func RateLimit(limiter ratelimit.Limiter, proxyHops int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIP(r, proxyHops)

			allowed, err := limiter.Allow(r.Context(), "ip:"+ip)
			if err != nil {
				slog.ErrorContext(r.Context(), "rate limiter failed, allowing request",
					slog.Any("err", err))
				next.ServeHTTP(w, r)
				return
			}
			if !allowed {
				slog.WarnContext(r.Context(), "rate limited", slog.String("ip", ip))
				httperr.Response(w, r, tooManyRequestsError{})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
