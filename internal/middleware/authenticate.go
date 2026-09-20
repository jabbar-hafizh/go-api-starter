// Package middleware holds the cross-cutting HTTP layers.
package middleware

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

type ctxKey int

const userIDKey ctxKey = iota

type unauthorizedError struct{}

func (unauthorizedError) Error() string   { return "missing or invalid access token" }
func (unauthorizedError) HTTPStatus() int { return http.StatusUnauthorized }
func (unauthorizedError) Code() string    { return "ERR_UNAUTHORIZED" }

// Authenticate verifies the bearer token and puts the user id in the context.
//
// It fails closed: anything not listed in public needs a token, so a new route
// is protected the moment it exists and opening one is a deliberate edit here.
func Authenticate(v token.Verifier, public map[string]struct{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := public[cleanPath(r.URL)]; ok {
				next.ServeHTTP(w, r)
				return
			}

			raw, ok := bearerToken(r)
			if !ok {
				httperr.Response(w, r, unauthorizedError{})
				return
			}

			claims, err := v.Verify(raw)
			if err != nil {
				httperr.Response(w, r, unauthorizedError{})
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDKey, claims.UserID)))
		})
	}
}

// UserID returns the authenticated user. The second result is false on public
// routes, where no token was required.
func UserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "

	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	raw := strings.TrimSpace(header[len(prefix):])
	return raw, raw != ""
}

// cleanPath strips a trailing slash so /v1/auth/login and /v1/auth/login/ are
// not two different decisions.
func cleanPath(u *url.URL) string {
	p := u.Path
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}
