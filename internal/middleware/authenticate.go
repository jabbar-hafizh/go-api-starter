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
// It fails closed: anything not listed as public needs a token, so a new route
// is protected the moment it exists and opening one is a deliberate edit at the
// call site.
//
// patterns cover routes with a path parameter, written the same way the routes
// are: "/v1/auth/{provider}/start". A {segment} matches exactly one segment, so
// this stays as narrow as an exact path rather than opening a whole subtree.
func Authenticate(v token.Verifier, public map[string]struct{}, patterns []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublic(cleanPath(r.URL), public, patterns) {
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

func isPublic(path string, public map[string]struct{}, patterns []string) bool {
	if _, ok := public[path]; ok {
		return true
	}
	for _, pattern := range patterns {
		if matchPattern(pattern, path) {
			return true
		}
	}
	return false
}

// matchPattern compares segment by segment. A {name} segment matches any single
// non-empty segment; everything else must be equal.
func matchPattern(pattern, path string) bool {
	want := strings.Split(strings.Trim(pattern, "/"), "/")
	got := strings.Split(strings.Trim(path, "/"), "/")
	if len(want) != len(got) {
		return false
	}

	for i, segment := range want {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			if got[i] == "" {
				return false
			}
			continue
		}
		if segment != got[i] {
			return false
		}
	}
	return true
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
