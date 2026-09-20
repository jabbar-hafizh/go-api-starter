package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

var public = map[string]struct{}{"/healthz": {}, "/v1/auth/login": {}}

func TestPublicPathsSkipTheToken(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/healthz", "/v1/auth/login", "/v1/auth/login/"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			rec, reached := call(t, path, "")
			require.Equal(t, http.StatusOK, rec.Code)
			require.True(t, *reached)
		})
	}
}

// Anything not listed as public needs a token, so a newly added route is
// protected before anyone remembers to think about it.
func TestUnlistedPathsRequireAToken(t *testing.T) {
	t.Parallel()

	rec, reached := call(t, "/v1/some/brand/new/route", "")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.False(t, *reached, "the handler must not run")
}

func TestValidTokenReachesTheHandlerWithTheUserID(t *testing.T) {
	t.Parallel()

	signer := newSigner()
	userID := uuid.Must(uuid.NewV7())
	access, err := signer.Issue(userID)
	require.NoError(t, err)

	var got uuid.UUID
	handler := middleware.Authenticate(signer, public, nil)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			id, ok := middleware.UserID(r.Context())
			require.True(t, ok)
			got = id
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+access.Value)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, userID, got)
}

func TestRejectedAuthorizationHeaders(t *testing.T) {
	t.Parallel()

	signer := newSigner()
	access, err := signer.Issue(uuid.Must(uuid.NewV7()))
	require.NoError(t, err)

	tests := map[string]string{
		"missing":         "",
		"no scheme":       access.Value,
		"wrong scheme":    "Basic " + access.Value,
		"empty token":     "Bearer ",
		"garbage token":   "Bearer not-a-token",
		"just the scheme": "Bearer",
	}

	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec, reached := call(t, "/v1/me", header)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.False(t, *reached)

			var body struct {
				Code string `json:"code"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, "ERR_UNAUTHORIZED", body.Code)
		})
	}
}

// Lowercase "bearer" is valid per RFC 7235, and some HTTP clients send it.
func TestSchemeIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	signer := newSigner()
	access, err := signer.Issue(uuid.Must(uuid.NewV7()))
	require.NoError(t, err)

	rec, reached := call(t, "/v1/me", "bearer "+access.Value)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, *reached)
}

func newSigner() *token.HS256 {
	return token.NewHS256([]byte(strings.Repeat("s", 32)), "k1", 15*time.Minute)
}

func call(t *testing.T, path, authHeader string) (*httptest.ResponseRecorder, *bool) {
	t.Helper()

	reached := false
	handler := middleware.Authenticate(newSigner(), public, nil)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, &reached
}

var patterns = []string{"/v1/auth/{provider}/start", "/v1/auth/{provider}/callback"}

func TestPatternRoutesArePublic(t *testing.T) {
	t.Parallel()

	open := []string{
		"/v1/auth/google/start",
		"/v1/auth/google/callback",
		"/v1/auth/microsoft/start",
	}
	for _, path := range open {
		t.Run("open "+path, func(t *testing.T) {
			t.Parallel()

			rec, reached := callWith(t, path, "", patterns)
			require.Equal(t, http.StatusOK, rec.Code)
			require.True(t, *reached)
		})
	}

	// A {provider} matches exactly one segment, so the pattern never opens a
	// whole subtree. This is what keeps a new authenticated route under
	// /v1/auth/ protected by default.
	closed := []string{
		"/v1/auth/google",
		"/v1/auth/google/start/extra",
		"/v1/auth/google/token",
		"/v1/auth//start",
		"/v1/me",
	}
	for _, path := range closed {
		t.Run("closed "+path, func(t *testing.T) {
			t.Parallel()

			rec, reached := callWith(t, path, "", patterns)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.False(t, *reached)
		})
	}
}

func callWith(t *testing.T, path, authHeader string, patterns []string) (*httptest.ResponseRecorder, *bool) {
	t.Helper()

	reached := false
	handler := middleware.Authenticate(newSigner(), public, patterns)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, &reached
}
