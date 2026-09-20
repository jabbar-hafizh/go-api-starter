package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
)

var allowedOrigins = []string{"https://app.example.com", "http://localhost:3000"}

func TestCORSAllowsListedOrigin(t *testing.T) {
	t.Parallel()

	rec := cors(t, http.MethodGet, "https://app.example.com")

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))
	// Caches must not hand one origin's response to another.
	require.Contains(t, rec.Header().Values("Vary"), "Origin")
}

// Reflecting whatever Origin arrives is the usual shortcut, and combined with
// credentials it lets any site on the internet make authenticated calls for a
// signed-in user.
func TestCORSRefusesUnlistedOrigins(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{
		"https://evil.com",
		"https://app.example.com.evil.com",
		"https://app.example.com:8443",
		"http://app.example.com",
		"null",
	} {
		t.Run(origin, func(t *testing.T) {
			t.Parallel()

			rec := cors(t, http.MethodGet, origin)
			require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
			require.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
			// Still served: CORS is a browser rule, not authorisation.
			require.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestCORSPreflight(t *testing.T) {
	t.Parallel()

	rec := cors(t, http.MethodOptions, "https://app.example.com")

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodPost)
	require.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	require.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), middleware.ClientVersionHeader)
	require.NotEmpty(t, rec.Header().Get("Access-Control-Max-Age"))
}

// A preflight from an origin that is not allowed must reach the handler
// unmarked rather than be answered as if it were allowed.
func TestCORSPreflightFromUnlistedOrigin(t *testing.T) {
	t.Parallel()

	rec := cors(t, http.MethodOptions, "https://evil.com")
	require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestCORSWithNoOriginHeader(t *testing.T) {
	t.Parallel()

	rec := cors(t, http.MethodGet, "")
	require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, http.StatusOK, rec.Code)
}

func cors(t *testing.T, method, origin string) *httptest.ResponseRecorder {
	t.Helper()

	handler := middleware.CORS(allowedOrigins)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(method, "/v1/me", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
