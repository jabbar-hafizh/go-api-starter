package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
)

func TestChainAppliesFirstListedOutermost(t *testing.T) {
	t.Parallel()

	var order []string
	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	handler := middleware.Chain(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { order = append(order, "handler") }),
		mark("first"), mark("second"), mark("third"),
	)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, []string{"first", "second", "third", "handler"}, order)
}

// A panic must become a logged 500, not a dropped connection with no status
// and no body, which is the hardest failure to diagnose from outside.
func TestRecoverTurnsPanicIntoAnError(t *testing.T) {
	t.Parallel()

	handler := middleware.Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("something went very wrong with secret-value-in-the-panic")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Contains(t, rec.Body.String(), "ERR_INTERNAL")
	require.NotContains(t, rec.Body.String(), "secret-value-in-the-panic")
}

// http.ErrAbortHandler is how net/http signals a deliberate abort, not a bug.
func TestRecoverPassesOnAbortHandler(t *testing.T) {
	t.Parallel()

	handler := middleware.Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	require.Panics(t, func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	})
}

func TestBodyLimit(t *testing.T) {
	t.Parallel()

	handler := middleware.BodyLimit(16)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	small := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("tiny"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, small)
	require.Equal(t, http.StatusOK, rec.Code)

	big := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 64)))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, big)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	handler := middleware.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	require.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
}

func TestRequestIDIsGeneratedAndEchoed(t *testing.T) {
	t.Parallel()

	var seen string
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = middleware.RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// An incoming id is ignored: a caller could otherwise collide with or
	// poison somebody else's trace.
	req.Header.Set(middleware.RequestIDHeader, "attacker-supplied")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.NotEmpty(t, seen)
	require.NotEqual(t, "attacker-supplied", seen)
	require.Equal(t, seen, rec.Header().Get(middleware.RequestIDHeader))
}
