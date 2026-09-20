package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// Client headers that say who is calling. Recorded on every request, because
// without them there is no way to know when an old mobile build has finally
// stopped calling an endpoint you want to remove.
const (
	ClientPlatformHeader = "X-Client-Platform"
	ClientVersionHeader  = "X-Client-Version"
)

// RequestLog records one line per request, except for the paths given.
//
// Probes are the reason for that exception: an orchestrator calls them every
// few seconds forever, and logging each one buries everything else.
func RequestLog(quiet ...string) func(http.Handler) http.Handler {
	silent := make(map[string]struct{}, len(quiet))
	for _, path := range quiet {
		silent[path] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := silent[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}
			logged(next, w, r)
		})
	}
}

func logged(next http.Handler, w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	next.ServeHTTP(rec, r)

	slog.InfoContext(r.Context(), "request",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", rec.status),
		slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		slog.String("request_id", RequestIDFrom(r.Context())),
		slog.String("client_platform", r.Header.Get(ClientPlatformHeader)),
		slog.String("client_version", r.Header.Get(ClientVersionHeader)),
	)
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.written {
		return
	}
	r.written = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}
