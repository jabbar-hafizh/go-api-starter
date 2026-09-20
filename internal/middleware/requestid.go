package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// RequestIDHeader is echoed on every response so a client can quote it in a
// bug report and it can be found in the logs.
const RequestIDHeader = "X-Request-Id"

const requestIDKey ctxKey = iota + 1

// RequestID always generates its own id rather than trusting an incoming
// header, which a caller could use to collide with or poison another trace.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.Must(uuid.NewV7()).String()

		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// RequestIDFrom returns the id assigned to this request, if any.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}
