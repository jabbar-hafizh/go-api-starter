package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
)

// Recover turns a panic into a logged 500 instead of a dropped connection.
//
// Without it the client sees the connection close with no status and no body,
// which is the hardest kind of failure to diagnose from the outside.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}

			// ErrAbortHandler is how net/http signals a deliberate abort. It
			// is not a bug and must be passed on.
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(recovered)
			}

			slog.ErrorContext(ctx, "panic recovered",
				slog.Any("panic", recovered),
				slog.String("path", r.URL.Path),
				slog.String("stack", string(debug.Stack())),
			)
			httperr.Response(w, r, errors.New("panic recovered"))
		}()

		next.ServeHTTP(w, r)
	})
}
