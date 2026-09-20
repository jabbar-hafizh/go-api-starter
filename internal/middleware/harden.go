package middleware

import "net/http"

// BodyLimit caps how much a caller can send. Without it a single request can
// make the server read an unbounded amount into memory.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders sets the few that mean anything for a JSON API.
//
// The usual list is aimed at HTML: a CSP or X-Frame-Options on a response that
// is always application/json protects nothing and only suggests the list was
// copied rather than chosen.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Stops a browser guessing a content type other than the one sent,
		// which is what turns a stored value into executable script.
		h.Set("X-Content-Type-Options", "nosniff")
		// Tokens and ids must not leak to third parties through Referer.
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// Chain applies middleware so the first listed is the outermost.
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
