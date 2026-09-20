package middleware

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const corsMaxAge = 12 * time.Hour

// CORS answers preflights and marks responses for an allowlisted origin.
//
// The allowlist is exact. Reflecting whatever Origin arrives, which is the
// usual shortcut, combined with credentials would let any site on the internet
// make authenticated calls on a signed-in user's behalf.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowedHeaders := strings.Join([]string{
		"Authorization", "Content-Type", "Idempotency-Key",
		ClientPlatformHeader, ClientVersionHeader,
	}, ", ")
	allowedMethods := strings.Join([]string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions,
	}, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && slices.Contains(allowedOrigins, origin) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				// Caches must not serve one origin's response to another.
				h.Add("Vary", "Origin")
				// Needed for the refresh cookie to be sent and set.
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Expose-Headers", RequestIDHeader)

				if r.Method == http.MethodOptions {
					h.Set("Access-Control-Allow-Methods", allowedMethods)
					h.Set("Access-Control-Allow-Headers", allowedHeaders)
					h.Set("Access-Control-Max-Age", strconv.Itoa(int(corsMaxAge.Seconds())))
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
