package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP resolves who to attribute a request to.
//
// hops is how many proxies sit in front of this process. X-Forwarded-For is
// appended to, so the entry that many places from the right is the one the
// nearest trusted proxy wrote, and everything left of it is caller-supplied.
// With hops at zero the header is ignored entirely: trusting it then would let
// anyone rotate their apparent address and walk straight through rate limits.
func ClientIP(r *http.Request, hops int) string {
	if hops > 0 {
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if idx := len(forwarded) - hops; idx >= 0 && idx < len(forwarded) {
			if ip := strings.TrimSpace(forwarded[idx]); ip != "" {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
