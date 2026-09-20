package auth

import (
	"net/http"
	"time"
)

// refreshCookieName is scoped to the auth paths below, so it is not attached
// to every request the browser makes.
const (
	refreshCookieName = "refresh_token"
	refreshCookiePath = "/v1/auth"
)

// newRefreshCookie stores the token where a script cannot read it. This is the
// whole reason web clients never receive it in the response body.
func newRefreshCookie(value string, ttl time.Duration, secure bool) *http.Cookie {
	//nolint:gosec // Secure is deliberately a variable: it is true everywhere
	// except local HTTP, where a Secure cookie would simply be dropped.
	return &http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     refreshCookiePath,
		HttpOnly: true,
		// Off over plain HTTP, otherwise the browser drops the cookie and
		// local development silently stops working.
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
}

func expiredRefreshCookie(secure bool) *http.Cookie {
	//nolint:gosec // same reasoning as newRefreshCookie
	c := newRefreshCookie("", 0, secure)
	c.MaxAge = -1
	return c
}
