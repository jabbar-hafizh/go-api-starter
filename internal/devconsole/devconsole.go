// Package devconsole serves a page that stands in for the front end.
//
// It exists because two things in this API end in a browser redirect rather
// than a response body: provider sign-in, and the link in a verification
// email. Without a page to land on, exercising either one means reading
// cookies out of developer tools by hand.
//
// Registered only when APP_ENV is local.
package devconsole

import (
	_ "embed"
	"net/http"
)

// Path is where the console is served. APP_BASE_URL should point at it, so the
// provider callback and the email link both land here.
const Path = "/dev"

//go:embed page.html
var page []byte

// Register adds the console to mux.
func Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+Path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})
}
