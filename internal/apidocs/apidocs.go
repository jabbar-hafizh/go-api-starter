// Package apidocs serves the API contract and a page to read it in.
//
// These routes are not in the OpenAPI document and so are not generated: a
// document cannot describe how it is itself served.
package apidocs

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
)

// Paths served by Register. They are public: the API surface is not a secret,
// and every client ships with these paths inside it anyway.
const (
	SpecPath = "/openapi.json"
	UIPath   = "/docs"
)

// page renders the spec. Loaded from a CDN rather than vendored, because this
// is a development convenience and not part of the API.
const page = `<!doctype html>
<html>
  <head>
    <title>go-api-starter</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" data-url="` + SpecPath + `"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`

// Register adds the documentation routes to mux.
func Register(mux *http.ServeMux, spec *openapi3.T) {
	mux.HandleFunc("GET "+SpecPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(spec); err != nil {
			slog.ErrorContext(r.Context(), "failed to write openapi document", slog.Any("err", err))
		}
	})

	mux.HandleFunc("GET "+UIPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
}
