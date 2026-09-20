package middleware

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
)

type specViolationError struct{ detail string }

func (e specViolationError) Error() string { return e.detail }
func (specViolationError) HTTPStatus() int { return http.StatusBadRequest }
func (specViolationError) Code() string    { return "ERR_SPEC_VIOLATION" }

// ValidateSpec checks every request against the OpenAPI document.
//
// The generated types already constrain shape, but not required fields, enum
// membership or formats. This closes that gap, and it is how a contract
// violation fails a test rather than reaching a client.
//
// A path the document does not describe is rejected, which is deliberate: it
// catches a route that exists but was never written down. skip lists the few
// routes served on purpose outside the contract, such as the documentation
// itself, since a document cannot describe how it is served.
//
// It is expensive, so it runs in development and tests only. Responses are not
// checked: the strict server derives those types from the same document, so
// they cannot drift from it.
func ValidateSpec(spec *openapi3.T, skip ...string) func(http.Handler) http.Handler {
	// The servers list would otherwise make the router reject any host that is
	// not listed, which is every host but the one in the document.
	spec.Servers = nil

	skipped := make(map[string]struct{}, len(skip))
	for _, path := range skip {
		skipped[path] = struct{}{}
	}

	validate := nethttpmiddleware.OapiRequestValidatorWithOptions(spec,
		&nethttpmiddleware.Options{
			Options: openapi3filter.Options{
				// Authentication is the Authenticate middleware's job. Without
				// this the validator would reject every secured route for
				// having no security handler registered.
				AuthenticationFunc: func(context.Context, *openapi3filter.AuthenticationInput) error {
					return nil
				},
			},
			ErrorHandlerWithOpts: func(_ context.Context, err error, w http.ResponseWriter, r *http.Request, _ nethttpmiddleware.ErrorHandlerOpts) {
				httperr.Response(w, r, specViolationError{detail: err.Error()})
			},
		})

	return func(next http.Handler) http.Handler {
		validated := validate(next)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := skipped[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}
			validated.ServeHTTP(w, r)
		})
	}
}
