// Package httperr is the only place errors become HTTP responses.
//
// It imports no feature package. Features just satisfy StatusError and Go
// matches it implicitly, which is what keeps auth -> httperr -> auth from
// becoming an import cycle.
package httperr

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

// Error codes owned by this package. Everything else comes from a feature.
const (
	CodeInternal   = "ERR_INTERNAL"
	CodeBadRequest = "ERR_BAD_REQUEST"
)

// StatusError is satisfied by domain errors that know how they should look
// over HTTP.
type StatusError interface {
	error
	HTTPStatus() int
	Code() string
}

// Detail is one field-level problem. It is declared here rather than reused
// from the generated types so feature packages can report validation errors
// without importing generated code.
type Detail struct {
	Field   string
	Message string
}

// DetailProvider is optional, for validation errors that point at a field.
type DetailProvider interface {
	Details() []Detail
}

// Response is wired in as the strict server's ResponseErrorHandlerFunc, so
// handlers just return a domain error.
func Response(w http.ResponseWriter, r *http.Request, err error) {
	var se StatusError
	if errors.As(err, &se) {
		body := openapi.Error{Code: se.Code(), Message: se.Error()}

		var dp DetailProvider
		if errors.As(err, &dp) {
			details := make([]openapi.ErrorDetail, 0, len(dp.Details()))
			for _, d := range dp.Details() {
				details = append(details, openapi.ErrorDetail{Field: d.Field, Message: d.Message})
			}
			body.Details = &details
		}
		write(w, r, se.HTTPStatus(), body)
		return
	}

	// Anything unrecognised is a 500 and gets logged. Backstop: even if a path
	// forgets to wrap its error, internals never reach the client.
	slog.ErrorContext(r.Context(), "unhandled error",
		slog.String("path", r.URL.Path),
		slog.String("method", r.Method),
		slog.Any("err", err),
	)
	write(w, r, http.StatusInternalServerError, openapi.Error{
		Code:    CodeInternal,
		Message: "internal server error",
	})
}

// Request handles failures before the handler runs, like a malformed body.
func Request(w http.ResponseWriter, r *http.Request, err error) {
	slog.WarnContext(r.Context(), "bad request",
		slog.String("path", r.URL.Path),
		slog.Any("err", err),
	)
	write(w, r, http.StatusBadRequest, openapi.Error{
		Code:    CodeBadRequest,
		Message: "request could not be processed",
	})
}

func write(w http.ResponseWriter, r *http.Request, status int, body openapi.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Headers are already out, so logging is all that is left.
		slog.ErrorContext(r.Context(), "failed to write error body", slog.Any("err", err))
	}
}
