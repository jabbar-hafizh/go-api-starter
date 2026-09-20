package httperr_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
)

type domainError struct {
	status  int
	code    string
	message string
}

func (e domainError) Error() string   { return e.message }
func (e domainError) HTTPStatus() int { return e.status }
func (e domainError) Code() string    { return e.code }

type withDetails struct {
	domainError
	details []httperr.Detail
}

func (e withDetails) Details() []httperr.Detail { return e.details }

func TestResponseUsesTheDomainErrorsStatusAndCode(t *testing.T) {
	t.Parallel()

	body, status := respond(t, domainError{http.StatusConflict, "ERR_TAKEN", "already taken"})

	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "ERR_TAKEN", body.Code)
	require.Equal(t, "already taken", body.Message)
	require.Nil(t, body.Details)
}

// A domain error stays recognisable through wrapping, so a caller can add
// context with %w without turning a 409 into a 500.
func TestResponseSeesThroughWrapping(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("register: %w", domainError{http.StatusConflict, "ERR_TAKEN", "already taken"})
	body, status := respond(t, err)

	require.Equal(t, http.StatusConflict, status)
	require.Equal(t, "ERR_TAKEN", body.Code)
}

func TestResponseIncludesFieldDetails(t *testing.T) {
	t.Parallel()

	body, status := respond(t, withDetails{
		domainError: domainError{http.StatusUnprocessableEntity, "ERR_VALIDATION_FAILED", "validation failed"},
		details: []httperr.Detail{
			{Field: "email", Message: "is required"},
			{Field: "password", Message: "is too short"},
		},
	})

	require.Equal(t, http.StatusUnprocessableEntity, status)
	require.Len(t, body.Details, 2)
	require.Equal(t, "email", body.Details[0].Field)
	require.Equal(t, "is too short", body.Details[1].Message)
}

// Anything that is not a domain error becomes a flat 500. This is the backstop
// that stops a driver message or a stack detail reaching the client.
func TestResponseHidesUnknownErrors(t *testing.T) {
	t.Parallel()

	body, status := respond(t, errors.New("pq: relation \"users\" does not exist at host db-prod-1"))

	require.Equal(t, http.StatusInternalServerError, status)
	require.Equal(t, "ERR_INTERNAL", body.Code)
	require.Equal(t, "internal server error", body.Message)
	require.NotContains(t, body.Message, "users")
	require.NotContains(t, body.Message, "db-prod-1")
}

func TestRequestErrorsAreFlat400s(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	rec := httptest.NewRecorder()
	httperr.Request(rec, req, errors.New("can't decode JSON body: unexpected EOF at offset 17"))

	require.Equal(t, http.StatusBadRequest, rec.Code)

	var body errorBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "ERR_BAD_REQUEST", body.Code)
	require.NotContains(t, body.Message, "offset")
}

func TestContentTypeIsJSON(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	rec := httptest.NewRecorder()
	httperr.Response(rec, req, domainError{http.StatusUnauthorized, "ERR_UNAUTHORIZED", "nope"})

	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details []struct {
		Field   string `json:"field"`
		Message string `json:"message"`
	} `json:"details"`
}

func respond(t *testing.T, err error) (errorBody, int) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", nil)
	rec := httptest.NewRecorder()
	httperr.Response(rec, req, err)

	var body errorBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body, rec.Code
}
