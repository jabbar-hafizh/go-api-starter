package calculator

import (
	"net/http"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
)

type calcError struct {
	code    string
	message string
	details []httperr.Detail
}

func (e *calcError) Error() string { return e.message }

// HTTPStatus is 422 for everything here: the request was understood, the
// arithmetic it asked for is the problem.
func (e *calcError) HTTPStatus() int { return http.StatusUnprocessableEntity }

func (e *calcError) Code() string { return e.code }

func (e *calcError) Details() []httperr.Detail { return e.details }

// Failures a caller can cause.
var (
	ErrDivideByZero = &calcError{
		code:    "ERR_CALC_DIVIDE_BY_ZERO",
		message: "cannot divide by zero",
		details: []httperr.Detail{{Field: "b", Message: "must not be zero when dividing"}},
	}
	ErrUnknownOperation = &calcError{
		code:    "ERR_CALC_UNKNOWN_OPERATION",
		message: "unknown operation",
		details: []httperr.Detail{{Field: "operation", Message: "must be add, subtract, multiply or divide"}},
	}
)

func newInvalidOperand(field, message string) *calcError {
	return &calcError{
		code:    "ERR_CALC_INVALID_OPERAND",
		message: "invalid operand",
		details: []httperr.Detail{{Field: field, Message: message}},
	}
}
