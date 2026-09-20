package calculator_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/calculator"
	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

func TestHandlerCalculate(t *testing.T) {
	t.Parallel()

	got, err := calculate(t, "add", "10.5", "3")
	require.NoError(t, err)
	require.Equal(t, openapi.Calculate200JSONResponse{Result: "13.5"}, got)
}

func TestHandlerReportsTheOffendingField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		op, a, b      string
		wantCode      string
		wantField     string
		wantSubstring string
	}{
		{
			name: "a is not a number", op: "add", a: "twelve", b: "3",
			wantCode: "ERR_CALC_INVALID_OPERAND", wantField: "a",
			wantSubstring: "decimal number",
		},
		{
			name: "b is not a number", op: "add", a: "1", b: "",
			wantCode: "ERR_CALC_INVALID_OPERAND", wantField: "b",
			wantSubstring: "required",
		},
		{
			name: "b is too long", op: "add", a: "1", b: strings.Repeat("9", 65),
			wantCode: "ERR_CALC_INVALID_OPERAND", wantField: "b",
			wantSubstring: "at most",
		},
		{
			name: "divide by zero", op: "divide", a: "1", b: "0",
			wantCode: "ERR_CALC_DIVIDE_BY_ZERO", wantField: "b",
			wantSubstring: "zero",
		},
		{
			name: "unknown operation", op: "power", a: "2", b: "8",
			wantCode: "ERR_CALC_UNKNOWN_OPERATION", wantField: "operation",
			wantSubstring: "add, subtract",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := calculate(t, tt.op, tt.a, tt.b)
			require.Error(t, err)

			// Bad arithmetic is the caller's input, not a broken server, so
			// this must never become a 500.
			var se httperr.StatusError
			require.ErrorAs(t, err, &se)
			require.Equal(t, 422, se.HTTPStatus())
			require.Equal(t, tt.wantCode, se.Code())

			var dp httperr.DetailProvider
			require.ErrorAs(t, err, &dp)
			require.Len(t, dp.Details(), 1)
			require.Equal(t, tt.wantField, dp.Details()[0].Field)
			require.Contains(t, dp.Details()[0].Message, tt.wantSubstring)
		})
	}
}

func TestHandlerRejectsMissingBody(t *testing.T) {
	t.Parallel()

	_, err := calculator.NewHandler().Calculate(t.Context(), openapi.CalculateRequestObject{})
	require.Error(t, err)

	var se httperr.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, 422, se.HTTPStatus())
}

func calculate(t *testing.T, op, a, b string) (openapi.CalculateResponseObject, error) {
	t.Helper()

	return calculator.NewHandler().Calculate(t.Context(), openapi.CalculateRequestObject{
		Body: &openapi.CalculationRequest{
			Operation: openapi.CalculationRequestOperation(op),
			A:         a,
			B:         b,
		},
	})
}
