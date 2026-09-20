package calculator_test

import (
	"strings"
	"testing"

	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/calculator"
)

func TestEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		op   calculator.Operation
		a, b string
		want string
	}{
		{"add", calculator.Add, "10.5", "3", "13.5"},
		{"subtract", calculator.Subtract, "10.5", "3", "7.5"},
		{"multiply", calculator.Multiply, "10.5", "3", "31.5"},
		{"divide", calculator.Divide, "10.5", "3", "3.5"},

		{"add negatives", calculator.Add, "-7", "-3", "-10"},
		{"subtract into negative", calculator.Subtract, "3", "10", "-7"},
		{"multiply by zero", calculator.Multiply, "12345.6789", "0", "0"},
		{"divide into a negative", calculator.Divide, "-9", "3", "-3"},

		// The whole reason for decimal over float64. In float64 this is
		// 0.30000000000000004, which is a bug report waiting to happen in
		// something called a calculator.
		{"tenths add exactly", calculator.Add, "0.1", "0.2", "0.3"},
		{"cents subtract exactly", calculator.Subtract, "1.10", "1.00", "0.1"},

		{
			"big integers keep every digit", calculator.Multiply,
			"99999999999999999999", "99999999999999999999",
			"9999999999999999999800000000000000000001",
		},
		{
			"many decimal places survive", calculator.Add,
			"0.000000000000000001", "0.000000000000000002", "0.000000000000000003",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := calculator.Evaluate(tt.op, dec(t, tt.a), dec(t, tt.b))
			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())
		})
	}
}

// Division that does not terminate is rounded rather than refused, and the
// precision is whatever the decimal library is configured for.
func TestDivideRoundsRepeatingResults(t *testing.T) {
	t.Parallel()

	got, err := calculator.Evaluate(calculator.Divide, dec(t, "1"), dec(t, "3"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(got.String(), "0.3333333333333333"))
}

func TestDivideByZero(t *testing.T) {
	t.Parallel()

	for _, numerator := range []string{"1", "0", "-42.5"} {
		t.Run(numerator, func(t *testing.T) {
			t.Parallel()

			_, err := calculator.Evaluate(calculator.Divide, dec(t, numerator), dec(t, "0"))
			require.ErrorIs(t, err, calculator.ErrDivideByZero)
		})
	}
}

func TestUnknownOperation(t *testing.T) {
	t.Parallel()

	for _, op := range []string{"", "power", "ADD", "Add", "modulo"} {
		t.Run(op, func(t *testing.T) {
			t.Parallel()

			_, err := calculator.Evaluate(calculator.Operation(op), dec(t, "1"), dec(t, "1"))
			require.ErrorIs(t, err, calculator.ErrUnknownOperation)
		})
	}
}

func TestParseOperand(t *testing.T) {
	t.Parallel()

	valid := []struct{ in, want string }{
		{"0", "0"},
		{"42", "42"},
		{"-42", "-42"},
		{"10.5", "10.5"},
		{"-0.001", "-0.001"},
		{"1e3", "1000"},
		// shopspring accepts a trailing dot. Lenient, but harmless: it parses
		// to the number a person clearly meant.
		{"12.", "12"},
	}

	for _, tt := range valid {
		t.Run("valid "+tt.in, func(t *testing.T) {
			t.Parallel()

			got, err := calculator.ParseOperand("a", tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())
		})
	}

	invalid := map[string]string{
		"empty":       "",
		"words":       "twelve",
		"two dots":    "1.2.3",
		"with spaces": " 12 ",
		"hex":         "0xFF",
		// Bounded so one request cannot ask for arbitrarily large arithmetic.
		"too long": strings.Repeat("9", 65),
	}

	for name, in := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			t.Parallel()

			_, err := calculator.ParseOperand("a", in)
			require.Error(t, err)
		})
	}
}

func dec(t *testing.T, s string) decimal.Decimal {
	t.Helper()

	d, err := decimal.NewFromString(s)
	require.NoError(t, err)
	return d
}
