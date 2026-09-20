// Package calculator evaluates a single arithmetic operation.
//
// The operations are fixed rather than parsed from an expression. "2 + 3 * (4
// - 1)" needs a tokeniser, precedence, an AST and its own protection against
// input bombs, which is a different piece of work with its own design.
package calculator

import (
	"fmt"

	"github.com/shopspring/decimal"
)

// Operation is one of the supported arithmetic operations.
type Operation string

// The supported operations.
const (
	Add      Operation = "add"
	Subtract Operation = "subtract"
	Multiply Operation = "multiply"
	Divide   Operation = "divide"
)

// maxOperandLen bounds a single operand. decimal is arbitrary precision, so
// without a cap one request can ask the server to multiply two numbers with a
// million digits each.
const maxOperandLen = 64

// Evaluate is a pure function: no context, no clock, no dependencies. That is
// what makes it exhaustively testable, and it is the whole point of keeping it
// separate from the handler.
func Evaluate(op Operation, a, b decimal.Decimal) (decimal.Decimal, error) {
	switch op {
	case Add:
		return a.Add(b), nil
	case Subtract:
		return a.Sub(b), nil
	case Multiply:
		return a.Mul(b), nil
	case Divide:
		if b.IsZero() {
			// A caller asking for x/0 sent bad input; the server is fine. A 500
			// here would page someone over a user typing a zero.
			return decimal.Decimal{}, ErrDivideByZero
		}
		return a.Div(b), nil
	default:
		return decimal.Decimal{}, ErrUnknownOperation
	}
}

// ParseOperand turns the string form used on the wire into a number.
func ParseOperand(field, raw string) (decimal.Decimal, error) {
	switch {
	case raw == "":
		return decimal.Decimal{}, newInvalidOperand(field, "is required")
	case len(raw) > maxOperandLen:
		return decimal.Decimal{}, newInvalidOperand(field,
			fmt.Sprintf("must be at most %d characters", maxOperandLen))
	}

	value, err := decimal.NewFromString(raw)
	if err != nil {
		return decimal.Decimal{}, newInvalidOperand(field, "is not a decimal number")
	}
	return value, nil
}
