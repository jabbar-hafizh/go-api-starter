package calculator

import (
	"context"

	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

// Handler adapts the arithmetic to the generated server interface. There is no
// service layer between them because there would be nothing for it to do.
type Handler struct{}

// NewHandler returns the HTTP handler for this package's operations.
func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Calculate(_ context.Context, req openapi.CalculateRequestObject) (openapi.CalculateResponseObject, error) {
	if req.Body == nil {
		return nil, newInvalidOperand("a", "is required")
	}

	a, err := ParseOperand("a", req.Body.A)
	if err != nil {
		return nil, err
	}
	b, err := ParseOperand("b", req.Body.B)
	if err != nil {
		return nil, err
	}

	result, err := Evaluate(Operation(req.Body.Operation), a, b)
	if err != nil {
		return nil, err
	}

	return openapi.Calculate200JSONResponse{Result: result.String()}, nil
}
