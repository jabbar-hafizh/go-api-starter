// Package health answers two different questions that often get mixed up:
// is this process alive, and is it ready to take traffic.
package health

import (
	"context"
	"time"

	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

// pinger is the only thing this package needs from a database pool, declared
// here by the code that uses it.
type pinger interface {
	Ping(ctx context.Context) error
}

// A readiness probe that hangs is worse than one that says no, so each
// dependency check is bounded.
const probeTimeout = 2 * time.Second

// Handler serves the liveness and readiness endpoints.
type Handler struct {
	postgres pinger
}

// NewHandler returns a handler that probes the given dependencies.
func NewHandler(postgres pinger) *Handler {
	return &Handler{postgres: postgres}
}

// GetHealthz touches no dependency on purpose. Liveness that fails when the
// database is down makes the orchestrator restart a healthy process.
func (h *Handler) GetHealthz(_ context.Context, _ openapi.GetHealthzRequestObject) (openapi.GetHealthzResponseObject, error) {
	return openapi.GetHealthz200JSONResponse{Status: openapi.HealthStatusStatusOk}, nil
}

// GetReadyz refuses traffic if any dependency is not ready.
func (h *Handler) GetReadyz(ctx context.Context, _ openapi.GetReadyzRequestObject) (openapi.GetReadyzResponseObject, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	checks := []openapi.ReadinessCheck{h.checkPostgres(ctx)}

	for _, c := range checks {
		if !c.Ok {
			return openapi.GetReadyz503JSONResponse{
				Status: openapi.ReadinessStatusStatusDegraded,
				Checks: checks,
			}, nil
		}
	}
	return openapi.GetReadyz200JSONResponse{
		Status: openapi.ReadinessStatusStatusOk,
		Checks: checks,
	}, nil
}

func (h *Handler) checkPostgres(ctx context.Context) openapi.ReadinessCheck {
	check := openapi.ReadinessCheck{Name: "postgres", Ok: true}
	if err := h.postgres.Ping(ctx); err != nil {
		// The driver message can carry host, port and database name.
		msg := "unreachable"
		check.Ok = false
		check.Error = &msg
	}
	return check
}
