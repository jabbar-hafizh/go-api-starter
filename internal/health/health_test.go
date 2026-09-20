package health_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/health"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

type stubPinger struct{ err error }

func (p stubPinger) Ping(context.Context) error { return p.err }

// Liveness must not depend on anything. If it failed whenever the database
// blipped, the orchestrator would restart a process that is working fine.
func TestHealthzIgnoresDependencies(t *testing.T) {
	t.Parallel()

	h := health.NewHandler(stubPinger{err: errors.New("database is down")})

	got, err := h.GetHealthz(context.Background(), openapi.GetHealthzRequestObject{})
	require.NoError(t, err)
	require.Equal(t, openapi.GetHealthz200JSONResponse{Status: openapi.HealthStatusStatusOk}, got)
}

func TestReadyzWhenEverythingIsUp(t *testing.T) {
	t.Parallel()

	h := health.NewHandler(stubPinger{})

	got, err := h.GetReadyz(context.Background(), openapi.GetReadyzRequestObject{})
	require.NoError(t, err)

	ok, isOK := got.(openapi.GetReadyz200JSONResponse)
	require.True(t, isOK, "a healthy dependency must produce a 200")
	require.Equal(t, openapi.ReadinessStatusStatusOk, ok.Status)
	require.Len(t, ok.Checks, 1)
	require.Equal(t, "postgres", ok.Checks[0].Name)
	require.True(t, ok.Checks[0].Ok)
	require.Nil(t, ok.Checks[0].Error)
}

func TestReadyzWhenPostgresIsDown(t *testing.T) {
	t.Parallel()

	h := health.NewHandler(stubPinger{
		err: errors.New(`dial tcp 10.0.3.7:5432: connect: connection refused`),
	})

	got, err := h.GetReadyz(context.Background(), openapi.GetReadyzRequestObject{})
	require.NoError(t, err)

	degraded, isDegraded := got.(openapi.GetReadyz503JSONResponse)
	require.True(t, isDegraded, "a failed dependency must produce a 503")
	require.Equal(t, openapi.ReadinessStatusStatusDegraded, degraded.Status)
	require.False(t, degraded.Checks[0].Ok)
	require.NotNil(t, degraded.Checks[0].Error)

	// The driver message names the host and port. Readiness is usually the
	// most exposed endpoint there is, so none of that is passed on.
	require.Equal(t, "unreachable", *degraded.Checks[0].Error)
}
