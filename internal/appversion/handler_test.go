package appversion_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/appversion"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

func TestHandlerForcesUpgrade(t *testing.T) {
	t.Parallel()

	got := decide(t, "ios", "1.0.0")
	require.True(t, got.ForceUpgrade)
	require.Equal(t, "2.0.0", *got.MinSupportedVersion)
	require.Equal(t, "Update to continue.", *got.UpgradeMessage)
}

func TestHandlerAllowsCurrentBuild(t *testing.T) {
	t.Parallel()

	got := decide(t, "ios", "2.1.0")
	require.False(t, got.ForceUpgrade)
	require.Equal(t, "2.0.0", *got.MinSupportedVersion)
	require.Nil(t, got.UpgradeMessage, "no message when nothing is wrong")
}

// Omitted headers must not force an upgrade, and must not panic on the nil
// pointers the generated params use for optional values.
func TestHandlerWithoutHeaders(t *testing.T) {
	t.Parallel()

	h := appversion.NewHandler(appversion.NewGate("2.0.0", "3.1.0", "Update to continue."))

	got, err := h.GetAppConfig(t.Context(), openapi.GetAppConfigRequestObject{})
	require.NoError(t, err)

	body, ok := got.(openapi.GetAppConfig200JSONResponse)
	require.True(t, ok)
	require.False(t, body.ForceUpgrade)
	require.Nil(t, body.MinSupportedVersion)
}

func decide(t *testing.T, platform, version string) openapi.GetAppConfig200JSONResponse {
	t.Helper()

	h := appversion.NewHandler(appversion.NewGate("2.0.0", "3.1.0", "Update to continue."))
	p := openapi.GetAppConfigParamsXClientPlatform(platform)

	got, err := h.GetAppConfig(t.Context(), openapi.GetAppConfigRequestObject{
		Params: openapi.GetAppConfigParams{
			XClientPlatform: &p,
			XClientVersion:  &version,
		},
	})
	require.NoError(t, err)

	body, ok := got.(openapi.GetAppConfig200JSONResponse)
	require.True(t, ok)
	return body
}
