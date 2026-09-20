package appversion

import (
	"context"

	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

// Handler serves the client's own configuration.
type Handler struct {
	gate *Gate
}

// NewHandler returns the HTTP handler for this package's operations.
func NewHandler(gate *Gate) *Handler { return &Handler{gate: gate} }

func (h *Handler) GetAppConfig(_ context.Context, req openapi.GetAppConfigRequestObject) (openapi.GetAppConfigResponseObject, error) {
	var platform, version string
	if req.Params.XClientPlatform != nil {
		platform = string(*req.Params.XClientPlatform)
	}
	if req.Params.XClientVersion != nil {
		version = *req.Params.XClientVersion
	}

	d := h.gate.Decide(platform, version)

	out := openapi.GetAppConfig200JSONResponse{ForceUpgrade: d.ForceUpgrade}
	if d.MinSupportedVersion != "" {
		out.MinSupportedVersion = &d.MinSupportedVersion
	}
	if d.UpgradeMessage != "" {
		out.UpgradeMessage = &d.UpgradeMessage
	}
	return out, nil
}
