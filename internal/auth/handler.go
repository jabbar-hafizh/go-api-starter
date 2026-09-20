package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

// Handler adapts the account use cases to the generated server interface.
// It holds no logic: everything here is translation.
type Handler struct {
	svc *Service
	// secureCookies is off over plain HTTP, otherwise browsers drop the
	// refresh cookie and local development silently stops working.
	secureCookies bool
}

// NewHandler returns the HTTP handler for this package's operations.
func NewHandler(svc *Service, secureCookies bool) *Handler {
	return &Handler{svc: svc, secureCookies: secureCookies}
}

func (h *Handler) RegisterUser(ctx context.Context, req openapi.RegisterUserRequestObject) (openapi.RegisterUserResponseObject, error) {
	if req.Body == nil {
		return nil, &ValidationError{details: requiredBodyDetails()}
	}

	user, err := h.svc.Register(ctx, req.Body.Email, req.Body.Password)
	if err != nil {
		return nil, err
	}

	return openapi.RegisterUser201JSONResponse{
		Id:            user.ID,
		Email:         openapi_types.Email(user.Email),
		EmailVerified: user.EmailVerified(),
	}, nil
}

func (h *Handler) LoginUser(ctx context.Context, req openapi.LoginUserRequestObject) (openapi.LoginUserResponseObject, error) {
	if req.Body == nil {
		return nil, &ValidationError{details: requiredBodyDetails()}
	}

	platform := platformOf((*string)(req.Params.XClientPlatform))

	session, err := h.svc.Login(ctx, req.Body.Email, req.Body.Password, platform)
	if err != nil {
		return nil, err
	}
	return h.sessionResponse(session, platform), nil
}

func (h *Handler) RefreshSession(ctx context.Context, req openapi.RefreshSessionRequestObject) (openapi.RefreshSessionResponseObject, error) {
	platform := platformOf((*string)(req.Params.XClientPlatform))

	presented := (*string)(req.Params.RefreshToken)
	if req.Body != nil && req.Body.RefreshToken != nil {
		presented = req.Body.RefreshToken
	}

	session, err := h.svc.Refresh(ctx, deref(presented), platform)
	if err != nil {
		return nil, err
	}
	return h.sessionResponse(session, platform), nil
}

func (h *Handler) Logout(ctx context.Context, req openapi.LogoutRequestObject) (openapi.LogoutResponseObject, error) {
	presented := (*string)(req.Params.RefreshToken)
	if req.Body != nil && req.Body.RefreshToken != nil {
		presented = req.Body.RefreshToken
	}

	h.svc.Logout(ctx, deref(presented))

	// The cookie is cleared whether or not anything was revoked, so a client
	// that asked to leave is never left holding a token.
	return logoutResponse{clear: expiredRefreshCookie(h.secureCookies)}, nil
}

func (h *Handler) VerifyEmail(ctx context.Context, req openapi.VerifyEmailRequestObject) (openapi.VerifyEmailResponseObject, error) {
	if req.Body == nil {
		return nil, ErrTokenNotUsable
	}

	if err := h.svc.VerifyEmail(ctx, req.Body.Token); err != nil {
		return nil, err
	}
	return openapi.VerifyEmail204Response{}, nil
}

func (h *Handler) GetMe(ctx context.Context, _ openapi.GetMeRequestObject) (openapi.GetMeResponseObject, error) {
	userID, ok := middleware.UserID(ctx)
	if !ok {
		// The middleware should have stopped this, so reaching here means the
		// route was wired as public by mistake.
		return nil, errors.New("authenticated route reached without a user id")
	}

	account, err := h.svc.Account(ctx, userID)
	if err != nil {
		return nil, err
	}

	identities := make([]openapi.Identity, 0, len(account.Identities))
	for _, id := range account.Identities {
		identities = append(identities, openapi.Identity{
			Id:       id.ID,
			Provider: id.Provider,
			Email:    id.Email,
		})
	}

	return openapi.GetMe200JSONResponse{
		Id:            account.User.ID,
		Email:         openapi_types.Email(account.User.Email),
		EmailVerified: account.User.EmailVerified(),
		AuthMethods: openapi.AuthMethods{
			Password:   account.HasPassword,
			Identities: identities,
		},
	}, nil
}

// sessionResponse decides where the refresh token goes. Web gets a cookie and
// nothing in the body; everyone else gets it in the body and no cookie.
func (h *Handler) sessionResponse(s Session, p Platform) sessionJSONResponse {
	body := openapi.TokenPair{
		AccessToken: s.Access.Value,
		TokenType:   openapi.Bearer,
		ExpiresIn:   int(s.Access.ExpiresIn.Seconds()),
	}

	if p.IsWeb() {
		return sessionJSONResponse{
			body:   body,
			cookie: newRefreshCookie(s.RefreshToken, s.RefreshTTL, h.secureCookies),
		}
	}

	body.RefreshToken = &s.RefreshToken
	return sessionJSONResponse{body: body}
}

// sessionJSONResponse implements the generated response interfaces by hand,
// because setting a cookie is not something the generated types can express.
type sessionJSONResponse struct {
	body   openapi.TokenPair
	cookie *http.Cookie
}

func (r sessionJSONResponse) VisitLoginUserResponse(w http.ResponseWriter) error {
	return r.write(w)
}

func (r sessionJSONResponse) VisitRefreshSessionResponse(w http.ResponseWriter) error {
	return r.write(w)
}

// write emits the token pair. gosec flags serialising a field named like a
// secret, which is exactly what a token endpoint is for.
//
//nolint:gosec // G117
func (r sessionJSONResponse) write(w http.ResponseWriter) error {
	if r.cookie != nil {
		http.SetCookie(w, r.cookie)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(r.body)
}

type logoutResponse struct{ clear *http.Cookie }

func (r logoutResponse) VisitLogoutResponse(w http.ResponseWriter) error {
	http.SetCookie(w, r.clear)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// platformOf treats anything unrecognised as a native client, which is the
// safer default: it never puts a token in a cookie.
func platformOf(raw *string) Platform {
	if raw == nil {
		return ""
	}
	return Platform(*raw)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func requiredBodyDetails() []httperr.Detail {
	return []httperr.Detail{{Field: "body", Message: "is required"}}
}
