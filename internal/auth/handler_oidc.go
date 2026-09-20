package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

func (h *Handler) ListProviders(ctx context.Context, _ openapi.ListProvidersRequestObject) (openapi.ListProvidersResponseObject, error) {
	providers, err := h.svc.Providers(ctx)
	if err != nil {
		return nil, err
	}

	out := make(openapi.ListProviders200JSONResponse, 0, len(providers))
	for _, p := range providers {
		out = append(out, openapi.ProviderInfo{Code: p.Code, DisplayName: p.DisplayName})
	}
	return out, nil
}

func (h *Handler) StartProviderSignIn(ctx context.Context, req openapi.StartProviderSignInRequestObject) (openapi.StartProviderSignInResponseObject, error) {
	redirectTo, err := safeRedirectPath(req.Params.RedirectTo)
	if err != nil {
		return nil, err
	}

	target, err := h.svc.StartProviderSignIn(ctx, req.Provider, redirectTo)
	if err != nil {
		return nil, err
	}
	return openapi.StartProviderSignIn302Response{
		Headers: openapi.StartProviderSignIn302ResponseHeaders{Location: &target},
	}, nil
}

func (h *Handler) CompleteProviderSignIn(ctx context.Context, req openapi.CompleteProviderSignInRequestObject) (openapi.CompleteProviderSignInResponseObject, error) {
	// The browser flow is a web client by definition, so the refresh token
	// goes in the cookie and nowhere else.
	session, redirectTo, err := h.svc.CompleteProviderSignIn(ctx, req.Params.State, req.Params.Code, PlatformWeb)
	if err != nil {
		return nil, err
	}

	return callbackResponse{
		location: h.appURL(redirectTo),
		cookie:   newRefreshCookie(session.RefreshToken, session.RefreshTTL, h.secureCookies),
	}, nil
}

func (h *Handler) SignInWithProviderToken(ctx context.Context, req openapi.SignInWithProviderTokenRequestObject) (openapi.SignInWithProviderTokenResponseObject, error) {
	if req.Body == nil {
		return nil, ErrProviderTokenInvalid
	}

	platform := platformOf((*string)(req.Params.XClientPlatform))

	session, err := h.svc.SignInWithProviderToken(ctx, req.Provider, req.Body.IdToken, platform)
	if err != nil {
		return nil, err
	}
	return h.sessionResponse(session, platform.IsWeb()), nil
}

func (h *Handler) ListIdentities(ctx context.Context, _ openapi.ListIdentitiesRequestObject) (openapi.ListIdentitiesResponseObject, error) {
	userID, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}

	account, err := h.svc.Account(ctx, userID)
	if err != nil {
		return nil, err
	}
	return openapi.ListIdentities200JSONResponse(toAPIIdentities(account.Identities)), nil
}

func (h *Handler) LinkIdentity(ctx context.Context, req openapi.LinkIdentityRequestObject) (openapi.LinkIdentityResponseObject, error) {
	userID, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, ErrProviderTokenInvalid
	}

	identity, err := h.svc.LinkProviderToken(ctx, userID, req.Provider, req.Body.IdToken)
	if err != nil {
		return nil, err
	}
	return openapi.LinkIdentity201JSONResponse(toAPIIdentity(identity)), nil
}

func (h *Handler) UnlinkIdentity(ctx context.Context, req openapi.UnlinkIdentityRequestObject) (openapi.UnlinkIdentityResponseObject, error) {
	userID, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}

	if err := h.svc.UnlinkIdentity(ctx, userID, req.Id); err != nil {
		return nil, err
	}
	return openapi.UnlinkIdentity204Response{}, nil
}

// appURL appends a caller-supplied path to the configured base. Only a path is
// ever accepted, so this cannot be turned into an open redirect.
func (h *Handler) appURL(path *string) string {
	if path == nil || *path == "" {
		return h.baseURL
	}
	return strings.TrimRight(h.baseURL, "/") + *path
}

// safeRedirectPath accepts a single-slash path and nothing else. "//evil.com"
// and "https://evil.com" are both rejected: browsers treat the first as a
// protocol-relative URL, which is the classic open redirect.
func safeRedirectPath(raw *string) (*string, error) {
	if raw == nil || *raw == "" {
		return nil, nil
	}

	value := *raw
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return nil, errBadRedirect()
	}
	if u, err := url.Parse(value); err != nil || u.Scheme != "" || u.Host != "" {
		return nil, errBadRedirect()
	}
	return &value, nil
}

type callbackResponse struct {
	location string
	cookie   *http.Cookie
}

func (r callbackResponse) VisitCompleteProviderSignInResponse(w http.ResponseWriter) error {
	http.SetCookie(w, r.cookie)
	w.Header().Set("Location", r.location)
	w.WriteHeader(http.StatusFound)
	return nil
}

func errBadRedirect() error {
	return &ValidationError{details: []httperr.Detail{{
		Field:   "redirect_to",
		Message: "must be a path beginning with a single slash",
	}}}
}

// requireUser reads the user the middleware put in the context. Failing here
// means the route was wired as public by mistake, which is a bug, not a
// caller error, so it becomes a logged 500.
func requireUser(ctx context.Context) (uuid.UUID, error) {
	userID, ok := middleware.UserID(ctx)
	if !ok {
		return uuid.Nil, errors.New("authenticated route reached without a user id")
	}
	return userID, nil
}

func toAPIIdentities(in []Identity) []openapi.Identity {
	out := make([]openapi.Identity, 0, len(in))
	for _, i := range in {
		out = append(out, toAPIIdentity(i))
	}
	return out
}

func toAPIIdentity(i Identity) openapi.Identity {
	return openapi.Identity{Id: i.ID, Provider: i.Provider, Email: i.Email}
}
