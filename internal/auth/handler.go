package auth

import (
	"context"
	"errors"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/jabbar-hafizh/go-api-starter/internal/middleware"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

// Handler adapts the account use cases to the generated server interface.
// It holds no logic: everything here is translation.
type Handler struct {
	svc *Service
}

// NewHandler returns the HTTP handler for this package's operations.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) RegisterUser(ctx context.Context, req openapi.RegisterUserRequestObject) (openapi.RegisterUserResponseObject, error) {
	if req.Body == nil {
		return nil, ErrTokenNotUsable
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
		return nil, ErrInvalidCredentials
	}

	access, err := h.svc.Login(ctx, req.Body.Email, req.Body.Password)
	if err != nil {
		return nil, err
	}

	return openapi.LoginUser200JSONResponse{
		AccessToken: access.Value,
		TokenType:   openapi.Bearer,
		ExpiresIn:   int(access.ExpiresIn.Seconds()),
	}, nil
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
