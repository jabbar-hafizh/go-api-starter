package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

// Login exchanges an email and password for an access token.
func (s *Service) Login(ctx context.Context, email, password string) (token.Access, error) {
	user, err := s.store.UserByEmail(ctx, normalizeEmail(email))
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Hash anyway. Skipping this makes an unknown email answer in
			// milliseconds while a wrong password takes tens of them, which
			// tells an attacker exactly which addresses are registered.
			burnPasswordTime()
			return token.Access{}, ErrInvalidCredentials
		}
		return token.Access{}, err
	}

	if !user.HasPassword() {
		// SSO-only account. Same answer and same cost as an unknown email:
		// saying "this one uses Google" would confirm the address exists.
		burnPasswordTime()
		return token.Access{}, ErrInvalidCredentials
	}

	ok, err := verifyPassword(password, *user.PasswordHash)
	if err != nil {
		return token.Access{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return token.Access{}, ErrInvalidCredentials
	}

	// Only after the password checks out, so this cannot be used to probe
	// which addresses exist.
	if !user.EmailVerified() {
		return token.Access{}, ErrEmailNotVerified
	}

	access, err := s.issuer.Issue(user.ID)
	if err != nil {
		return token.Access{}, fmt.Errorf("issue access token: %w", err)
	}
	return access, nil
}
