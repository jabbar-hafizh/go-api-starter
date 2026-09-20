package auth

import (
	"context"
	"errors"
	"fmt"
)

// Login exchanges an email and password for a session.
func (s *Service) Login(ctx context.Context, email, password string, p Platform) (Session, error) {
	user, err := s.store.UserByEmail(ctx, normalizeEmail(email))
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Hash anyway. Skipping this makes an unknown email answer in
			// milliseconds while a wrong password takes tens of them, which
			// tells an attacker exactly which addresses are registered.
			burnPasswordTime()
			return Session{}, ErrInvalidCredentials
		}
		return Session{}, err
	}

	if !user.HasPassword() {
		// SSO-only account. Same answer and same cost as an unknown email:
		// saying "this one uses Google" would confirm the address exists.
		burnPasswordTime()
		return Session{}, ErrInvalidCredentials
	}

	ok, err := verifyPassword(password, *user.PasswordHash)
	if err != nil {
		return Session{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return Session{}, ErrInvalidCredentials
	}

	// Only after the password checks out, so this cannot be used to probe
	// which addresses exist.
	if !user.EmailVerified() {
		return Session{}, ErrEmailNotVerified
	}

	return s.startSession(ctx, user.ID, p)
}
