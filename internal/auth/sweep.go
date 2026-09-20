package auth

import (
	"context"
	"fmt"
)

// refreshTokenGraceDays is how long an expired refresh token is kept. Deleting
// it the moment it expires would mean a replay just after expiry looks like an
// unknown token rather than reuse, and its chain would survive.
const refreshTokenGraceDays = 30

// SweepExpired deletes records that have aged out.
//
// Without it every abandoned sign-in leaves an oauth_states row forever, which
// is a slow leak an attacker can drive by repeatedly starting a sign-in they
// never finish.
func (s *Service) SweepExpired(ctx context.Context) error {
	if err := s.store.DeleteExpiredOAuthStates(ctx); err != nil {
		return fmt.Errorf("sweep oauth states: %w", err)
	}
	if err := s.store.DeleteExpiredVerificationTokens(ctx); err != nil {
		return fmt.Errorf("sweep verification tokens: %w", err)
	}
	if err := s.store.DeleteExpiredRefreshTokens(ctx, refreshTokenGraceDays); err != nil {
		return fmt.Errorf("sweep refresh tokens: %w", err)
	}
	return nil
}
