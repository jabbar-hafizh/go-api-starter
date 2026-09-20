package auth

import (
	"context"
	"errors"
)

// VerifyEmail burns the token and marks the address verified, in one statement
// so the two can never come apart.
func (s *Service) VerifyEmail(ctx context.Context, plain string) error {
	if plain == "" {
		return ErrTokenNotUsable
	}

	_, err := s.store.ConsumeEmailVerification(ctx, hashToken(plain))
	if err != nil {
		// Unknown, expired and already used are one answer: a client that can
		// tell them apart can probe for valid tokens.
		if errors.Is(err, ErrTokenNotUsable) {
			return ErrTokenNotUsable
		}
		return err
	}
	return nil
}
