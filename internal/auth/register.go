package auth

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/google/uuid"
)

const (
	maxEmailLen    = 254
	minPasswordLen = 12
	maxPasswordLen = 256
)

// Register creates an account and emails a verification link.
//
// It deliberately issues no session. Verifying the email first is what makes
// auto-linking a provider identity safe later: without it, someone can claim
// an address they do not own and inherit the real owner's SSO login.
func (s *Service) Register(ctx context.Context, email, password string) (User, error) {
	email = normalizeEmail(email)

	if err := validateRegistration(email, password); err != nil {
		return User{}, err
	}

	hash, err := hashPassword(password)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	user, err := s.store.CreateUser(ctx, uuid.Must(uuid.NewV7()), email, &hash)
	if err != nil {
		return User{}, err
	}

	if err := s.sendEmailVerification(ctx, user); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Service) sendEmailVerification(ctx context.Context, user User) error {
	plain, hash, err := newVerificationToken()
	if err != nil {
		return err
	}

	err = s.store.CreateVerificationToken(ctx, VerificationToken{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    user.ID,
		Purpose:   purposeEmailVerify,
		TokenHash: hash,
		ExpiresAt: s.now().Add(s.emailTTL),
	})
	if err != nil {
		return err
	}

	if err := s.mailer.SendEmailVerification(ctx, user.Email, plain); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	return nil
}

func validateRegistration(email, password string) error {
	var v validator

	switch {
	case email == "":
		v.add("email", "is required")
	case len(email) > maxEmailLen:
		v.add("email", fmt.Sprintf("must be at most %d characters", maxEmailLen))
	default:
		if _, err := mail.ParseAddress(email); err != nil {
			v.add("email", "is not a valid email address")
		}
	}

	switch {
	case password == "":
		v.add("password", "is required")
	case len(password) < minPasswordLen:
		// Length is the only rule. Composition rules push people towards
		// predictable substitutions without adding real entropy.
		v.add("password", fmt.Sprintf("must be at least %d characters", minPasswordLen))
	case len(password) > maxPasswordLen:
		v.add("password", fmt.Sprintf("must be at most %d characters", maxPasswordLen))
	}

	return v.err()
}

// normalizeEmail only trims and lowercases. The database column is citext, so
// uniqueness is enforced there rather than relying on this.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
