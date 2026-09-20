package auth

import (
	"context"
	"fmt"
	"log/slog"
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

	// Mail failure does not fail registration. The account exists at this
	// point, so answering with an error would tell the caller it did not, and
	// their retry would hit "email already registered" with no way forward.
	// The address stays unverified and the caller can ask for another link.
	if err := s.sendEmailVerification(ctx, user); err != nil {
		slog.ErrorContext(ctx, "registration succeeded but the verification email did not send",
			slog.String("user_id", user.ID.String()),
			slog.Any("err", err),
		)
	}
	return user, nil
}

// ResendEmailVerification issues a fresh link.
//
// It reports nothing back. Saying "no such account" would turn this into a way
// to test which addresses are registered, and saying "already verified" would
// do the same. The caller is told to check their email either way.
func (s *Service) ResendEmailVerification(ctx context.Context, email string) {
	normalized := normalizeEmail(email)

	// Keyed per address, because this endpoint sends mail to whatever address
	// is named: without a ceiling it is a way to bomb someone else's inbox.
	allowed, err := s.resendLimiter.Allow(ctx, "verify-resend:"+normalized)
	if err != nil {
		slog.ErrorContext(ctx, "resend limiter failed, allowing", slog.Any("err", err))
	} else if !allowed {
		return
	}

	user, err := s.store.UserByEmail(ctx, normalized)
	if err != nil || user.EmailVerified() {
		return
	}

	// Retire the earlier links so only the newest one works.
	if err := s.store.InvalidateEmailVerificationTokens(ctx, user.ID); err != nil {
		slog.ErrorContext(ctx, "failed to invalidate earlier verification tokens",
			slog.Any("err", err))
		return
	}

	if err := s.sendEmailVerification(ctx, user); err != nil {
		slog.ErrorContext(ctx, "failed to resend verification email", slog.Any("err", err))
	}
}

func (s *Service) sendEmailVerification(ctx context.Context, user User) error {
	plain, hash, err := newOpaqueToken()
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
