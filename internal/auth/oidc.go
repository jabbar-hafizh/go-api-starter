package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ProviderClaims is what a provider reports about a person, already reduced to
// the three things this package cares about.
type ProviderClaims struct {
	// Subject is the provider's stable identity, already mapped by the
	// provider. It is not always the sub claim: Microsoft's sub is unique per
	// user and application, so there the stable value is tid + oid.
	Subject       string
	Email         string
	EmailVerified bool
}

// Provider is everything an identity provider must supply. Adding Microsoft or
// Apple means a new file implementing this, not a change to the flow below.
type Provider interface {
	Code() string
	// AuthCodeURL builds the redirect that starts the browser flow.
	AuthCodeURL(state, nonce, codeVerifier string) string
	// Exchange swaps an authorization code for verified claims.
	Exchange(ctx context.Context, code, codeVerifier, nonce string) (ProviderClaims, error)
	// VerifyIDToken checks a token a native client obtained from the provider
	// SDK directly.
	VerifyIDToken(ctx context.Context, rawIDToken string) (ProviderClaims, error)
}

// Identity links an account to an external provider.
type Identity struct {
	ID       uuid.UUID
	UserID   uuid.UUID
	Provider string
	Subject  string
	Email    *string
}

// signInWithProvider turns verified provider claims into a session, applying
// the linking policy. It is provider agnostic on purpose: every provider goes
// through exactly these rules.
func (s *Service) signInWithProvider(ctx context.Context, provider string, c ProviderClaims, p Platform) (Session, error) {
	// An unverified address proves nothing. Accepting it would let anyone with
	// a provider account claim any email they can type.
	if !c.EmailVerified {
		return Session{}, ErrProviderEmailUnverified
	}
	if c.Subject == "" || c.Email == "" {
		return Session{}, ErrProviderClaimsIncomplete
	}
	email := normalizeEmail(c.Email)

	// Known identity: just sign in.
	identity, err := s.store.IdentityByProviderSubject(ctx, provider, c.Subject)
	if err == nil {
		return s.startSession(ctx, identity.UserID, p)
	}
	if !errors.Is(err, ErrIdentityNotFound) {
		return Session{}, err
	}

	user, err := s.store.UserByEmail(ctx, email)
	switch {
	case errors.Is(err, ErrUserNotFound):
		// Nobody owns this address yet. Create the account and its identity
		// together, already verified because the provider vouched for it.
		user, err = s.store.CreateUserWithIdentity(ctx, email, Identity{
			ID:       uuid.Must(uuid.NewV7()),
			Provider: provider,
			Subject:  c.Subject,
			Email:    &c.Email,
		})
		if err != nil {
			return Session{}, err
		}
		return s.startSession(ctx, user.ID, p)

	case err != nil:
		return Session{}, err
	}

	// The address is already registered under a different login method.
	//
	// Linking automatically is only safe when the local address was proven.
	// Otherwise an attacker registers with someone else's address, waits for
	// them to sign in with the provider, and inherits the account they made.
	// That is why email verification is a prerequisite for this, not a nicety.
	if !user.EmailVerified() {
		return Session{}, ErrLinkNeedsVerifiedEmail
	}

	if _, err := s.store.CreateIdentity(ctx, user.ID, Identity{
		ID:       uuid.Must(uuid.NewV7()),
		Provider: provider,
		Subject:  c.Subject,
		Email:    &c.Email,
	}); err != nil {
		return Session{}, err
	}
	return s.startSession(ctx, user.ID, p)
}
