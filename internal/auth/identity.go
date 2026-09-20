package auth

import (
	"context"

	"github.com/google/uuid"
)

// Providers lists what the client can offer as sign-in buttons.
func (s *Service) Providers(ctx context.Context) ([]ProviderInfo, error) {
	all, err := s.store.EnabledProviders(ctx)
	if err != nil {
		return nil, err
	}

	// A provider enabled in the database but not configured on this server
	// would render a button that cannot work.
	usable := make([]ProviderInfo, 0, len(all))
	for _, p := range all {
		if _, ok := s.providers[p.Code]; ok {
			usable = append(usable, p)
		}
	}
	return usable, nil
}

// LinkProviderToken attaches a provider account to the signed-in user.
//
// Linking while authenticated needs no email checks: the person has already
// proved they own this account, and the unique index on (provider, subject)
// stops the provider account being attached to two users.
func (s *Service) LinkProviderToken(ctx context.Context, userID uuid.UUID, providerCode, rawIDToken string) (Identity, error) {
	claims, err := s.verifyProviderToken(ctx, providerCode, rawIDToken)
	if err != nil {
		return Identity{}, err
	}
	if !claims.EmailVerified {
		return Identity{}, ErrProviderEmailUnverified
	}

	return s.store.CreateIdentity(ctx, userID, Identity{
		ID:       uuid.Must(uuid.NewV7()),
		Provider: providerCode,
		Subject:  claims.Subject,
		Email:    &claims.Email,
	})
}

// UnlinkIdentity removes a provider from the account, unless it is the only
// way in.
//
// Without this guard, someone who signed up with Google and never set a
// password could unlink it and lose the account permanently.
func (s *Service) UnlinkIdentity(ctx context.Context, userID, identityID uuid.UUID) error {
	methods, err := s.store.CountAuthMethods(ctx, userID)
	if err != nil {
		return err
	}
	if methods <= 1 {
		return ErrLastAuthMethod
	}
	return s.store.DeleteIdentity(ctx, identityID, userID)
}
