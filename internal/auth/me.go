package auth

import (
	"context"

	"github.com/google/uuid"
)

// Account is a user plus the ways they can sign in. Clients need the second
// part to decide between "Set password" and "Change password", and when to
// disable unlinking.
type Account struct {
	User        User
	HasPassword bool
	Identities  []Identity
}

// Account returns the signed-in user.
func (s *Service) Account(ctx context.Context, userID uuid.UUID) (Account, error) {
	user, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return Account{}, err
	}

	identities, err := s.store.IdentitiesByUser(ctx, userID)
	if err != nil {
		return Account{}, err
	}

	return Account{
		User:        user,
		HasPassword: user.HasPassword(),
		Identities:  identities,
	}, nil
}
