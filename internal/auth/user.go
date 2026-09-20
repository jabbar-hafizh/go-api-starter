package auth

import (
	"time"

	"github.com/google/uuid"
)

// User is an account. PasswordHash is nil for accounts that only sign in
// through an identity provider.
type User struct {
	ID              uuid.UUID
	Email           string
	EmailVerifiedAt *time.Time
	PasswordHash    *string
	CreatedAt       time.Time
}

// HasPassword reports whether this account can sign in with a password.
func (u User) HasPassword() bool { return u.PasswordHash != nil && *u.PasswordHash != "" }

// EmailVerified reports whether the address has been proven.
func (u User) EmailVerified() bool { return u.EmailVerifiedAt != nil }

// Identity links an account to an external provider. Empty until phase 4.
type Identity struct {
	ID       uuid.UUID
	Provider string
	Email    *string
}
