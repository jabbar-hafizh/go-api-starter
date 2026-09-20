// Package auth owns accounts and how people prove they own one: passwords
// today, identity providers from phase 4.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

const (
	purposeEmailVerify = "email_verify"
	// verificationTokenBytes is the entropy in a link token. 32 bytes is far
	// past anything guessable and keeps the URL short enough to survive email
	// clients that wrap lines.
	verificationTokenBytes = 32
)

// store is declared here, by the code that uses it, and lists only the methods
// this package calls.
type store interface {
	CreateUser(ctx context.Context, id uuid.UUID, email string, passwordHash *string) (User, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	UserByID(ctx context.Context, id uuid.UUID) (User, error)
	CreateVerificationToken(ctx context.Context, t VerificationToken) error
	ConsumeEmailVerification(ctx context.Context, tokenHash []byte) (uuid.UUID, error)
}

// Mailer delivers the transactional emails this package sends.
type Mailer interface {
	SendEmailVerification(ctx context.Context, email, token string) error
}

// VerificationToken is stored hashed. The plaintext only ever exists in the
// email.
type VerificationToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Purpose   string
	TokenHash []byte
	ExpiresAt time.Time
}

// Service holds the account use cases.
type Service struct {
	store    store
	issuer   token.Issuer
	mailer   Mailer
	emailTTL time.Duration
	now      func() time.Time
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) ServiceOption {
	return func(s *Service) { s.now = now }
}

// NewService wires the account use cases.
func NewService(st store, issuer token.Issuer, mailer Mailer, emailTTL time.Duration, opts ...ServiceOption) *Service {
	s := &Service{store: st, issuer: issuer, mailer: mailer, emailTTL: emailTTL, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// newVerificationToken returns the plaintext to email and the hash to store.
func newVerificationToken() (plain string, hash []byte, err error) {
	raw := make([]byte, verificationTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("read random: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(raw)
	return plain, hashToken(plain), nil
}

// hashToken is a plain SHA-256, not a password hash. The input already has 256
// bits of entropy, so there is nothing to slow an attacker down about.
func hashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}
