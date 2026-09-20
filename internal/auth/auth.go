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

	"github.com/jabbar-hafizh/go-api-starter/internal/ratelimit"
	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

const (
	purposeEmailVerify = "email_verify"
	// opaqueTokenBytes is the entropy in a verification link or refresh token.
	// 32 bytes is far past anything guessable and keeps a link short enough to
	// survive email clients that wrap lines.
	opaqueTokenBytes = 32
)

// store is declared here, by the code that uses it, and lists only the methods
// this package calls.
type store interface {
	CreateUser(ctx context.Context, id uuid.UUID, email string, passwordHash *string) (User, error)
	UserByEmail(ctx context.Context, email string) (User, error)
	UserByID(ctx context.Context, id uuid.UUID) (User, error)
	CreateVerificationToken(ctx context.Context, t VerificationToken) error
	ConsumeEmailVerification(ctx context.Context, tokenHash []byte) (uuid.UUID, error)
	CreateRefreshToken(ctx context.Context, t RefreshToken) error
	UseRefreshToken(ctx context.Context, tokenHash []byte) (RefreshTokenUse, error)
	RefreshTokenByHash(ctx context.Context, tokenHash []byte) (RefreshTokenStatus, error)
	RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error

	IdentityByProviderSubject(ctx context.Context, provider, subject string) (Identity, error)
	IdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]Identity, error)
	CreateIdentity(ctx context.Context, userID uuid.UUID, i Identity) (Identity, error)
	CreateUserWithIdentity(ctx context.Context, email string, i Identity) (User, error)
	DeleteIdentity(ctx context.Context, id, userID uuid.UUID) error
	CountAuthMethods(ctx context.Context, userID uuid.UUID) (int, error)
	EnabledProviders(ctx context.Context) ([]ProviderInfo, error)

	CreateOAuthState(ctx context.Context, st OAuthState) error
	ConsumeOAuthState(ctx context.Context, state string) (OAuthState, error)

	DeleteExpiredOAuthStates(ctx context.Context) error
	DeleteExpiredVerificationTokens(ctx context.Context) error
	DeleteExpiredRefreshTokens(ctx context.Context, graceDays int32) error
}

// ProviderInfo is what a client needs to render a sign-in button.
type ProviderInfo struct {
	Code        string
	DisplayName string
}

// OAuthState is the short-lived, single-use record tying a redirect to the
// callback that comes back.
type OAuthState struct {
	State        string
	Nonce        string
	CodeVerifier string
	Provider     string
	RedirectTo   *string
	ExpiresAt    time.Time
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

// Config carries the lifetimes this package needs. A struct rather than five
// positional arguments, so a caller cannot silently swap two durations.
type Config struct {
	EmailTokenTTL    time.Duration
	RefreshTTLWeb    time.Duration
	RefreshTTLMobile time.Duration
}

// Service holds the account use cases.
type Service struct {
	store            store
	issuer           token.Issuer
	mailer           Mailer
	emailTTL         time.Duration
	refreshTTLWeb    time.Duration
	refreshTTLMobile time.Duration
	providers        map[string]Provider
	loginLimiter     ratelimit.Limiter
	now              func() time.Time
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) ServiceOption {
	return func(s *Service) { s.now = now }
}

// WithLoginLimiter bounds sign-in attempts per email address.
func WithLoginLimiter(l ratelimit.Limiter) ServiceOption {
	return func(s *Service) { s.loginLimiter = l }
}

// WithProviders registers the identity providers this server can serve. One
// that is absent answers 501 rather than failing in some subtler way.
func WithProviders(providers ...Provider) ServiceOption {
	return func(s *Service) {
		for _, p := range providers {
			s.providers[p.Code()] = p
		}
	}
}

// NewService wires the account use cases.
func NewService(st store, issuer token.Issuer, mailer Mailer, cfg Config, opts ...ServiceOption) *Service {
	s := &Service{
		store:            st,
		issuer:           issuer,
		mailer:           mailer,
		emailTTL:         cfg.EmailTokenTTL,
		refreshTTLWeb:    cfg.RefreshTTLWeb,
		refreshTTLMobile: cfg.RefreshTTLMobile,
		providers:        map[string]Provider{},
		loginLimiter:     ratelimit.Allowed{},
		now:              time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// newOpaqueToken returns the plaintext to hand out and the hash to store. Used
// for both verification links and refresh tokens: same shape, same handling.
func newOpaqueToken() (plain string, hash []byte, err error) {
	raw := make([]byte, opaqueTokenBytes)
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

// RegisterProvider adds a provider after construction, for wiring that has to
// do network discovery before it can build one.
func (s *Service) RegisterProvider(p Provider) { s.providers[p.Code()] = p }
