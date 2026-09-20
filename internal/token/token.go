// Package token issues and verifies access tokens. It knows nothing about
// auth, so middleware can verify a token without pulling in the auth package.
package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ErrInvalid covers every rejection reason. Callers get one answer because the
// difference between expired, tampered and malformed is not the client's
// business.
var ErrInvalid = errors.New("invalid token")

const (
	algHS256 = "HS256"
	// typeAccess separates access tokens from anything else signed with the
	// same key later, so one cannot be replayed as the other.
	typeAccess = "access"
)

// Claims is what a verified token carries. Deliberately small: a JWT cannot be
// revoked, so every claim is stale data until it expires.
type Claims struct {
	UserID uuid.UUID
	ID     string
}

// Access is a freshly issued token and how long it lives.
type Access struct {
	Value     string
	ExpiresIn time.Duration
}

// Issuer mints access tokens.
type Issuer interface {
	Issue(userID uuid.UUID) (Access, error)
}

// Verifier checks them.
type Verifier interface {
	Verify(raw string) (Claims, error)
}

type jwtClaims struct {
	jwt.RegisteredClaims
	Type string `json:"typ"`
}

// HS256 signs with a shared secret. Right enough while one service issues and
// verifies; the moment a second service must verify, swap this for RS256 and
// nothing outside this package changes.
type HS256 struct {
	secret []byte
	keyID  string
	ttl    time.Duration
	now    func() time.Time
}

// Option configures an HS256 issuer.
type Option func(*HS256)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(h *HS256) { h.now = now }
}

// NewHS256 returns an issuer and verifier backed by a shared secret.
func NewHS256(secret []byte, keyID string, ttl time.Duration, opts ...Option) *HS256 {
	h := &HS256{secret: secret, keyID: keyID, ttl: ttl, now: time.Now}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *HS256) Issue(userID uuid.UUID) (Access, error) {
	now := h.now()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ID:        uuid.Must(uuid.NewV7()).String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(h.ttl)),
		},
		Type: typeAccess,
	})
	// kid is set from the very first token so a future key or algorithm change
	// only needs a short dual-verification window.
	tok.Header["kid"] = h.keyID

	signed, err := tok.SignedString(h.secret)
	if err != nil {
		return Access{}, fmt.Errorf("sign token: %w", err)
	}
	return Access{Value: signed, ExpiresIn: h.ttl}, nil
}

func (h *HS256) Verify(raw string) (Claims, error) {
	var c jwtClaims
	_, err := jwt.ParseWithClaims(raw, &c, h.keyFunc,
		// Pinning the algorithm is what closes the "alg: none" and
		// "RS256 public key used as an HMAC secret" attacks.
		jwt.WithValidMethods([]string{algHS256}),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(h.now),
	)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	if c.Type != typeAccess {
		return Claims{}, ErrInvalid
	}

	userID, err := uuid.Parse(c.Subject)
	if err != nil {
		return Claims{}, ErrInvalid
	}
	return Claims{UserID: userID, ID: c.ID}, nil
}

func (h *HS256) keyFunc(tok *jwt.Token) (any, error) {
	kid, _ := tok.Header["kid"].(string)
	if kid != h.keyID {
		return nil, ErrInvalid
	}
	return h.secret, nil
}
