package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

// Platform is the kind of client asking. It decides the refresh lifetime and
// how the refresh token is delivered.
type Platform string

// Known platforms. An unrecognised value is treated as a native client, which
// is the safer default: it never puts a token in a cookie.
const (
	PlatformWeb     Platform = "web"
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
)

// IsWeb reports whether the refresh token belongs in an httpOnly cookie.
func (p Platform) IsWeb() bool { return p == PlatformWeb }

// Session is everything a client needs after authenticating. RefreshToken is
// the only place the plaintext exists: the database only ever holds its hash.
type Session struct {
	Access       token.Access
	RefreshToken string
	RefreshTTL   time.Duration
}

// RefreshToken is a stored rotation-chain member.
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	FamilyID  uuid.UUID
	Platform  string
	ExpiresAt time.Time
}

// RefreshTokenUse is what spending a token returns.
type RefreshTokenUse struct {
	UserID   uuid.UUID
	FamilyID uuid.UUID
}

// RefreshTokenStatus is read only after a spend failed, to tell a replayed
// token apart from one that merely expired.
type RefreshTokenStatus struct {
	FamilyID uuid.UUID
	UsedAt   *time.Time
}

func (s *Service) refreshTTL(p Platform) time.Duration {
	if p.IsWeb() {
		return s.refreshTTLWeb
	}
	return s.refreshTTLMobile
}

// startSession mints an access token and the first refresh token of a new
// rotation chain.
func (s *Service) startSession(ctx context.Context, userID uuid.UUID, p Platform) (Session, error) {
	return s.issueSession(ctx, userID, uuid.Must(uuid.NewV7()), p)
}

// issueSession mints a pair inside an existing chain, which is what makes
// rotation a chain rather than a set of unrelated tokens.
func (s *Service) issueSession(ctx context.Context, userID, familyID uuid.UUID, p Platform) (Session, error) {
	access, err := s.issuer.Issue(userID)
	if err != nil {
		return Session{}, fmt.Errorf("issue access token: %w", err)
	}

	plain, hash, err := newOpaqueToken()
	if err != nil {
		return Session{}, err
	}

	ttl := s.refreshTTL(p)
	err = s.store.CreateRefreshToken(ctx, RefreshToken{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    userID,
		TokenHash: hash,
		FamilyID:  familyID,
		Platform:  string(p),
		ExpiresAt: s.now().Add(ttl),
	})
	if err != nil {
		return Session{}, err
	}

	return Session{Access: access, RefreshToken: plain, RefreshTTL: ttl}, nil
}

// Refresh spends the presented token and issues a new pair in the same chain.
func (s *Service) Refresh(ctx context.Context, plain string, p Platform) (Session, error) {
	if plain == "" {
		return Session{}, ErrRefreshInvalid
	}
	hash := hashToken(plain)

	use, err := s.store.UseRefreshToken(ctx, hash)
	if err == nil {
		return s.issueSession(ctx, use.UserID, use.FamilyID, p)
	}
	if !errors.Is(err, ErrRefreshInvalid) {
		return Session{}, err
	}

	s.handleUnusableRefresh(ctx, hash)
	return Session{}, ErrRefreshInvalid
}

// handleUnusableRefresh revokes the whole chain when a spent token comes back.
// Two parties holding the same token is the signal, and the only safe response
// is to end the session rather than guess which one is the owner.
func (s *Service) handleUnusableRefresh(ctx context.Context, hash []byte) {
	status, err := s.store.RefreshTokenByHash(ctx, hash)
	if err != nil {
		return
	}
	if status.UsedAt == nil {
		return
	}

	slog.WarnContext(ctx, "refresh token reuse detected, revoking the family",
		slog.String("family_id", status.FamilyID.String()),
	)
	if err := s.store.RevokeRefreshFamily(ctx, status.FamilyID); err != nil {
		slog.ErrorContext(ctx, "failed to revoke refresh family",
			slog.String("family_id", status.FamilyID.String()),
			slog.Any("err", err),
		)
	}
}

// Logout revokes the whole chain, so a copy taken earlier in it is dead too.
// It never reports failure: a client asking to leave must not be told it is
// still signed in.
func (s *Service) Logout(ctx context.Context, plain string) {
	if plain == "" {
		return
	}

	status, err := s.store.RefreshTokenByHash(ctx, hashToken(plain))
	if err != nil {
		return
	}
	if err := s.store.RevokeRefreshFamily(ctx, status.FamilyID); err != nil {
		slog.ErrorContext(ctx, "failed to revoke refresh family on logout",
			slog.String("family_id", status.FamilyID.String()),
			slog.Any("err", err),
		)
	}
}
