package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jabbar-hafizh/go-api-starter/internal/db/gen"
)

// uniqueViolation is the SQLSTATE for a duplicate key.
const uniqueViolation = "23505"

// PostgresStore is the only place database errors become domain errors.
// pgx.ErrNoRows never escapes it.
type PostgresStore struct {
	q *gen.Queries
}

// NewPostgresStore returns a store backed by the given pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{q: gen.New(pool)}
}

func (s *PostgresStore) CreateUser(ctx context.Context, id uuid.UUID, email string, passwordHash *string) (User, error) {
	row, err := s.q.CreateUser(ctx, gen.CreateUserParams{
		ID:           id,
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		// The unique index is what actually decides this, not a prior SELECT,
		// so two simultaneous registrations cannot both succeed.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return toUser(row), nil
}

func (s *PostgresStore) UserByEmail(ctx context.Context, email string) (User, error) {
	row, err := s.q.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("user by email: %w", err)
	}
	return toUser(gen.User(row)), nil
}

func (s *PostgresStore) UserByID(ctx context.Context, id uuid.UUID) (User, error) {
	row, err := s.q.UserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("user by id: %w", err)
	}
	return toUser(gen.User(row)), nil
}

func (s *PostgresStore) CreateVerificationToken(ctx context.Context, t VerificationToken) error {
	err := s.q.CreateVerificationToken(ctx, gen.CreateVerificationTokenParams{
		ID:        t.ID,
		UserID:    t.UserID,
		Purpose:   t.Purpose,
		TokenHash: t.TokenHash,
		ExpiresAt: t.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("create verification token: %w", err)
	}
	return nil
}

func (s *PostgresStore) ConsumeEmailVerification(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	id, err := s.q.ConsumeEmailVerification(ctx, tokenHash)
	if err != nil {
		// No row means unknown, expired or already used. The query cannot tell
		// them apart and neither should the caller.
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrTokenNotUsable
		}
		return uuid.Nil, fmt.Errorf("consume email verification: %w", err)
	}
	return id, nil
}

func toUser(row gen.User) User {
	return User{
		ID:              row.ID,
		Email:           row.Email,
		EmailVerifiedAt: row.EmailVerifiedAt,
		PasswordHash:    row.PasswordHash,
		CreatedAt:       row.CreatedAt,
	}
}

func (s *PostgresStore) CreateRefreshToken(ctx context.Context, t RefreshToken) error {
	var platform *string
	if t.Platform != "" {
		platform = &t.Platform
	}

	err := s.q.CreateRefreshToken(ctx, gen.CreateRefreshTokenParams{
		ID:             t.ID,
		UserID:         t.UserID,
		TokenHash:      t.TokenHash,
		FamilyID:       t.FamilyID,
		ClientPlatform: platform,
		ExpiresAt:      t.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func (s *PostgresStore) UseRefreshToken(ctx context.Context, tokenHash []byte) (RefreshTokenUse, error) {
	row, err := s.q.UseRefreshToken(ctx, tokenHash)
	if err != nil {
		// No row means unknown, expired, revoked or already spent. Which one
		// it was is decided by the caller reading the row separately.
		if errors.Is(err, pgx.ErrNoRows) {
			return RefreshTokenUse{}, ErrRefreshInvalid
		}
		return RefreshTokenUse{}, fmt.Errorf("use refresh token: %w", err)
	}
	return RefreshTokenUse{UserID: row.UserID, FamilyID: row.FamilyID}, nil
}

func (s *PostgresStore) RefreshTokenByHash(ctx context.Context, tokenHash []byte) (RefreshTokenStatus, error) {
	row, err := s.q.RefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RefreshTokenStatus{}, ErrRefreshInvalid
		}
		return RefreshTokenStatus{}, fmt.Errorf("refresh token by hash: %w", err)
	}
	return RefreshTokenStatus{FamilyID: row.FamilyID, UsedAt: row.UsedAt}, nil
}

func (s *PostgresStore) RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error {
	if err := s.q.RevokeRefreshFamily(ctx, familyID); err != nil {
		return fmt.Errorf("revoke refresh family: %w", err)
	}
	return nil
}

func (s *PostgresStore) IdentityByProviderSubject(ctx context.Context, provider, subject string) (Identity, error) {
	row, err := s.q.IdentityByProviderSubject(ctx, gen.IdentityByProviderSubjectParams{
		Provider:       provider,
		ProviderUserID: subject,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Identity{}, ErrIdentityNotFound
		}
		return Identity{}, fmt.Errorf("identity by provider subject: %w", err)
	}
	return toIdentity(gen.AuthIdentity{
		ID: row.ID, UserID: row.UserID, Provider: row.Provider,
		ProviderUserID: row.ProviderUserID, Email: row.Email,
	}), nil
}

func (s *PostgresStore) IdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]Identity, error) {
	rows, err := s.q.IdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("identities by user: %w", err)
	}

	out := make([]Identity, 0, len(rows))
	for _, row := range rows {
		out = append(out, toIdentity(gen.AuthIdentity{
			ID: row.ID, UserID: row.UserID, Provider: row.Provider,
			ProviderUserID: row.ProviderUserID, Email: row.Email,
		}))
	}
	return out, nil
}

func (s *PostgresStore) CreateIdentity(ctx context.Context, userID uuid.UUID, i Identity) (Identity, error) {
	row, err := s.q.CreateIdentity(ctx, gen.CreateIdentityParams{
		ID:             i.ID,
		UserID:         userID,
		Provider:       i.Provider,
		ProviderUserID: i.Subject,
		Email:          i.Email,
	})
	if err != nil {
		// The unique index on (provider, provider_user_id) is what decides
		// this, so two requests racing to link the same provider account
		// cannot both win.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return Identity{}, ErrIdentityAlreadyLinked
		}
		return Identity{}, fmt.Errorf("create identity: %w", err)
	}
	return toIdentity(gen.AuthIdentity{
		ID: row.ID, UserID: row.UserID, Provider: row.Provider,
		ProviderUserID: row.ProviderUserID, Email: row.Email,
	}), nil
}

func (s *PostgresStore) CreateUserWithIdentity(ctx context.Context, email string, i Identity) (User, error) {
	row, err := s.q.CreateUserWithIdentity(ctx, gen.CreateUserWithIdentityParams{
		ID:             uuid.Must(uuid.NewV7()),
		Email:          email,
		ID_2:           i.ID,
		Provider:       i.Provider,
		ProviderUserID: i.Subject,
		Email_2:        i.Email,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("create user with identity: %w", err)
	}
	return toUser(gen.User(row)), nil
}

func (s *PostgresStore) DeleteIdentity(ctx context.Context, id, userID uuid.UUID) error {
	if _, err := s.q.DeleteIdentity(ctx, gen.DeleteIdentityParams{ID: id, UserID: userID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Scoped by user id, so asking for someone else's identity is
			// indistinguishable from asking for one that does not exist.
			return ErrIdentityNotFound
		}
		return fmt.Errorf("delete identity: %w", err)
	}
	return nil
}

func (s *PostgresStore) CountAuthMethods(ctx context.Context, userID uuid.UUID) (int, error) {
	count, err := s.q.CountAuthMethods(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("count auth methods: %w", err)
	}
	return int(count), nil
}

func (s *PostgresStore) EnabledProviders(ctx context.Context) ([]ProviderInfo, error) {
	rows, err := s.q.EnabledProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("enabled providers: %w", err)
	}

	out := make([]ProviderInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, ProviderInfo{Code: row.Code, DisplayName: row.DisplayName})
	}
	return out, nil
}

func (s *PostgresStore) CreateOAuthState(ctx context.Context, st OAuthState) error {
	err := s.q.CreateOAuthState(ctx, gen.CreateOAuthStateParams{
		State:        st.State,
		Nonce:        st.Nonce,
		CodeVerifier: st.CodeVerifier,
		Provider:     st.Provider,
		RedirectTo:   st.RedirectTo,
		ExpiresAt:    st.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("create oauth state: %w", err)
	}
	return nil
}

func (s *PostgresStore) ConsumeOAuthState(ctx context.Context, state string) (OAuthState, error) {
	row, err := s.q.ConsumeOAuthState(ctx, state)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OAuthState{}, ErrOAuthStateInvalid
		}
		return OAuthState{}, fmt.Errorf("consume oauth state: %w", err)
	}
	return OAuthState{
		State:        state,
		Nonce:        row.Nonce,
		CodeVerifier: row.CodeVerifier,
		Provider:     row.Provider,
		RedirectTo:   row.RedirectTo,
	}, nil
}

func toIdentity(row gen.AuthIdentity) Identity {
	return Identity{
		ID:       row.ID,
		UserID:   row.UserID,
		Provider: row.Provider,
		Subject:  row.ProviderUserID,
		Email:    row.Email,
	}
}

func (s *PostgresStore) DeleteExpiredOAuthStates(ctx context.Context) error {
	if err := s.q.DeleteExpiredOAuthStates(ctx); err != nil {
		return fmt.Errorf("delete expired oauth states: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteExpiredVerificationTokens(ctx context.Context) error {
	if err := s.q.DeleteExpiredVerificationTokens(ctx); err != nil {
		return fmt.Errorf("delete expired verification tokens: %w", err)
	}
	return nil
}

func (s *PostgresStore) DeleteExpiredRefreshTokens(ctx context.Context, graceDays int32) error {
	if err := s.q.DeleteExpiredRefreshTokens(ctx, graceDays); err != nil {
		return fmt.Errorf("delete expired refresh tokens: %w", err)
	}
	return nil
}

func (s *PostgresStore) InvalidateEmailVerificationTokens(ctx context.Context, userID uuid.UUID) error {
	if err := s.q.InvalidateEmailVerificationTokens(ctx, userID); err != nil {
		return fmt.Errorf("invalidate email verification tokens: %w", err)
	}
	return nil
}
