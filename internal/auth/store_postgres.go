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
