package auth_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
	"github.com/jabbar-hafizh/go-api-starter/internal/config"
	"github.com/jabbar-hafizh/go-api-starter/internal/db"
)

// These run against a real Postgres. Mocking SQL only tests the mock: a typo in
// a column name, a constraint that does not fire, or a CTE that is not actually
// atomic all survive a fake store and none of them survive this.
func newStore(t *testing.T) *auth.PostgresStore {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}

	ctx := t.Context()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("app"),
		tcpostgres.WithUsername("app"),
		tcpostgres.WithPassword("app"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("5432/tcp").WithStartupTimeout(60*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	pool, err := db.Connect(ctx, config.Postgres{DSN: dsn, MaxConns: 4, MinConns: 1})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, db.Migrate(ctx, pool))
	return auth.NewPostgresStore(pool)
}

func TestStoreCreateAndReadUser(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	hash := "$argon2id$fake"
	id := uuid.Must(uuid.NewV7())

	created, err := store.CreateUser(ctx, id, "jabbar@example.com", &hash)
	require.NoError(t, err)
	require.Equal(t, id, created.ID)
	require.Nil(t, created.EmailVerifiedAt)
	require.False(t, created.CreatedAt.IsZero())

	byEmail, err := store.UserByEmail(ctx, "jabbar@example.com")
	require.NoError(t, err)
	require.Equal(t, id, byEmail.ID)

	byID, err := store.UserByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "jabbar@example.com", byID.Email)
}

// The citext column is what enforces this, not the application, so two
// concurrent registrations differing only in case cannot both win.
func TestStoreEmailIsCaseInsensitivelyUnique(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	_, err := store.CreateUser(ctx, uuid.Must(uuid.NewV7()), "jabbar@example.com", nil)
	require.NoError(t, err)

	_, err = store.CreateUser(ctx, uuid.Must(uuid.NewV7()), "JABBAR@example.com", nil)
	require.ErrorIs(t, err, auth.ErrEmailTaken)
}

func TestStoreMissingUser(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	_, err := store.UserByEmail(ctx, "nobody@example.com")
	require.ErrorIs(t, err, auth.ErrUserNotFound)

	_, err = store.UserByID(ctx, uuid.Must(uuid.NewV7()))
	require.ErrorIs(t, err, auth.ErrUserNotFound)
}

func TestStoreConsumeEmailVerification(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	user := mustCreateUser(t, store, "jabbar@example.com")
	hash := mustCreateToken(t, store, user.ID, time.Now().Add(time.Hour))

	gotID, err := store.ConsumeEmailVerification(ctx, hash)
	require.NoError(t, err)
	require.Equal(t, user.ID, gotID)

	// One statement did both halves, so the user is verified as a consequence
	// of the token being burned, never separately.
	verified, err := store.UserByID(ctx, user.ID)
	require.NoError(t, err)
	require.True(t, verified.EmailVerified())

	_, err = store.ConsumeEmailVerification(ctx, hash)
	require.ErrorIs(t, err, auth.ErrTokenNotUsable, "a token must be single use")
}

func TestStoreRejectsUnusableTokens(t *testing.T) {
	store := newStore(t)
	user := mustCreateUser(t, store, "jabbar@example.com")

	t.Run("expired", func(t *testing.T) {
		hash := mustCreateToken(t, store, user.ID, time.Now().Add(-time.Second))
		_, err := store.ConsumeEmailVerification(t.Context(), hash)
		require.ErrorIs(t, err, auth.ErrTokenNotUsable)
	})

	t.Run("unknown", func(t *testing.T) {
		sum := sha256.Sum256([]byte("never issued"))
		_, err := store.ConsumeEmailVerification(t.Context(), sum[:])
		require.ErrorIs(t, err, auth.ErrTokenNotUsable)
	})
}

func mustCreateUser(t *testing.T, store *auth.PostgresStore, email string) auth.User {
	t.Helper()

	hash := "$argon2id$fake"
	user, err := store.CreateUser(t.Context(), uuid.Must(uuid.NewV7()), email, &hash)
	require.NoError(t, err)
	return user
}

func mustCreateToken(t *testing.T, store *auth.PostgresStore, userID uuid.UUID, expires time.Time) []byte {
	t.Helper()

	sum := sha256.Sum256([]byte(uuid.Must(uuid.NewV7()).String()))
	err := store.CreateVerificationToken(t.Context(), auth.VerificationToken{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    userID,
		Purpose:   "email_verify",
		TokenHash: sum[:],
		ExpiresAt: expires,
	})
	require.NoError(t, err)
	return sum[:]
}
