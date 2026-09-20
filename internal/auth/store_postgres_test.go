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

func TestStoreRefreshTokenIsSpentOnce(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	user := mustCreateUser(t, store, "jabbar@example.com")
	family := uuid.Must(uuid.NewV7())
	hash := mustCreateRefresh(t, store, user.ID, family, time.Now().Add(time.Hour))

	use, err := store.UseRefreshToken(ctx, hash)
	require.NoError(t, err)
	require.Equal(t, user.ID, use.UserID)
	require.Equal(t, family, use.FamilyID)

	_, err = store.UseRefreshToken(ctx, hash)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)

	status, err := store.RefreshTokenByHash(ctx, hash)
	require.NoError(t, err)
	require.NotNil(t, status.UsedAt, "a spent token must be marked, that is how reuse is detected")
}

// Two requests arriving with the same token must not both succeed. A read then
// write would let both see it unused; the conditional UPDATE is what makes
// exactly one of them win.
func TestStoreConcurrentRefreshHasOneWinner(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	user := mustCreateUser(t, store, "jabbar@example.com")
	hash := mustCreateRefresh(t, store, user.ID, uuid.Must(uuid.NewV7()), time.Now().Add(time.Hour))

	const racers = 8
	results := make(chan error, racers)
	start := make(chan struct{})

	for range racers {
		go func() {
			<-start
			_, err := store.UseRefreshToken(ctx, hash)
			results <- err
		}()
	}
	close(start)

	won := 0
	for range racers {
		if err := <-results; err == nil {
			won++
		}
	}
	require.Equal(t, 1, won, "exactly one request may spend the token")
}

func TestStoreRevokeRefreshFamily(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	user := mustCreateUser(t, store, "jabbar@example.com")
	family := uuid.Must(uuid.NewV7())

	first := mustCreateRefresh(t, store, user.ID, family, time.Now().Add(time.Hour))
	second := mustCreateRefresh(t, store, user.ID, family, time.Now().Add(time.Hour))
	other := mustCreateRefresh(t, store, user.ID, uuid.Must(uuid.NewV7()), time.Now().Add(time.Hour))

	require.NoError(t, store.RevokeRefreshFamily(ctx, family))

	_, err := store.UseRefreshToken(ctx, first)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)
	_, err = store.UseRefreshToken(ctx, second)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)

	// A different chain belongs to a different session and is untouched.
	_, err = store.UseRefreshToken(ctx, other)
	require.NoError(t, err)
}

func TestStoreRefreshTokenExpiry(t *testing.T) {
	store := newStore(t)

	user := mustCreateUser(t, store, "jabbar@example.com")
	hash := mustCreateRefresh(t, store, user.ID, uuid.Must(uuid.NewV7()), time.Now().Add(-time.Second))

	_, err := store.UseRefreshToken(t.Context(), hash)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)
}

func TestStoreUnknownRefreshToken(t *testing.T) {
	store := newStore(t)

	sum := sha256.Sum256([]byte("never issued"))
	_, err := store.UseRefreshToken(t.Context(), sum[:])
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)

	_, err = store.RefreshTokenByHash(t.Context(), sum[:])
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)
}

func mustCreateRefresh(t *testing.T, store *auth.PostgresStore, userID, familyID uuid.UUID, expires time.Time) []byte {
	t.Helper()

	sum := sha256.Sum256([]byte(uuid.Must(uuid.NewV7()).String()))
	err := store.CreateRefreshToken(t.Context(), auth.RefreshToken{
		ID:        uuid.Must(uuid.NewV7()),
		UserID:    userID,
		TokenHash: sum[:],
		FamilyID:  familyID,
		Platform:  "web",
		ExpiresAt: expires,
	})
	require.NoError(t, err)
	return sum[:]
}

func TestStoreCreateUserWithIdentity(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	email := "sso@example.com"
	subject := "google-subject-1"

	user, err := store.CreateUserWithIdentity(ctx, email, auth.Identity{
		ID:       uuid.Must(uuid.NewV7()),
		Provider: "google",
		Subject:  subject,
		Email:    &email,
	})
	require.NoError(t, err)
	require.True(t, user.EmailVerified(), "the provider vouched for the address")
	require.False(t, user.HasPassword())

	// Both halves landed. A user without its identity would be an account
	// nobody can sign in to.
	identity, err := store.IdentityByProviderSubject(ctx, "google", subject)
	require.NoError(t, err)
	require.Equal(t, user.ID, identity.UserID)
}

// One provider account belongs to exactly one user, and the unique index is
// what decides it, so two requests racing to link cannot both win.
func TestStoreIdentityIsUniquePerProviderSubject(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	first := mustCreateUser(t, store, "one@example.com")
	second := mustCreateUser(t, store, "two@example.com")

	_, err := store.CreateIdentity(ctx, first.ID, auth.Identity{
		ID: uuid.Must(uuid.NewV7()), Provider: "google", Subject: "shared-subject",
	})
	require.NoError(t, err)

	_, err = store.CreateIdentity(ctx, second.ID, auth.Identity{
		ID: uuid.Must(uuid.NewV7()), Provider: "google", Subject: "shared-subject",
	})
	require.ErrorIs(t, err, auth.ErrIdentityAlreadyLinked)
}

// CountAuthMethods is what the last-method guard rests on, so the SQL has to
// be right across every combination.
func TestStoreCountAuthMethods(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	withPassword := mustCreateUser(t, store, "password@example.com")
	count, err := store.CountAuthMethods(ctx, withPassword.ID)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	_, err = store.CreateIdentity(ctx, withPassword.ID, auth.Identity{
		ID: uuid.Must(uuid.NewV7()), Provider: "google", Subject: "sub-both",
	})
	require.NoError(t, err)

	count, err = store.CountAuthMethods(ctx, withPassword.ID)
	require.NoError(t, err)
	require.Equal(t, 2, count, "password plus one identity")

	email := "ssoonly@example.com"
	ssoOnly, err := store.CreateUserWithIdentity(ctx, email, auth.Identity{
		ID: uuid.Must(uuid.NewV7()), Provider: "google", Subject: "sub-sso", Email: &email,
	})
	require.NoError(t, err)

	count, err = store.CountAuthMethods(ctx, ssoOnly.ID)
	require.NoError(t, err)
	require.Equal(t, 1, count, "an SSO-only account has exactly one way in")
}

func TestStoreDeleteIdentityIsScopedToItsOwner(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	owner := mustCreateUser(t, store, "owner@example.com")
	stranger := mustCreateUser(t, store, "stranger@example.com")

	identity, err := store.CreateIdentity(ctx, owner.ID, auth.Identity{
		ID: uuid.Must(uuid.NewV7()), Provider: "google", Subject: "sub-owned",
	})
	require.NoError(t, err)

	// Scoped by user id, so asking for someone else's identity looks exactly
	// like asking for one that does not exist.
	require.ErrorIs(t, store.DeleteIdentity(ctx, identity.ID, stranger.ID), auth.ErrIdentityNotFound)
	require.NoError(t, store.DeleteIdentity(ctx, identity.ID, owner.ID))
	require.ErrorIs(t, store.DeleteIdentity(ctx, identity.ID, owner.ID), auth.ErrIdentityNotFound)
}

func TestStoreOAuthStateIsSingleUse(t *testing.T) {
	store := newStore(t)
	ctx := t.Context()

	redirect := "/dashboard"
	st := auth.OAuthState{
		State:        "state-value",
		Nonce:        "nonce-value",
		CodeVerifier: "verifier-value",
		Provider:     "google",
		RedirectTo:   &redirect,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}
	require.NoError(t, store.CreateOAuthState(ctx, st))

	got, err := store.ConsumeOAuthState(ctx, st.State)
	require.NoError(t, err)
	require.Equal(t, st.Nonce, got.Nonce)
	require.Equal(t, st.CodeVerifier, got.CodeVerifier)
	require.Equal(t, "/dashboard", *got.RedirectTo)

	// Reading deleted it, which is what stops a captured callback URL from
	// being replayed.
	_, err = store.ConsumeOAuthState(ctx, st.State)
	require.ErrorIs(t, err, auth.ErrOAuthStateInvalid)
}

func TestStoreOAuthStateExpires(t *testing.T) {
	store := newStore(t)

	st := auth.OAuthState{
		State: "old-state", Nonce: "n", CodeVerifier: "v",
		Provider: "google", ExpiresAt: time.Now().Add(-time.Second),
	}
	require.NoError(t, store.CreateOAuthState(t.Context(), st))

	_, err := store.ConsumeOAuthState(t.Context(), st.State)
	require.ErrorIs(t, err, auth.ErrOAuthStateInvalid)
}

func TestStoreEnabledProviders(t *testing.T) {
	store := newStore(t)

	providers, err := store.EnabledProviders(t.Context())
	require.NoError(t, err)
	require.Len(t, providers, 1, "the migration seeds google")
	require.Equal(t, "google", providers[0].Code)
	require.Equal(t, "Google", providers[0].DisplayName)
}
