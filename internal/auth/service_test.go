package auth_test

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

const goodPassword = "correct-horse-battery-staple"

func TestRegister(t *testing.T) {
	t.Parallel()

	svc, store, mail := newService(t)

	user, err := svc.Register(context.Background(), "Jabbar@Example.COM ", goodPassword)
	require.NoError(t, err)

	// The address is normalised before it is stored, so the same person cannot
	// register twice by changing the case.
	require.Equal(t, "jabbar@example.com", user.Email)
	require.False(t, user.EmailVerified(), "registration must not verify the address by itself")
	require.True(t, user.HasPassword())
	require.NotEmpty(t, mail.lastToken, "a verification email must be sent")
	require.Len(t, store.tokens, 1)
}

func TestRegisterRejectsDuplicateEmail(t *testing.T) {
	t.Parallel()

	svc, _, _ := newService(t)
	ctx := context.Background()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)

	_, err = svc.Register(ctx, "jabbar@example.com", "a different long password")
	require.ErrorIs(t, err, auth.ErrEmailTaken)
}

func TestRegisterValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		email      string
		password   string
		wantFields []string
	}{
		{"empty email", "", goodPassword, []string{"email"}},
		{"malformed email", "not-an-email", goodPassword, []string{"email"}},
		{"long email", strings.Repeat("a", 250) + "@example.com", goodPassword, []string{"email"}},
		{"short password", "jabbar@example.com", "short", []string{"password"}},
		{"empty password", "jabbar@example.com", "", []string{"password"}},
		{"both wrong", "nope", "short", []string{"email", "password"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, _, _ := newService(t)
			_, err := svc.Register(context.Background(), tt.email, tt.password)
			require.Error(t, err)

			var ve *auth.ValidationError
			require.ErrorAs(t, err, &ve)

			got := make([]string, 0, len(ve.Details()))
			for _, d := range ve.Details() {
				got = append(got, d.Field)
			}
			require.Equal(t, tt.wantFields, got)
		})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	svc, store, mail := newService(t)
	ctx := context.Background()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)

	// Unverified accounts are refused, and only after the password checks out
	// so this cannot be used to probe which addresses exist.
	_, err = svc.Login(ctx, "jabbar@example.com", goodPassword, auth.PlatformWeb)
	require.ErrorIs(t, err, auth.ErrEmailNotVerified)

	require.NoError(t, svc.VerifyEmail(ctx, mail.lastToken))

	session, err := svc.Login(ctx, "jabbar@example.com", goodPassword, auth.PlatformWeb)
	require.NoError(t, err)
	require.NotEmpty(t, session.Access.Value)
	require.Equal(t, 15*time.Minute, session.Access.ExpiresIn)
	require.NotEmpty(t, session.RefreshToken)
	require.Equal(t, 7*24*time.Hour, session.RefreshTTL)

	claims, err := store.verifier.Verify(session.Access.Value)
	require.NoError(t, err)
	require.Equal(t, store.byEmail["jabbar@example.com"].ID, claims.UserID)
}

// An unknown email, a wrong password and an SSO-only account must be
// indistinguishable, otherwise login becomes a user enumeration oracle.
func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	t.Parallel()

	svc, store, mail := newService(t)
	ctx := context.Background()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)
	require.NoError(t, svc.VerifyEmail(ctx, mail.lastToken))

	store.addSSOOnly("google-user@example.com")

	tests := map[string]struct{ email, password string }{
		"unknown email":    {"nobody@example.com", goodPassword},
		"wrong password":   {"jabbar@example.com", "definitely not it"},
		"sso only account": {"google-user@example.com", goodPassword},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := svc.Login(ctx, tt.email, tt.password, auth.PlatformWeb)
			require.ErrorIs(t, err, auth.ErrInvalidCredentials)
		})
	}
}

func TestVerifyEmail(t *testing.T) {
	t.Parallel()

	svc, _, mail := newService(t)
	ctx := context.Background()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)

	require.NoError(t, svc.VerifyEmail(ctx, mail.lastToken))

	// A token is single use, so a leaked link cannot be replayed.
	require.ErrorIs(t, svc.VerifyEmail(ctx, mail.lastToken), auth.ErrTokenNotUsable)
	require.ErrorIs(t, svc.VerifyEmail(ctx, ""), auth.ErrTokenNotUsable)
	require.ErrorIs(t, svc.VerifyEmail(ctx, "made-up-token"), auth.ErrTokenNotUsable)
}

func TestVerifyEmailRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	store := newFakeStore()
	mail := &fakeMailer{}
	cfg := testConfig()
	cfg.EmailTokenTTL = time.Hour
	svc := auth.NewService(store, store.issuer, mail, cfg, auth.WithClock(func() time.Time { return now }))

	_, err := svc.Register(context.Background(), "jabbar@example.com", goodPassword)
	require.NoError(t, err)

	store.now = now.Add(time.Hour + time.Second)
	require.ErrorIs(t, svc.VerifyEmail(context.Background(), mail.lastToken), auth.ErrTokenNotUsable)
}

func TestAccount(t *testing.T) {
	t.Parallel()

	svc, store, _ := newService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)

	account, err := svc.Account(ctx, user.ID)
	require.NoError(t, err)
	require.True(t, account.HasPassword)
	require.Empty(t, account.Identities)
	require.NotNil(t, account.Identities, "must serialise as [] rather than null")

	_, err = svc.Account(ctx, uuid.Must(uuid.NewV7()))
	require.ErrorIs(t, err, auth.ErrUserNotFound)

	require.Equal(t, store.byEmail["jabbar@example.com"].ID, user.ID)
}

func newService(t *testing.T) (*auth.Service, *fakeStore, *fakeMailer) {
	t.Helper()

	store := newFakeStore()
	mail := &fakeMailer{}
	return auth.NewService(store, store.issuer, mail, testConfig()), store, mail
}

func testConfig() auth.Config {
	return auth.Config{
		EmailTokenTTL:    24 * time.Hour,
		RefreshTTLWeb:    7 * 24 * time.Hour,
		RefreshTTLMobile: 30 * 24 * time.Hour,
	}
}

type fakeMailer struct{ lastToken string }

func (m *fakeMailer) SendEmailVerification(_ context.Context, _, tok string) error {
	m.lastToken = tok
	return nil
}

type fakeStore struct {
	byEmail    map[string]auth.User
	byID       map[uuid.UUID]auth.User
	tokens     map[string]auth.VerificationToken
	refresh    map[string]*storedRefresh
	identities map[uuid.UUID]auth.Identity
	states     map[string]auth.OAuthState
	now        time.Time
	issuer     *token.HS256
	verifier   *token.HS256
}

type storedRefresh struct {
	userID    uuid.UUID
	familyID  uuid.UUID
	platform  string
	usedAt    *time.Time
	revokedAt *time.Time
	expiresAt time.Time
}

func newFakeStore() *fakeStore {
	signer := token.NewHS256([]byte(strings.Repeat("s", 32)), "k1", 15*time.Minute)
	return &fakeStore{
		byEmail:    map[string]auth.User{},
		byID:       map[uuid.UUID]auth.User{},
		tokens:     map[string]auth.VerificationToken{},
		refresh:    map[string]*storedRefresh{},
		identities: map[uuid.UUID]auth.Identity{},
		states:     map[string]auth.OAuthState{},
		now:        time.Now(),
		issuer:     signer,
		verifier:   signer,
	}
}

func (s *fakeStore) addSSOOnly(email string) {
	user := auth.User{ID: uuid.Must(uuid.NewV7()), Email: email, CreatedAt: s.now}
	verified := s.now
	user.EmailVerifiedAt = &verified
	s.byEmail[email] = user
	s.byID[user.ID] = user
}

func (s *fakeStore) CreateUser(_ context.Context, id uuid.UUID, email string, passwordHash *string) (auth.User, error) {
	if _, exists := s.byEmail[email]; exists {
		return auth.User{}, auth.ErrEmailTaken
	}
	user := auth.User{ID: id, Email: email, PasswordHash: passwordHash, CreatedAt: s.now}
	s.byEmail[email] = user
	s.byID[id] = user
	return user, nil
}

func (s *fakeStore) UserByEmail(_ context.Context, email string) (auth.User, error) {
	user, ok := s.byEmail[email]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return user, nil
}

func (s *fakeStore) UserByID(_ context.Context, id uuid.UUID) (auth.User, error) {
	user, ok := s.byID[id]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return user, nil
}

func (s *fakeStore) CreateVerificationToken(_ context.Context, vt auth.VerificationToken) error {
	s.tokens[hex.EncodeToString(vt.TokenHash)] = vt
	return nil
}

func (s *fakeStore) ConsumeEmailVerification(_ context.Context, hash []byte) (uuid.UUID, error) {
	key := hex.EncodeToString(hash)
	vt, ok := s.tokens[key]
	if !ok || vt.Purpose != "email_verify" || !s.now.Before(vt.ExpiresAt) {
		return uuid.Nil, auth.ErrTokenNotUsable
	}
	delete(s.tokens, key)

	user := s.byID[vt.UserID]
	verified := s.now
	user.EmailVerifiedAt = &verified
	s.byID[user.ID] = user
	s.byEmail[user.Email] = user
	return user.ID, nil
}

func (s *fakeStore) CreateRefreshToken(_ context.Context, rt auth.RefreshToken) error {
	s.refresh[hex.EncodeToString(rt.TokenHash)] = &storedRefresh{
		userID:    rt.UserID,
		familyID:  rt.FamilyID,
		platform:  rt.Platform,
		expiresAt: rt.ExpiresAt,
	}
	return nil
}

func (s *fakeStore) UseRefreshToken(_ context.Context, hash []byte) (auth.RefreshTokenUse, error) {
	stored, ok := s.refresh[hex.EncodeToString(hash)]
	if !ok || stored.usedAt != nil || stored.revokedAt != nil || !s.now.Before(stored.expiresAt) {
		return auth.RefreshTokenUse{}, auth.ErrRefreshInvalid
	}
	used := s.now
	stored.usedAt = &used
	return auth.RefreshTokenUse{UserID: stored.userID, FamilyID: stored.familyID}, nil
}

func (s *fakeStore) RefreshTokenByHash(_ context.Context, hash []byte) (auth.RefreshTokenStatus, error) {
	stored, ok := s.refresh[hex.EncodeToString(hash)]
	if !ok {
		return auth.RefreshTokenStatus{}, auth.ErrRefreshInvalid
	}
	return auth.RefreshTokenStatus{FamilyID: stored.familyID, UsedAt: stored.usedAt}, nil
}

func (s *fakeStore) RevokeRefreshFamily(_ context.Context, familyID uuid.UUID) error {
	for _, stored := range s.refresh {
		if stored.familyID == familyID && stored.revokedAt == nil {
			revoked := s.now
			stored.revokedAt = &revoked
		}
	}
	return nil
}

// countLive reports how many tokens in the chain are still usable, which is
// what reuse detection is supposed to drive to zero.
func (s *fakeStore) countLive() int {
	live := 0
	for _, stored := range s.refresh {
		if stored.revokedAt == nil {
			live++
		}
	}
	return live
}

func (s *fakeStore) IdentityByProviderSubject(_ context.Context, provider, subject string) (auth.Identity, error) {
	for _, i := range s.identities {
		if i.Provider == provider && i.Subject == subject {
			return i, nil
		}
	}
	return auth.Identity{}, auth.ErrIdentityNotFound
}

func (s *fakeStore) IdentitiesByUser(_ context.Context, userID uuid.UUID) ([]auth.Identity, error) {
	out := []auth.Identity{}
	for _, i := range s.identities {
		if i.UserID == userID {
			out = append(out, i)
		}
	}
	return out, nil
}

func (s *fakeStore) CreateIdentity(_ context.Context, userID uuid.UUID, i auth.Identity) (auth.Identity, error) {
	for _, existing := range s.identities {
		if existing.Provider == i.Provider && existing.Subject == i.Subject {
			return auth.Identity{}, auth.ErrIdentityAlreadyLinked
		}
	}
	i.UserID = userID
	s.identities[i.ID] = i
	return i, nil
}

func (s *fakeStore) CreateUserWithIdentity(_ context.Context, email string, i auth.Identity) (auth.User, error) {
	if _, exists := s.byEmail[email]; exists {
		return auth.User{}, auth.ErrEmailTaken
	}

	verified := s.now
	user := auth.User{
		ID:              uuid.Must(uuid.NewV7()),
		Email:           email,
		EmailVerifiedAt: &verified,
		CreatedAt:       s.now,
	}
	s.byEmail[email] = user
	s.byID[user.ID] = user

	i.UserID = user.ID
	s.identities[i.ID] = i
	return user, nil
}

func (s *fakeStore) DeleteIdentity(_ context.Context, id, userID uuid.UUID) error {
	i, ok := s.identities[id]
	if !ok || i.UserID != userID {
		return auth.ErrIdentityNotFound
	}
	delete(s.identities, id)
	return nil
}

func (s *fakeStore) CountAuthMethods(_ context.Context, userID uuid.UUID) (int, error) {
	count := 0
	if user, ok := s.byID[userID]; ok && user.HasPassword() {
		count++
	}
	for _, i := range s.identities {
		if i.UserID == userID {
			count++
		}
	}
	return count, nil
}

func (s *fakeStore) EnabledProviders(context.Context) ([]auth.ProviderInfo, error) {
	return []auth.ProviderInfo{
		{Code: "google", DisplayName: "Google"},
		{Code: "microsoft", DisplayName: "Microsoft"},
	}, nil
}

func (s *fakeStore) CreateOAuthState(_ context.Context, st auth.OAuthState) error {
	s.states[st.State] = st
	return nil
}

func (s *fakeStore) ConsumeOAuthState(_ context.Context, state string) (auth.OAuthState, error) {
	st, ok := s.states[state]
	if !ok || !s.now.Before(st.ExpiresAt) {
		return auth.OAuthState{}, auth.ErrOAuthStateInvalid
	}
	delete(s.states, state)
	return st, nil
}
