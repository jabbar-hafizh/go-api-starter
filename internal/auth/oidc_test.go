package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
)

// fakeProvider stands in for Google. The flow under test is provider agnostic,
// which is exactly what this proves: nothing here is Google specific.
type fakeProvider struct {
	code     string
	claims   auth.ProviderClaims
	err      error
	lastURL  string
	lastNonc string
}

func (p *fakeProvider) Code() string { return p.code }

func (p *fakeProvider) AuthCodeURL(state, nonce, codeVerifier string) string {
	p.lastNonc = nonce
	p.lastURL = "https://provider.example/auth?state=" + state +
		"&nonce=" + nonce + "&code_challenge_len=" + itoa(len(codeVerifier))
	return p.lastURL
}

func (p *fakeProvider) Exchange(_ context.Context, _, _, nonce string) (auth.ProviderClaims, error) {
	if p.err != nil {
		return auth.ProviderClaims{}, p.err
	}
	if nonce != p.lastNonc {
		return auth.ProviderClaims{}, auth.ErrOAuthStateInvalid
	}
	return p.claims, nil
}

func (p *fakeProvider) VerifyIDToken(context.Context, string) (auth.ProviderClaims, error) {
	if p.err != nil {
		return auth.ProviderClaims{}, p.err
	}
	return p.claims, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func newServiceWithProvider(t *testing.T, claims auth.ProviderClaims) (*auth.Service, *fakeStore, *fakeMailer, *fakeProvider) {
	t.Helper()

	store := newFakeStore()
	mail := &fakeMailer{}
	provider := &fakeProvider{code: "google", claims: claims}
	svc := auth.NewService(store, store.issuer, mail, testConfig(), auth.WithProviders(provider))
	return svc, store, mail, provider
}

func verifiedClaims(email string) auth.ProviderClaims {
	return auth.ProviderClaims{Subject: "provider-subject-1", Email: email, EmailVerified: true}
}

// Nobody owns the address yet, so the account is created already verified:
// the provider vouched for it.
func TestProviderSignInCreatesAccount(t *testing.T) {
	t.Parallel()

	svc, store, _, _ := newServiceWithProvider(t, verifiedClaims("new@example.com"))

	session, err := svc.SignInWithProviderToken(t.Context(), "google", "any-id-token", auth.PlatformIOS)
	require.NoError(t, err)
	require.NotEmpty(t, session.Access.Value)

	user := store.byEmail["new@example.com"]
	require.True(t, user.EmailVerified())
	require.False(t, user.HasPassword(), "an SSO signup has no password")
	require.Len(t, store.identities, 1)
}

// Signing in twice must reuse the identity, not create a second account.
func TestProviderSignInIsIdempotent(t *testing.T) {
	t.Parallel()

	svc, store, _, _ := newServiceWithProvider(t, verifiedClaims("new@example.com"))
	ctx := t.Context()

	_, err := svc.SignInWithProviderToken(ctx, "google", "tok", auth.PlatformIOS)
	require.NoError(t, err)
	_, err = svc.SignInWithProviderToken(ctx, "google", "tok", auth.PlatformIOS)
	require.NoError(t, err)

	require.Len(t, store.byEmail, 1)
	require.Len(t, store.identities, 1)
}

// The address is registered and was proven, so linking is safe.
func TestProviderSignInLinksToVerifiedAccount(t *testing.T) {
	t.Parallel()

	svc, store, mail, _ := newServiceWithProvider(t, verifiedClaims("jabbar@example.com"))
	ctx := t.Context()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)
	require.NoError(t, svc.VerifyEmail(ctx, mail.lastToken))

	_, err = svc.SignInWithProviderToken(ctx, "google", "tok", auth.PlatformIOS)
	require.NoError(t, err)

	require.Len(t, store.byEmail, 1, "must attach to the existing account, not create another")
	require.Len(t, store.identities, 1)

	account, err := svc.Account(ctx, store.byEmail["jabbar@example.com"].ID)
	require.NoError(t, err)
	require.True(t, account.HasPassword)
	require.Len(t, account.Identities, 1)
}

// The attack this whole design is arranged around.
//
// An attacker registers with an address they do not own and never verifies it.
// The real owner later signs in with the provider. Linking automatically here
// would hand the attacker's account, whose password they know, to the victim
// and every piece of data the victim then puts in it.
func TestProviderSignInRefusesToLinkUnverifiedAccount(t *testing.T) {
	t.Parallel()

	svc, store, _, _ := newServiceWithProvider(t, verifiedClaims("victim@example.com"))
	ctx := t.Context()

	// The attacker registers with the victim's address and stops there.
	_, err := svc.Register(ctx, "victim@example.com", goodPassword)
	require.NoError(t, err)

	_, err = svc.SignInWithProviderToken(ctx, "google", "tok", auth.PlatformIOS)
	require.ErrorIs(t, err, auth.ErrLinkNeedsVerifiedEmail)

	require.Empty(t, store.identities, "nothing may be linked")
}

func TestProviderSignInRefusesUnverifiedProviderEmail(t *testing.T) {
	t.Parallel()

	claims := verifiedClaims("nope@example.com")
	claims.EmailVerified = false
	svc, store, _, _ := newServiceWithProvider(t, claims)

	_, err := svc.SignInWithProviderToken(t.Context(), "google", "tok", auth.PlatformIOS)
	require.ErrorIs(t, err, auth.ErrProviderEmailUnverified)
	require.Empty(t, store.byEmail)
}

func TestProviderSignInRefusesIncompleteClaims(t *testing.T) {
	t.Parallel()

	tests := map[string]auth.ProviderClaims{
		"no subject": {Subject: "", Email: "a@example.com", EmailVerified: true},
		"no email":   {Subject: "sub-1", Email: "", EmailVerified: true},
	}

	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			svc, _, _, _ := newServiceWithProvider(t, claims)
			_, err := svc.SignInWithProviderToken(t.Context(), "google", "tok", auth.PlatformIOS)
			require.ErrorIs(t, err, auth.ErrProviderClaimsIncomplete)
		})
	}
}

func TestUnknownProviderIsNotImplemented(t *testing.T) {
	t.Parallel()

	svc, _, _, _ := newServiceWithProvider(t, verifiedClaims("a@example.com"))
	ctx := t.Context()

	_, err := svc.SignInWithProviderToken(ctx, "microsoft", "tok", auth.PlatformIOS)
	require.ErrorIs(t, err, auth.ErrProviderNotConfigured)

	_, err = svc.StartProviderSignIn(ctx, "microsoft", nil)
	require.ErrorIs(t, err, auth.ErrProviderNotConfigured)
}

// A provider enabled in the database but not configured here would render a
// button that cannot work.
func TestProvidersListsOnlyConfiguredOnes(t *testing.T) {
	t.Parallel()

	svc, _, _, _ := newServiceWithProvider(t, verifiedClaims("a@example.com"))

	providers, err := svc.Providers(t.Context())
	require.NoError(t, err)
	require.Len(t, providers, 1)
	require.Equal(t, "google", providers[0].Code)
}

func TestBrowserFlow(t *testing.T) {
	t.Parallel()

	svc, store, _, provider := newServiceWithProvider(t, verifiedClaims("web@example.com"))
	ctx := t.Context()

	redirect := "/dashboard"
	target, err := svc.StartProviderSignIn(ctx, "google", &redirect)
	require.NoError(t, err)
	require.Contains(t, target, "state=")
	require.Contains(t, target, "nonce=")
	// 43 characters is a valid PKCE code_verifier length.
	require.Contains(t, provider.lastURL, "code_challenge_len=43")
	require.Len(t, store.states, 1)

	var state string
	for k := range store.states {
		state = k
	}

	session, back, err := svc.CompleteProviderSignIn(ctx, state, "auth-code", auth.PlatformWeb)
	require.NoError(t, err)
	require.NotEmpty(t, session.RefreshToken)
	require.Equal(t, 7*24*time.Hour, session.RefreshTTL, "the browser flow is a web client")
	require.NotNil(t, back)
	require.Equal(t, "/dashboard", *back)

	// Reading the state deleted it, so a captured callback cannot be replayed.
	require.Empty(t, store.states)
	_, _, err = svc.CompleteProviderSignIn(ctx, state, "auth-code", auth.PlatformWeb)
	require.ErrorIs(t, err, auth.ErrOAuthStateInvalid)
}

func TestBrowserFlowRejectsBadState(t *testing.T) {
	t.Parallel()

	tests := map[string]func(store *fakeStore, state string) string{
		"empty":   func(*fakeStore, string) string { return "" },
		"unknown": func(*fakeStore, string) string { return "never-issued" },
		"expired": func(store *fakeStore, state string) string {
			store.now = store.now.Add(11 * time.Minute)
			return state
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			svc, store, _, _ := newServiceWithProvider(t, verifiedClaims("web@example.com"))
			ctx := t.Context()

			_, err := svc.StartProviderSignIn(ctx, "google", nil)
			require.NoError(t, err)

			var issued string
			for k := range store.states {
				issued = k
			}

			_, _, err = svc.CompleteProviderSignIn(ctx, mutate(store, issued), "code", auth.PlatformWeb)
			require.ErrorIs(t, err, auth.ErrOAuthStateInvalid)
		})
	}
}

func TestLinkAndUnlink(t *testing.T) {
	t.Parallel()

	svc, store, mail, _ := newServiceWithProvider(t, verifiedClaims("jabbar@example.com"))
	ctx := t.Context()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)
	require.NoError(t, svc.VerifyEmail(ctx, mail.lastToken))
	userID := store.byEmail["jabbar@example.com"].ID

	identity, err := svc.LinkProviderToken(ctx, userID, "google", "tok")
	require.NoError(t, err)
	require.Equal(t, "google", identity.Provider)

	// One provider account cannot belong to two users.
	other := uuid.Must(uuid.NewV7())
	_, err = svc.LinkProviderToken(ctx, other, "google", "tok")
	require.ErrorIs(t, err, auth.ErrIdentityAlreadyLinked)

	// Two methods now, so removing one is fine.
	require.NoError(t, svc.UnlinkIdentity(ctx, userID, identity.ID))

	account, err := svc.Account(ctx, userID)
	require.NoError(t, err)
	require.Empty(t, account.Identities)
	require.True(t, account.HasPassword)
}

// Someone who signed up with a provider and never set a password would lose
// the account permanently.
func TestUnlinkRefusesTheLastMethod(t *testing.T) {
	t.Parallel()

	svc, store, _, _ := newServiceWithProvider(t, verifiedClaims("sso@example.com"))
	ctx := t.Context()

	_, err := svc.SignInWithProviderToken(ctx, "google", "tok", auth.PlatformIOS)
	require.NoError(t, err)

	userID := store.byEmail["sso@example.com"].ID
	account, err := svc.Account(ctx, userID)
	require.NoError(t, err)
	require.Len(t, account.Identities, 1)
	require.False(t, account.HasPassword)

	err = svc.UnlinkIdentity(ctx, userID, account.Identities[0].ID)
	require.ErrorIs(t, err, auth.ErrLastAuthMethod)

	still, err := svc.Account(ctx, userID)
	require.NoError(t, err)
	require.Len(t, still.Identities, 1, "the identity must survive the refusal")
}

func TestProviderEmailIsNormalised(t *testing.T) {
	t.Parallel()

	svc, store, _, _ := newServiceWithProvider(t, verifiedClaims("  MiXeD@Example.COM "))

	_, err := svc.SignInWithProviderToken(t.Context(), "google", "tok", auth.PlatformIOS)
	require.NoError(t, err)

	_, ok := store.byEmail["mixed@example.com"]
	require.True(t, ok, "the stored address must be normalised")
	require.NotContains(t, strings.Join(keys(store.byEmail), ","), "MiXeD")
}

func keys(m map[string]auth.User) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
