package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
)

// signIn registers, verifies and logs in, returning the first session.
func signIn(t *testing.T, p auth.Platform) (*auth.Service, *fakeStore, auth.Session) {
	t.Helper()

	svc, store, mail := newService(t)
	ctx := t.Context()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)
	require.NoError(t, svc.VerifyEmail(ctx, mail.lastToken))

	session, err := svc.Login(ctx, "jabbar@example.com", goodPassword, p)
	require.NoError(t, err)
	return svc, store, session
}

func TestRefreshRotates(t *testing.T) {
	t.Parallel()

	svc, store, first := signIn(t, auth.PlatformWeb)

	second, err := svc.Refresh(t.Context(), first.RefreshToken, auth.PlatformWeb)
	require.NoError(t, err)

	require.NotEqual(t, first.RefreshToken, second.RefreshToken, "every refresh must mint a new token")
	require.NotEqual(t, first.Access.Value, second.Access.Value)

	claims, err := store.verifier.Verify(second.Access.Value)
	require.NoError(t, err)
	require.Equal(t, store.byEmail["jabbar@example.com"].ID, claims.UserID)

	// Two rows now, both in the same chain, with only the newer one usable.
	require.Len(t, store.refresh, 2)
}

// The whole point of rotation: a token works once. This is what turns a stolen
// copy into something detectable instead of something silently reusable.
func TestRefreshTokenIsSingleUse(t *testing.T) {
	t.Parallel()

	svc, _, first := signIn(t, auth.PlatformWeb)

	_, err := svc.Refresh(t.Context(), first.RefreshToken, auth.PlatformWeb)
	require.NoError(t, err)

	_, err = svc.Refresh(t.Context(), first.RefreshToken, auth.PlatformWeb)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)
}

// Replaying a spent token means two parties hold it. There is no way to tell
// which one is the owner, so the safe answer is to end the session for both.
func TestReuseRevokesTheWholeChain(t *testing.T) {
	t.Parallel()

	svc, store, first := signIn(t, auth.PlatformWeb)
	ctx := t.Context()

	second, err := svc.Refresh(ctx, first.RefreshToken, auth.PlatformWeb)
	require.NoError(t, err)
	require.Equal(t, 2, store.countLive())

	// An attacker replays the copy they took.
	_, err = svc.Refresh(ctx, first.RefreshToken, auth.PlatformWeb)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)

	require.Zero(t, store.countLive(), "every token in the chain must be revoked")

	// And the legitimate holder is signed out too, which is the intended cost.
	_, err = svc.Refresh(ctx, second.RefreshToken, auth.PlatformWeb)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)
}

func TestRefreshRejectsUnusableTokens(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, store *fakeStore, s auth.Session) string{
		"empty":   func(*testing.T, *fakeStore, auth.Session) string { return "" },
		"unknown": func(*testing.T, *fakeStore, auth.Session) string { return "never-issued-token" },
		"expired": func(_ *testing.T, store *fakeStore, s auth.Session) string {
			store.now = store.now.Add(8 * 24 * time.Hour)
			return s.RefreshToken
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			svc, store, session := signIn(t, auth.PlatformWeb)
			presented := setup(t, store, session)

			_, err := svc.Refresh(t.Context(), presented, auth.PlatformWeb)
			require.ErrorIs(t, err, auth.ErrRefreshInvalid)
		})
	}
}

// An expired token is not evidence of theft, so it must not take the chain
// down with it.
func TestExpiryDoesNotRevokeTheChain(t *testing.T) {
	t.Parallel()

	svc, store, session := signIn(t, auth.PlatformWeb)
	store.now = store.now.Add(8 * 24 * time.Hour)

	_, err := svc.Refresh(t.Context(), session.RefreshToken, auth.PlatformWeb)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)
	require.Equal(t, 1, store.countLive(), "the chain must not be revoked merely because a token aged out")
}

func TestLogoutRevokesTheWholeChain(t *testing.T) {
	t.Parallel()

	svc, store, first := signIn(t, auth.PlatformWeb)
	ctx := t.Context()

	second, err := svc.Refresh(ctx, first.RefreshToken, auth.PlatformWeb)
	require.NoError(t, err)

	svc.Logout(ctx, second.RefreshToken)
	require.Zero(t, store.countLive())

	_, err = svc.Refresh(ctx, second.RefreshToken, auth.PlatformWeb)
	require.ErrorIs(t, err, auth.ErrRefreshInvalid)
}

// Logout never reports a problem. A client that asked to leave must not be
// told it is still signed in.
func TestLogoutIsSilentOnUnknownTokens(t *testing.T) {
	t.Parallel()

	svc, store, _ := signIn(t, auth.PlatformWeb)

	svc.Logout(t.Context(), "never-issued-token")
	svc.Logout(t.Context(), "")

	require.Equal(t, 1, store.countLive(), "an unknown token must not revoke anything")
}

// A phone user will not accept signing in again every week, a browser session
// should not last a month.
func TestPlatformDecidesTheRefreshLifetime(t *testing.T) {
	t.Parallel()

	tests := map[auth.Platform]time.Duration{
		auth.PlatformWeb:     7 * 24 * time.Hour,
		auth.PlatformIOS:     30 * 24 * time.Hour,
		auth.PlatformAndroid: 30 * 24 * time.Hour,
		// Anything unrecognised is treated as a native client.
		auth.Platform("unknown"): 30 * 24 * time.Hour,
		auth.Platform(""):        30 * 24 * time.Hour,
	}

	for platform, want := range tests {
		t.Run(string(platform), func(t *testing.T) {
			t.Parallel()

			_, _, session := signIn(t, platform)
			require.Equal(t, want, session.RefreshTTL)
		})
	}
}
