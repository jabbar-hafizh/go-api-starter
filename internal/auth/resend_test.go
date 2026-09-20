package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
	"github.com/jabbar-hafizh/go-api-starter/internal/ratelimit"
)

type brokenMailer struct{ calls int }

func (m *brokenMailer) SendEmailVerification(context.Context, string, string) error {
	m.calls++
	return errors.New("smtp is down")
}

// The account exists by the time the email is attempted. Failing the request
// would tell the caller it does not, and their retry would hit "email already
// registered" with no way forward. A bad SMTP credential produced exactly this
// before it was fixed.
func TestRegisterSucceedsWhenMailFails(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	mail := &brokenMailer{}
	svc := auth.NewService(store, store.issuer, mail, testConfig())

	user, err := svc.Register(t.Context(), "jabbar@example.com", goodPassword)
	require.NoError(t, err, "registration must not fail because mail failed")
	require.False(t, user.EmailVerified())
	require.Equal(t, 1, mail.calls)

	// And the caller must not be able to register again and get stuck.
	_, err = svc.Register(t.Context(), "jabbar@example.com", goodPassword)
	require.ErrorIs(t, err, auth.ErrEmailTaken)
}

func TestResendIssuesAFreshLink(t *testing.T) {
	t.Parallel()

	svc, store, mail := newService(t)
	ctx := t.Context()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)
	first := mail.lastToken

	svc.ResendEmailVerification(ctx, "jabbar@example.com")
	second := mail.lastToken

	require.NotEqual(t, first, second, "a resend must issue a new token")
	require.Len(t, store.tokens, 1, "the earlier link is retired, not accumulated")

	// Only the newest works, so a stale link cannot be used later.
	require.ErrorIs(t, svc.VerifyEmail(ctx, first), auth.ErrTokenNotUsable)
	require.NoError(t, svc.VerifyEmail(ctx, second))
}

// Any answer that varies would turn this into a way to test which addresses
// have accounts.
func TestResendIsSilent(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, svc *auth.Service, mail *fakeMailer) string{
		"unknown address": func(*testing.T, *auth.Service, *fakeMailer) string {
			return "nobody@example.com"
		},
		"already verified": func(t *testing.T, svc *auth.Service, mail *fakeMailer) string {
			_, err := svc.Register(t.Context(), "done@example.com", goodPassword)
			require.NoError(t, err)
			require.NoError(t, svc.VerifyEmail(t.Context(), mail.lastToken))
			mail.lastToken = ""
			return "done@example.com"
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			svc, _, mail := newService(t)
			email := setup(t, svc, mail)

			// No panic, no error, and nothing sent.
			svc.ResendEmailVerification(t.Context(), email)
			require.Empty(t, mail.lastToken)
		})
	}
}

// This endpoint sends mail to whatever address is named, so without a ceiling
// it is a way to bomb someone else's inbox.
func TestResendIsRateLimited(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	mail := &fakeMailer{}
	svc := auth.NewService(store, store.issuer, mail, testConfig(),
		auth.WithResendLimiter(ratelimit.NewMemory(1.0/3600, 2, time.Hour)))

	ctx := t.Context()
	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)

	sent := map[string]bool{}
	for range 6 {
		mail.lastToken = ""
		svc.ResendEmailVerification(ctx, "jabbar@example.com")
		if mail.lastToken != "" {
			sent[mail.lastToken] = true
		}
	}

	require.Len(t, sent, 2, "the burst allows two, and no more")
}

// Normalised, so the limit cannot be sidestepped by changing the case.
func TestResendNormalisesTheAddress(t *testing.T) {
	t.Parallel()

	svc, _, mail := newService(t)
	ctx := t.Context()

	_, err := svc.Register(ctx, "jabbar@example.com", goodPassword)
	require.NoError(t, err)

	mail.lastToken = ""
	svc.ResendEmailVerification(ctx, "  JABBAR@Example.COM ")
	require.NotEmpty(t, mail.lastToken)
}
