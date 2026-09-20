package token_test

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/token"
)

var (
	secret = []byte(strings.Repeat("s", 32))
	keyID  = "k1"
	ttl    = 15 * time.Minute
)

func TestIssueThenVerify(t *testing.T) {
	t.Parallel()

	h := token.NewHS256(secret, keyID, ttl)
	userID := uuid.Must(uuid.NewV7())

	issued, err := h.Issue(userID)
	require.NoError(t, err)
	require.Equal(t, ttl, issued.ExpiresIn)

	claims, err := h.Verify(issued.Value)
	require.NoError(t, err)
	require.Equal(t, userID, claims.UserID)
	require.NotEmpty(t, claims.ID)
}

// Two tokens for the same user must differ, otherwise a single leaked token
// identifies every session that user ever had.
func TestEveryTokenHasItsOwnID(t *testing.T) {
	t.Parallel()

	h := token.NewHS256(secret, keyID, ttl)
	userID := uuid.Must(uuid.NewV7())

	first, err := h.Issue(userID)
	require.NoError(t, err)
	second, err := h.Issue(userID)
	require.NoError(t, err)

	a, err := h.Verify(first.Value)
	require.NoError(t, err)
	b, err := h.Verify(second.Value)
	require.NoError(t, err)
	require.NotEqual(t, a.ID, b.ID)
}

func TestKeyIDIsInTheHeader(t *testing.T) {
	t.Parallel()

	h := token.NewHS256(secret, keyID, ttl)
	issued, err := h.Issue(uuid.Must(uuid.NewV7()))
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser().ParseUnverified(issued.Value, jwt.MapClaims{})
	require.NoError(t, err)
	require.Equal(t, keyID, parsed.Header["kid"])
}

func TestVerifyRejects(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	h := token.NewHS256(secret, keyID, ttl, token.WithClock(clock))

	valid, err := h.Issue(uuid.Must(uuid.NewV7()))
	require.NoError(t, err)

	tests := []struct {
		name  string
		token func() string
		with  *token.HS256
	}{
		{
			name:  "garbage",
			token: func() string { return "not-a-token" },
		},
		{
			name:  "empty",
			token: func() string { return "" },
		},
		{
			name: "tampered payload",
			token: func() string {
				parts := strings.Split(valid.Value, ".")
				return parts[0] + ".eyJzdWIiOiJhdHRhY2tlciJ9." + parts[2]
			},
		},
		{
			name:  "signed with a different secret",
			token: func() string { return issueWith(t, []byte(strings.Repeat("x", 32)), keyID, now) },
		},
		{
			// A token signed with an unexpected key id must not verify even
			// though the secret matches, or key rotation means nothing.
			name:  "unknown key id",
			token: func() string { return issueWith(t, secret, "k2", now) },
		},
		{
			name:  "alg none",
			token: func() string { return algNoneToken(t) },
		},
		{
			name:  "expired",
			token: func() string { return valid.Value },
			with: token.NewHS256(secret, keyID, ttl, token.WithClock(func() time.Time {
				return now.Add(ttl + time.Second)
			})),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			verifier := h
			if tt.with != nil {
				verifier = tt.with
			}
			_, err := verifier.Verify(tt.token())
			require.ErrorIs(t, err, token.ErrInvalid)
		})
	}
}

func issueWith(t *testing.T, secret []byte, kid string, now time.Time) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"jti": uuid.Must(uuid.NewV7()).String(),
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"typ": "access",
	})
	tok.Header["kid"] = kid

	signed, err := tok.SignedString(secret)
	require.NoError(t, err)
	return signed
}

func algNoneToken(t *testing.T) string {
	t.Helper()

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": uuid.Must(uuid.NewV7()).String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"typ": "access",
	})
	tok.Header["kid"] = keyID

	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return signed
}
