package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashThenVerify(t *testing.T) {
	t.Parallel()

	encoded, err := hashPassword("correct-horse-battery-staple")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$"))

	ok, err := verifyPassword("correct-horse-battery-staple", encoded)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = verifyPassword("not the password", encoded)
	require.NoError(t, err)
	require.False(t, ok)
}

// The same password must never produce the same hash, or equal hashes would
// reveal which accounts share a password.
func TestSaltIsRandom(t *testing.T) {
	t.Parallel()

	first, err := hashPassword("same password")
	require.NoError(t, err)
	second, err := hashPassword("same password")
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}

// Parameters are read from the stored hash, not from the constants, so raising
// the cost later does not lock anyone out.
func TestVerifyUsesTheStoredParameters(t *testing.T) {
	t.Parallel()

	weaker := "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHRzb21lc2FsdA$" +
		mustHashWith(t, "hello world 123", 8, 1, 1)

	ok, err := verifyPassword("hello world 123", weaker)
	require.NoError(t, err)
	require.True(t, ok, "a hash written under weaker parameters must still verify")
}

func TestVerifyRejectsMalformed(t *testing.T) {
	t.Parallel()

	valid, err := hashPassword("some password here")
	require.NoError(t, err)

	tests := map[string]string{
		"empty":           "",
		"not phc":         "plain-text-password",
		"wrong algorithm": strings.Replace(valid, "argon2id", "bcrypt00", 1),
		"wrong version":   strings.Replace(valid, "v=19", "v=16", 1),
		"bad params":      strings.Replace(valid, "m=19456,t=2,p=1", "m=abc", 1),
		"bad salt base64": "$argon2id$v=19$m=19456,t=2,p=1$not!valid!base64$" + strings.Split(valid, "$")[5],
		"bad key base64":  strings.Join(append(strings.Split(valid, "$")[:5], "not!valid!base64"), "$"),
		"truncated":       "$argon2id$v=19$m=19456,t=2,p=1$",
		"key too short":   "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$YWJj",
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ok, err := verifyPassword("some password here", encoded)
			require.Error(t, err)
			require.False(t, ok)
		})
	}
}

func mustHashWith(t *testing.T, plain string, memory, iterations uint32, parallelism uint8) string {
	t.Helper()

	salt, err := base64Decode("c29tZXNhbHRzb21lc2FsdA")
	require.NoError(t, err)

	return b64(argonKey(plain, salt, iterations, memory, parallelism, argonKeyLen))
}
