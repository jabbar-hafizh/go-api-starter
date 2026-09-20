package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// OWASP's baseline for argon2id. Memory dominates the cost, so raising it also
// raises what a burst of concurrent logins needs.
const (
	argonMemory      uint32 = 19456 // KiB
	argonIterations  uint32 = 2
	argonParallelism uint8  = 1
	argonSaltLen            = 16
	argonKeyLen      uint32 = 32

	minKeyLen = 16
	maxKeyLen = 64
)

var errMalformedHash = errors.New("malformed password hash")

// hashPassword returns a PHC string that carries its own parameters, so the
// cost can be raised later without invalidating existing hashes.
func hashPassword(plain string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	key := argon2.IDKey([]byte(plain), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		b64(salt), b64(key),
	), nil
}

// verifyPassword reads the parameters out of the stored hash rather than using
// the constants above, so hashes written under an older cost still verify.
func verifyPassword(plain, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errMalformedHash
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, errMalformedHash
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return false, errMalformedHash
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return false, errMalformedHash
	}

	// The key length is implied by the stored hash rather than written in the
	// parameter string, so bound it before trusting it as a length.
	if len(want) < minKeyLen || len(want) > maxKeyLen {
		return false, errMalformedHash
	}

	//nolint:gosec // bounded to [minKeyLen, maxKeyLen] three lines above
	got := argon2.IDKey([]byte(plain), salt, iterations, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when the email is unknown, so a missing
// account and a wrong password take the same time to answer. Without it the
// response time tells an attacker which emails are registered.
var dummyHash = sync.OnceValue(func() string {
	h, err := hashPassword("this password matches nothing")
	if err != nil {
		// hashPassword only fails if the system RNG fails, which is not a
		// condition this process can carry on through.
		panic(err)
	}
	return h
})

func burnPasswordTime() {
	_, _ = verifyPassword("this password matches nothing either", dummyHash())
}

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// argonKey and base64Decode exist so tests can build a hash under parameters
// other than the current constants.
func argonKey(plain string, salt []byte, iterations, memory uint32, parallelism uint8, keyLen uint32) []byte {
	return argon2.IDKey([]byte(plain), salt, iterations, memory, parallelism, keyLen)
}

func base64Decode(s string) ([]byte, error) {
	return base64.RawStdEncoding.Strict().DecodeString(s)
}
