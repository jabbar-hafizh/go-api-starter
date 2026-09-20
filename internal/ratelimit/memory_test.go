package ratelimit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/ratelimit"
)

func TestBurstThenRefill(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	// One per second, three at once.
	limiter := ratelimit.NewMemory(1, 3, time.Hour, ratelimit.WithClock(clock))

	for i := range 3 {
		allowed, err := limiter.Allow(t.Context(), "a")
		require.NoError(t, err)
		require.True(t, allowed, "the burst covers attempt %d", i+1)
	}

	allowed, err := limiter.Allow(t.Context(), "a")
	require.NoError(t, err)
	require.False(t, allowed, "the burst is spent")

	now = now.Add(time.Second)
	allowed, err = limiter.Allow(t.Context(), "a")
	require.NoError(t, err)
	require.True(t, allowed, "one second buys one attempt back")
}

// Limiting one key must not touch another, or one noisy address would lock out
// everybody else.
func TestKeysAreIndependent(t *testing.T) {
	t.Parallel()

	limiter := ratelimit.NewMemory(1, 1, time.Hour)

	allowed, err := limiter.Allow(t.Context(), "a")
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, err = limiter.Allow(t.Context(), "a")
	require.NoError(t, err)
	require.False(t, allowed)

	allowed, err = limiter.Allow(t.Context(), "b")
	require.NoError(t, err)
	require.True(t, allowed)
}

// Without the sweep the map grows with every distinct address that ever
// arrived, which is a slow leak an attacker can drive.
func TestIdleKeysAreReclaimed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	limiter := ratelimit.NewMemory(10, 10, 5*time.Minute, ratelimit.WithClock(clock))

	for _, key := range []string{"a", "b", "c"} {
		_, err := limiter.Allow(t.Context(), key)
		require.NoError(t, err)
	}
	require.Equal(t, 3, limiter.Len())

	// Past the idle window, and past the sweep interval so a sweep runs.
	now = now.Add(10 * time.Minute)
	_, err := limiter.Allow(t.Context(), "d")
	require.NoError(t, err)

	require.Equal(t, 1, limiter.Len(), "only the key just used survives")
}

func TestAllowedPermitsEverything(t *testing.T) {
	t.Parallel()

	var limiter ratelimit.Limiter = ratelimit.Allowed{}
	for range 100 {
		allowed, err := limiter.Allow(t.Context(), "same-key")
		require.NoError(t, err)
		require.True(t, allowed)
	}
}

func TestConcurrentAllowIsSafe(t *testing.T) {
	t.Parallel()

	limiter := ratelimit.NewMemory(1000, 1000, time.Hour)
	done := make(chan struct{})

	for range 16 {
		go func() {
			for range 50 {
				_, _ = limiter.Allow(t.Context(), "shared")
			}
			done <- struct{}{}
		}()
	}
	for range 16 {
		<-done
	}
}
