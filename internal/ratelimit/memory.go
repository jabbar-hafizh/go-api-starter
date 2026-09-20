package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// sweepInterval is how often idle keys are dropped. Without it the map grows
// with every distinct IP that ever arrived, which is a slow memory leak an
// attacker can drive.
const sweepInterval = time.Minute

// Memory limits per key inside this process. Correct for one replica; once
// there are two, each enforces the limit separately and the real ceiling is
// the sum. That is the point to swap in a shared store.
type Memory struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      rate.Limit
	burst     int
	idleTTL   time.Duration
	lastSweep time.Time
	now       func() time.Time
}

type bucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

// Option configures a Memory limiter.
type Option func(*Memory)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(m *Memory) { m.now = now }
}

// NewMemory allows perSecond sustained with room for a burst.
func NewMemory(perSecond float64, burst int, idleTTL time.Duration, opts ...Option) *Memory {
	m := &Memory{
		buckets: map[string]*bucket{},
		rate:    rate.Limit(perSecond),
		burst:   burst,
		idleTTL: idleTTL,
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(m)
	}
	m.lastSweep = m.now()
	return m
}

func (m *Memory) Allow(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.sweepLocked(now)

	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{limiter: rate.NewLimiter(m.rate, m.burst)}
		m.buckets[key] = b
	}
	b.seen = now

	return b.limiter.AllowN(now, 1), nil
}

// Len reports how many keys are being tracked, so tests can prove the sweep
// actually reclaims them.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}

func (m *Memory) sweepLocked(now time.Time) {
	if now.Sub(m.lastSweep) < sweepInterval {
		return
	}
	m.lastSweep = now

	for key, b := range m.buckets {
		if now.Sub(b.seen) > m.idleTTL {
			delete(m.buckets, key)
		}
	}
}
