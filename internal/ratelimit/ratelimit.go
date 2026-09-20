// Package ratelimit bounds how often a caller may do something.
package ratelimit

import "context"

// Limiter reports whether an action keyed by something the caller chooses is
// allowed right now.
//
// The context and the error are here for the Redis implementation that arrives
// when this runs on more than one instance. In-process limits are per replica,
// so two replicas means twice the real limit.
type Limiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

// Allowed is a Limiter that permits everything, for tests and for turning
// limiting off without threading a nil through the call sites.
type Allowed struct{}

// Allow always allows.
func (Allowed) Allow(context.Context, string) (bool, error) { return true, nil }
