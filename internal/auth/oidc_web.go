package auth

import (
	"context"
	"time"
)

// oauthStateTTL bounds how long a started sign-in stays valid. Long enough for
// someone to pick a Google account, short enough that a captured state is not
// useful later.
const oauthStateTTL = 10 * time.Minute

// StartProviderSignIn records the state, nonce and PKCE verifier, then returns
// the URL to send the browser to.
//
// The state lives server side and is deleted as it is read. A cookie alone
// would not do: it gives no replay protection, and a forged callback lets an
// attacker attach their provider account to the victim's session.
func (s *Service) StartProviderSignIn(ctx context.Context, providerCode string, redirectTo *string) (string, error) {
	provider, ok := s.providers[providerCode]
	if !ok {
		return "", ErrProviderNotConfigured
	}

	state, _, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	nonce, _, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	// 43 unreserved characters, which is a valid PKCE code_verifier.
	verifier, _, err := newOpaqueToken()
	if err != nil {
		return "", err
	}

	err = s.store.CreateOAuthState(ctx, OAuthState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		Provider:     providerCode,
		RedirectTo:   redirectTo,
		ExpiresAt:    s.now().Add(oauthStateTTL),
	})
	if err != nil {
		return "", err
	}

	return provider.AuthCodeURL(state, nonce, verifier), nil
}

// CompleteProviderSignIn finishes the browser flow and returns the session
// along with wherever the caller asked to be sent afterwards.
func (s *Service) CompleteProviderSignIn(ctx context.Context, state, code string, p Platform) (Session, *string, error) {
	if state == "" || code == "" {
		return Session{}, nil, ErrOAuthStateInvalid
	}

	// Reading deletes it, so a captured callback URL cannot be replayed.
	st, err := s.store.ConsumeOAuthState(ctx, state)
	if err != nil {
		return Session{}, nil, err
	}

	provider, ok := s.providers[st.Provider]
	if !ok {
		return Session{}, nil, ErrProviderNotConfigured
	}

	claims, err := provider.Exchange(ctx, code, st.CodeVerifier, st.Nonce)
	if err != nil {
		return Session{}, nil, err
	}

	session, err := s.signInWithProvider(ctx, st.Provider, claims, p)
	if err != nil {
		return Session{}, nil, err
	}
	return session, st.RedirectTo, nil
}
