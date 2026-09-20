package auth

import "context"

// SignInWithProviderToken is the native path: the app already got an ID token
// from the provider SDK and posts it here.
//
// It goes through exactly the same linking rules as the browser flow, because
// those rules are about who owns an address, not about how the token arrived.
func (s *Service) SignInWithProviderToken(ctx context.Context, providerCode, rawIDToken string, p Platform) (Session, error) {
	claims, err := s.verifyProviderToken(ctx, providerCode, rawIDToken)
	if err != nil {
		return Session{}, err
	}
	return s.signInWithProvider(ctx, providerCode, claims, p)
}

func (s *Service) verifyProviderToken(ctx context.Context, providerCode, rawIDToken string) (ProviderClaims, error) {
	if rawIDToken == "" {
		return ProviderClaims{}, ErrProviderTokenInvalid
	}

	provider, ok := s.providers[providerCode]
	if !ok {
		return ProviderClaims{}, ErrProviderNotConfigured
	}
	return provider.VerifyIDToken(ctx, rawIDToken)
}
