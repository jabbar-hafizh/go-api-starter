package auth

import (
	"context"
	"fmt"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// googleIssuer is the only issuer accepted. Discovery reads the signing keys
// from here and go-oidc keeps them fresh, which is the part hand-rolled
// verifications get wrong: someone pins a certificate and login dies the day
// Google rotates it.
const googleIssuer = "https://accounts.google.com"

// Google is the Google-specific half of the flow: issuer, scopes and how its
// claims map onto ProviderClaims. The flow itself lives in oidc.go and is
// shared with every other provider.
type Google struct {
	oauth     *oauth2.Config
	verifier  *oidc.IDTokenVerifier
	audiences []string
}

// NewGoogle performs OIDC discovery, so it talks to the network and belongs in
// startup rather than in a request.
func NewGoogle(ctx context.Context, clientID, clientSecret, redirectURL string, audiences []string) (*Google, error) {
	provider, err := oidc.NewProvider(ctx, googleIssuer)
	if err != nil {
		return nil, fmt.Errorf("google oidc discovery: %w", err)
	}

	if len(audiences) == 0 {
		audiences = []string{clientID}
	}

	return &Google{
		oauth: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		// The audience check is skipped here and done in checkAudience, because
		// a native client's token carries the web client id while the browser
		// flow carries the same one: one allowlist covers every platform.
		verifier:  provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
		audiences: audiences,
	}, nil
}

// Code is the provider key stored in auth_identities.
func (g *Google) Code() string { return "google" }

// AuthCodeURL builds the redirect. PKCE is applied even though this is a
// confidential client: it costs one parameter and closes authorization code
// interception.
func (g *Google) AuthCodeURL(state, nonce, codeVerifier string) string {
	return g.oauth.AuthCodeURL(state,
		oauth2.S256ChallengeOption(codeVerifier),
		oidc.Nonce(nonce),
	)
}

// Exchange completes the browser flow. The nonce is checked here because the
// server issued it, which is what makes it meaningful.
func (g *Google) Exchange(ctx context.Context, code, codeVerifier, nonce string) (ProviderClaims, error) {
	tok, err := g.oauth.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return ProviderClaims{}, fmt.Errorf("exchange google code: %w", err)
	}

	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return ProviderClaims{}, ErrProviderClaimsIncomplete
	}

	idToken, err := g.verify(ctx, raw)
	if err != nil {
		return ProviderClaims{}, err
	}
	if idToken.Nonce != nonce {
		return ProviderClaims{}, ErrOAuthStateInvalid
	}
	return g.claims(idToken)
}

// VerifyIDToken accepts a token a native client got from the Google SDK.
//
// There is no nonce check here: the client would be supplying both sides of it,
// which proves nothing. What holds instead is the signature, the issuer, the
// audience allowlist and a short expiry. Clients wanting the stronger guarantee
// use the browser flow, where the server issues the nonce.
func (g *Google) VerifyIDToken(ctx context.Context, raw string) (ProviderClaims, error) {
	idToken, err := g.verify(ctx, raw)
	if err != nil {
		return ProviderClaims{}, err
	}
	return g.claims(idToken)
}

func (g *Google) verify(ctx context.Context, raw string) (*oidc.IDToken, error) {
	idToken, err := g.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, ErrProviderTokenInvalid
	}
	if !g.audienceAllowed(idToken.Audience) {
		// Without this, an ID token Google issued for some other application
		// would sign its holder in here.
		return nil, ErrProviderTokenInvalid
	}
	return idToken, nil
}

func (g *Google) audienceAllowed(audience []string) bool {
	for _, aud := range audience {
		if slices.Contains(g.audiences, aud) {
			return true
		}
	}
	return false
}

func (g *Google) claims(idToken *oidc.IDToken) (ProviderClaims, error) {
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&c); err != nil {
		return ProviderClaims{}, ErrProviderClaimsIncomplete
	}

	// Google's sub is stable for the lifetime of the account, so it is the
	// identity. The email is not: a Workspace admin can change it.
	return ProviderClaims{
		Subject:       idToken.Subject,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
	}, nil
}
