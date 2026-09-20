package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/auth"
	"github.com/jabbar-hafizh/go-api-starter/internal/openapi"
)

func newHandler(t *testing.T) (*auth.Handler, *fakeStore, *fakeMailer) {
	t.Helper()

	svc, store, mail := newService(t)
	return auth.NewHandler(svc, "http://localhost:3000", false), store, mail
}

// signedIn registers, verifies and logs in, returning a refresh token.
func signedInVia(t *testing.T, platform auth.Platform) (*auth.Handler, string) {
	t.Helper()

	h, _, mail := newHandler(t)
	ctx := t.Context()

	body := openapi.RegisterUserJSONRequestBody{Email: "jabbar@example.com", Password: goodPassword}
	_, err := h.RegisterUser(ctx, openapi.RegisterUserRequestObject{Body: &body})
	require.NoError(t, err)

	verify := openapi.VerifyEmailJSONRequestBody{Token: mail.lastToken}
	_, err = h.VerifyEmail(ctx, openapi.VerifyEmailRequestObject{Body: &verify})
	require.NoError(t, err)

	p := openapi.LoginUserParamsXClientPlatform(platform)
	login := openapi.LoginUserJSONRequestBody{Email: "jabbar@example.com", Password: goodPassword}
	resp, err := h.LoginUser(ctx, openapi.LoginUserRequestObject{
		Params: openapi.LoginUserParams{XClientPlatform: &p},
		Body:   &login,
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	require.NoError(t, resp.VisitLoginUserResponse(rec))
	return h, tokenFrom(t, rec, platform == auth.PlatformWeb)
}

func tokenFrom(t *testing.T, rec *httptest.ResponseRecorder, fromCookie bool) string {
	t.Helper()

	if fromCookie {
		for _, c := range rec.Result().Cookies() {
			if c.Name == "refresh_token" {
				return c.Value
			}
		}
		t.Fatal("expected a refresh cookie")
	}

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, decodeJSON(rec, &body))
	require.NotEmpty(t, body.RefreshToken)
	return body.RefreshToken
}

// A browser that omits the platform header must still get a fresh cookie back.
//
// Deciding the response from the header instead meant the new token went into
// the body, the browser kept presenting the spent cookie, and the very next
// refresh tripped reuse detection and revoked the whole chain. That happened
// for real before this was fixed.
func TestRefreshFromCookieAnswersWithACookie(t *testing.T) {
	t.Parallel()

	h, token := signedInVia(t, auth.PlatformWeb)
	cookie := openapi.RefreshCookie(token)

	for i := range 3 {
		resp, err := h.RefreshSession(t.Context(), openapi.RefreshSessionRequestObject{
			// No X-Client-Platform, which is the whole point.
			Params: openapi.RefreshSessionParams{RefreshToken: &cookie},
		})
		require.NoError(t, err, "refresh %d must succeed", i+1)

		rec := httptest.NewRecorder()
		require.NoError(t, resp.VisitRefreshSessionResponse(rec))

		var body map[string]any
		require.NoError(t, decodeJSON(rec, &body))
		require.NotContains(t, body, "refresh_token",
			"a browser must never receive it where a script could read it")

		next := ""
		for _, c := range rec.Result().Cookies() {
			if c.Name == "refresh_token" {
				next = c.Value
			}
		}
		require.NotEmpty(t, next, "a rotated cookie must come back")
		require.NotEqual(t, string(cookie), next, "and it must be a new one")
		cookie = openapi.RefreshCookie(next)
	}
}

// The mirror image: a token sent in the body comes back in the body, and no
// cookie is set on a client that has nowhere to put one.
func TestRefreshFromBodyAnswersInTheBody(t *testing.T) {
	t.Parallel()

	h, token := signedInVia(t, auth.PlatformIOS)

	for range 3 {
		body := openapi.RefreshSessionJSONRequestBody{RefreshToken: &token}
		resp, err := h.RefreshSession(t.Context(), openapi.RefreshSessionRequestObject{Body: &body})
		require.NoError(t, err)

		rec := httptest.NewRecorder()
		require.NoError(t, resp.VisitRefreshSessionResponse(rec))
		require.Empty(t, rec.Result().Cookies(), "a native client gets no cookie")

		var out struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, decodeJSON(rec, &out))
		require.NotEmpty(t, out.RefreshToken)
		require.NotEqual(t, token, out.RefreshToken)
		token = out.RefreshToken
	}
}

// A cookie means a browser, so the session gets the shorter web lifetime even
// when the header says otherwise.
func TestACookieMeansWebWhateverTheHeaderSays(t *testing.T) {
	t.Parallel()

	h, token := signedInVia(t, auth.PlatformWeb)
	cookie := openapi.RefreshCookie(token)
	claimed := openapi.RefreshSessionParamsXClientPlatform("ios")

	resp, err := h.RefreshSession(t.Context(), openapi.RefreshSessionRequestObject{
		Params: openapi.RefreshSessionParams{RefreshToken: &cookie, XClientPlatform: &claimed},
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	require.NoError(t, resp.VisitRefreshSessionResponse(rec))

	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh_token" {
			require.Equal(t, int(7*24*time.Hour/time.Second), c.MaxAge)
			return
		}
	}
	t.Fatal("expected a refresh cookie")
}

func TestLogoutClearsTheCookie(t *testing.T) {
	t.Parallel()

	h, token := signedInVia(t, auth.PlatformWeb)
	cookie := openapi.RefreshCookie(token)

	resp, err := h.Logout(t.Context(), openapi.LogoutRequestObject{
		Params: openapi.LogoutParams{RefreshToken: &cookie},
	})
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	require.NoError(t, resp.VisitLogoutResponse(rec))
	require.Equal(t, http.StatusNoContent, rec.Code)

	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh_token" {
			require.Negative(t, c.MaxAge, "the cookie must be expired, not left in place")
			return
		}
	}
	t.Fatal("expected the cookie to be cleared")
}

func decodeJSON(rec *httptest.ResponseRecorder, into any) error {
	if rec.Body.Len() == 0 {
		return nil
	}
	return json.Unmarshal(rec.Body.Bytes(), into)
}
