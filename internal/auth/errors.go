package auth

import (
	"net/http"

	"github.com/jabbar-hafizh/go-api-starter/internal/httperr"
)

// Error is a domain error that knows how it should look over HTTP. It
// satisfies httperr.StatusError without either package importing the other.
type Error struct {
	status  int
	code    string
	message string
}

func (e *Error) Error() string   { return e.message }
func (e *Error) HTTPStatus() int { return e.status }
func (e *Error) Code() string    { return e.code }

// Codes are a public contract. Clients branch on them, so once released a code
// never changes.
var (
	ErrEmailTaken = &Error{
		http.StatusConflict, "ERR_AUTH_EMAIL_TAKEN", "email already registered",
	}
	// ErrInvalidCredentials is returned whether the email is unknown or the
	// password is wrong. Splitting them turns login into a user enumeration
	// oracle.
	ErrInvalidCredentials = &Error{
		http.StatusUnauthorized, "ERR_AUTH_INVALID_CREDENTIALS", "invalid email or password",
	}
	ErrEmailNotVerified = &Error{
		http.StatusForbidden, "ERR_AUTH_EMAIL_NOT_VERIFIED", "email is not verified",
	}
	ErrTokenNotUsable = &Error{
		http.StatusGone, "ERR_AUTH_TOKEN_NOT_USABLE", "token is expired or already used",
	}
	ErrUserNotFound = &Error{
		http.StatusNotFound, "ERR_AUTH_USER_NOT_FOUND", "user not found",
	}
	// ErrRefreshInvalid covers unknown, expired, revoked and already spent.
	// One answer for all four: a client that can tell them apart can probe for
	// valid tokens, and the action is the same in every case, sign in again.
	// Reuse is reported in the logs, where it can actually be acted on.
	ErrIdentityNotFound = &Error{
		http.StatusNotFound, "ERR_AUTH_IDENTITY_NOT_FOUND", "identity not found",
	}
	ErrProviderEmailUnverified = &Error{
		http.StatusForbidden, "ERR_AUTH_PROVIDER_EMAIL_UNVERIFIED",
		"the provider has not verified this email address",
	}
	ErrProviderClaimsIncomplete = &Error{
		http.StatusBadGateway, "ERR_AUTH_PROVIDER_CLAIMS_INCOMPLETE",
		"the provider did not return an identity and an email",
	}
	// ErrLinkNeedsVerifiedEmail closes the takeover where someone registers
	// with an address they do not own and waits to inherit the real owner's
	// provider sign-in.
	ErrLinkNeedsVerifiedEmail = &Error{
		http.StatusConflict, "ERR_AUTH_LINK_NEEDS_VERIFIED_EMAIL",
		"sign in with your password and verify this address before linking",
	}
	ErrIdentityAlreadyLinked = &Error{
		http.StatusConflict, "ERR_AUTH_IDENTITY_ALREADY_LINKED",
		"this provider account is already linked to another user",
	}
	// ErrLastAuthMethod stops an account from losing its only way in.
	ErrLastAuthMethod = &Error{
		http.StatusConflict, "ERR_AUTH_LAST_METHOD",
		"cannot remove the only remaining way to sign in",
	}
	ErrProviderTokenInvalid = &Error{
		http.StatusUnauthorized, "ERR_AUTH_PROVIDER_TOKEN_INVALID",
		"the provider token is not valid",
	}
	ErrProviderNotConfigured = &Error{
		http.StatusNotImplemented, "ERR_AUTH_PROVIDER_NOT_CONFIGURED",
		"this provider is not configured on this server",
	}
	ErrOAuthStateInvalid = &Error{
		http.StatusBadRequest, "ERR_AUTH_OAUTH_STATE_INVALID",
		"the sign-in attempt expired or was already used",
	}
	// ErrTooManyAttempts is keyed per email rather than per address, so
	// rotating IPs does not buy more guesses at one account.
	ErrTooManyAttempts = &Error{
		http.StatusTooManyRequests, "ERR_AUTH_TOO_MANY_ATTEMPTS",
		"too many sign-in attempts, try again later",
	}
	ErrRefreshInvalid = &Error{
		http.StatusUnauthorized, "ERR_AUTH_REFRESH_INVALID", "refresh token is not usable",
	}
)

// ValidationError reports every field problem at once so the client does not
// have to fix them one round trip at a time.
type ValidationError struct {
	details []httperr.Detail
}

func (e *ValidationError) Error() string   { return "validation failed" }
func (e *ValidationError) HTTPStatus() int { return http.StatusUnprocessableEntity }
func (e *ValidationError) Code() string    { return "ERR_VALIDATION_FAILED" }

// Details satisfies httperr.DetailProvider.
func (e *ValidationError) Details() []httperr.Detail { return e.details }

type validator struct {
	details []httperr.Detail
}

func (v *validator) add(field, message string) {
	v.details = append(v.details, httperr.Detail{Field: field, Message: message})
}

// err returns nil when nothing failed, so callers can return it directly.
func (v *validator) err() error {
	if len(v.details) == 0 {
		return nil
	}
	return &ValidationError{details: v.details}
}
