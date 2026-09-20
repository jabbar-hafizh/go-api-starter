package mailer

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	netmail "net/mail"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestSender(t *testing.T) *SMTP {
	t.Helper()

	s, err := NewSMTP(SMTPConfig{
		Host:     "smtp.example.com",
		Port:     587,
		Username: "user",
		Password: "pass",
		From:     "noreply@example.com",
		FromName: "Example",
		BaseURL:  "http://localhost:3000",
		LinkTTL:  24 * time.Hour,
	})
	require.NoError(t, err)
	return s
}

// rendered is a message decoded the way a mail client would read it. The wire
// format is quoted-printable, so "=" arrives as "=3D" and long lines are soft
// wrapped; asserting on the raw bytes would be asserting on the encoding.
type rendered struct {
	headers string
	text    string
	html    string
}

func (r rendered) all() string { return r.headers + r.text + r.html }

func render(t *testing.T, s *SMTP, email, token string) rendered {
	t.Helper()

	msg, err := s.buildVerification(email, token)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = msg.WriteTo(&buf)
	require.NoError(t, err)

	parsed, err := netmail.ReadMessage(&buf)
	require.NoError(t, err)

	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(mediaType, "multipart/"),
		"both a text and an HTML part must be present")

	out := rendered{headers: headerString(parsed)}
	reader := multipart.NewReader(parsed.Body, params["boundary"])

	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)

		body, err := io.ReadAll(quotedprintable.NewReader(part))
		require.NoError(t, err)

		switch {
		case strings.HasPrefix(part.Header.Get("Content-Type"), "text/plain"):
			out.text = string(body)
		case strings.HasPrefix(part.Header.Get("Content-Type"), "text/html"):
			out.html = string(body)
		}
	}

	require.NotEmpty(t, out.text, "a client that cannot render HTML needs the link too")
	require.NotEmpty(t, out.html)
	return out
}

func headerString(m *netmail.Message) string {
	var b strings.Builder
	for key, values := range m.Header {
		for _, v := range values {
			b.WriteString(key + ": " + v + "\n")
		}
	}
	return b.String()
}

func TestVerificationMessage(t *testing.T) {
	t.Parallel()

	out := render(t, newTestSender(t), "person@example.com", "plain-token")

	require.Contains(t, out.headers, "person@example.com")
	require.Contains(t, out.headers, "Confirm your email")
	require.Contains(t, out.headers, "noreply@example.com")

	const link = "http://localhost:3000/verify-email?token=plain-token"
	require.Contains(t, out.text, link)
	require.Contains(t, out.html, link)
	require.Contains(t, out.text, "24 hours")
}

// Verification tokens are base64url, which can contain characters that change
// meaning in a query string. Without escaping, a token would silently arrive
// truncated or altered.
func TestTokenIsEscapedInTheLink(t *testing.T) {
	t.Parallel()

	out := render(t, newTestSender(t), "person@example.com", "a+b/c=d&e?f")

	require.Contains(t, out.text, "token=a%2Bb%2Fc%3Dd%26e%3Ff")
	require.NotContains(t, out.text, "token=a+b/c=d&e?f")
}

// The link points at the front end, never at this API. A mail scanner fetching
// every URL in a message would burn a single-use token before the recipient
// ever clicked it.
func TestLinkPointsAtTheFrontEnd(t *testing.T) {
	t.Parallel()

	out := render(t, newTestSender(t), "person@example.com", "tok")

	require.Contains(t, out.text, "localhost:3000/verify-email")
	require.NotContains(t, out.all(), "/v1/auth/verify-email")
}

func TestBaseURLTrailingSlashDoesNotDouble(t *testing.T) {
	t.Parallel()

	s, err := NewSMTP(SMTPConfig{
		Host: "smtp.example.com", Port: 587,
		Username: "u", Password: "p",
		From: "noreply@example.com", FromName: "Example",
		BaseURL: "http://localhost:3000/", LinkTTL: time.Hour,
	})
	require.NoError(t, err)

	out := render(t, s, "person@example.com", "tok")
	require.Contains(t, out.text, "http://localhost:3000/verify-email")
	require.NotContains(t, out.text, "localhost:3000//verify-email")
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()

	tests := map[time.Duration]string{
		30 * time.Minute:   "30 minutes",
		2 * time.Hour:      "2 hours",
		24 * time.Hour:     "24 hours",
		72 * time.Hour:     "3 days",
		7 * 24 * time.Hour: "7 days",
	}

	for d, want := range tests {
		t.Run(want, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, want, humanDuration(d))
		})
	}
}

// The HTML body is rendered with html/template, so a token is escaped rather
// than able to close the attribute it sits in.
func TestHTMLIsEscaped(t *testing.T) {
	t.Parallel()

	out := render(t, newTestSender(t), "person@example.com", `"><script>alert(1)</script>`)

	require.NotContains(t, out.html, "<script>alert(1)</script>",
		"the token must arrive escaped, not as markup")
	require.Contains(t, out.html, "%22%3E%3Cscript%3E")
}
