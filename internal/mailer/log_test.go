package mailer_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jabbar-hafizh/go-api-starter/internal/mailer"
)

// The log mailer exists so local development can read a verification link
// without a mail provider. It has to make the token easy to find.
func TestLogMailerWritesTheToken(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	require.NoError(t, mailer.NewLog().SendEmailVerification(
		t.Context(), "person@example.com", "the-token"))

	out := buf.String()
	require.Contains(t, out, "person@example.com")
	require.Contains(t, out, "the-token")
	// Warn, not info, so it stands out in local output and is hard to enable
	// anywhere else by accident.
	require.Contains(t, out, "level=WARN")
}
