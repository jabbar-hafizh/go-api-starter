// Package mailer delivers transactional email.
package mailer

import (
	"context"
	"log/slog"
)

// Log writes the email to the log instead of sending it. It exists so local
// development has a way to read a verification link without a mail provider,
// and so the interface is already in place when a real sender is added.
type Log struct{}

// NewLog returns a mailer that logs instead of sending.
func NewLog() Log { return Log{} }

// SendEmailVerification logs the token at warn level so it is hard to miss in
// local output, and hard to enable by accident anywhere else.
func (Log) SendEmailVerification(ctx context.Context, email, token string) error {
	slog.WarnContext(ctx, "email not sent, logging instead",
		slog.String("kind", "email_verification"),
		slog.String("to", email),
		slog.String("token", token),
	)
	return nil
}
