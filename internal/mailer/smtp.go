package mailer

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/wneessen/go-mail"
)

//go:embed templates/*
var templates embed.FS

var (
	htmlTemplates = template.Must(template.ParseFS(templates, "templates/*.html"))
	textTemplates = texttemplate.Must(texttemplate.ParseFS(templates, "templates/*.txt"))
)

// SMTPConfig is what the sender needs. A struct rather than seven positional
// strings, so two of them cannot be swapped without the compiler noticing.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
	// BaseURL is where the link in the email points. It is the front end, not
	// this API: see SendEmailVerification.
	BaseURL string
	// LinkTTL is quoted in the message so the reader knows how long they have.
	LinkTTL time.Duration
}

// SMTP sends through any SMTP server, which keeps this provider neutral. The
// same code talks to Mailpit locally, Gmail, Resend or SES.
type SMTP struct {
	client *mail.Client
	cfg    SMTPConfig
}

// NewSMTP builds the sender. TLS is mandatory: an SMTP session in the clear
// carries the credentials and the message with it.
func NewSMTP(cfg SMTPConfig) (*SMTP, error) {
	client, err := mail.NewClient(cfg.Host,
		mail.WithPort(cfg.Port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(cfg.Username),
		mail.WithPassword(cfg.Password),
		mail.WithTLSPolicy(mail.TLSMandatory),
		mail.WithTimeout(15*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("build smtp client: %w", err)
	}
	return &SMTP{client: client, cfg: cfg}, nil
}

// SendEmailVerification sends the confirmation message.
//
// The link points at the front end rather than at this API on purpose. Mail
// scanners, antivirus and link previews routinely fetch every URL in a message
// before a person ever clicks it. Our tokens are single use, so a link that
// consumed one on GET would be burned by a scanner and the recipient would be
// told it was already used. A front end page is safe to prefetch: it only
// loads, and the POST happens when someone actually acts.
func (s *SMTP) SendEmailVerification(ctx context.Context, email, token string) error {
	msg, err := s.buildVerification(email, token)
	if err != nil {
		return err
	}

	if err := s.client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("send verification email: %w", err)
	}
	return nil
}

// buildVerification is separate from sending so the message can be rendered
// and asserted on without an SMTP server.
func (s *SMTP) buildVerification(email, token string) (*mail.Msg, error) {
	data := struct {
		Link      string
		ExpiresIn string
	}{
		Link: strings.TrimRight(s.cfg.BaseURL, "/") +
			"/verify-email?token=" + url.QueryEscape(token),
		ExpiresIn: humanDuration(s.cfg.LinkTTL),
	}

	msg := mail.NewMsg()
	if err := msg.FromFormat(s.cfg.FromName, s.cfg.From); err != nil {
		return nil, fmt.Errorf("set from: %w", err)
	}
	if err := msg.To(email); err != nil {
		return nil, fmt.Errorf("set recipient: %w", err)
	}
	msg.Subject("Confirm your email")

	// Plain text first and HTML as the alternative, which is the order clients
	// expect: they pick the richest part they can render.
	if err := msg.SetBodyTextTemplate(textTemplates.Lookup("verify_email.txt"), data); err != nil {
		return nil, fmt.Errorf("render text body: %w", err)
	}
	if err := msg.AddAlternativeHTMLTemplate(htmlTemplates.Lookup("verify_email.html"), data); err != nil {
		return nil, fmt.Errorf("render html body: %w", err)
	}
	return msg, nil
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "24 hours"
		}
		return fmt.Sprintf("%d days", days)
	case d >= time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}
