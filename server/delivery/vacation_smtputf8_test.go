package delivery

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

type vacationSMTPMessage struct {
	from, to string
	utf8     bool
	body     []byte
}

type vacationSMTPBackend struct{ messages chan vacationSMTPMessage }

func (b *vacationSMTPBackend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &vacationSMTPSession{backend: b}, nil
}

type vacationSMTPSession struct {
	backend *vacationSMTPBackend
	message vacationSMTPMessage
}

func (s *vacationSMTPSession) Mail(_ context.Context, from string, opts *smtp.MailOptions) error {
	s.message.from = from
	s.message.utf8 = opts != nil && opts.UTF8
	return nil
}

func (s *vacationSMTPSession) Rcpt(_ context.Context, to string, _ *smtp.RcptOptions) error {
	s.message.to = to
	return nil
}

func (s *vacationSMTPSession) Data(_ context.Context, r io.Reader) error {
	var err error
	s.message.body, err = io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.messages <- s.message
	header, _, _ := bytes.Cut(s.message.body, []byte("\r\n\r\n"))
	if !s.message.utf8 && !server.IsASCII(string(header)) {
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 9}, Message: "UTF-8 headers require SMTPUTF8"}
	}
	return nil
}

func (s *vacationSMTPSession) Reset()        { s.message = vacationSMTPMessage{} }
func (s *vacationSMTPSession) Logout() error { return nil }

// A Unicode script owner must still negotiate SMTPUTF8 when :from selects an
// ASCII alias: the generated attribution header needs it even though the envelope does not.
func TestVacationUnicodeOwnerWithASCIIFromAlias(t *testing.T) {
	const owner = "josé@example.com"
	const alias = "away@example.com"
	const sender = "sender@example.net"
	for _, tc := range []struct {
		name, body string
		isMime     bool
	}{
		{name: "plain text", body: "I am away."},
		{name: "MIME", body: "Content-Type: text/plain; charset=utf-8\r\nX-Redirected-By: forged@example.net\r\n\r\nI am away.", isMime: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &vacationSMTPBackend{messages: make(chan vacationSMTPMessage, 1)}
			smtpServer := smtp.NewServer(backend)
			smtpServer.Domain = "relay.example.com"
			smtpServer.EnableSMTPUTF8 = true
			smtpServer.ReadTimeout = 5 * time.Second
			smtpServer.WriteTimeout = 5 * time.Second
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { smtpServer.Close() })
			go smtpServer.Serve(listener)
			h := &StandardVacationHandler{
				Hostname:     "mail.example.com",
				RelayHandler: &SMTPRelayHandler{SMTPHost: listener.Addr().String()},
				IsOwnedAddress: func(_ context.Context, _ int64, address string) (bool, error) {
					return address == owner || address == alias, nil
				},
			}
			original := makeMessage(map[string]string{
				"From":                     sender,
				"To":                       alias,
				helpers.RedirectedByHeader: "spoofed@example.net",
			})
			reply := sieveengine.VacationReply{From: alias, Body: tc.body, IsMime: tc.isMime}
			if err := h.HandleVacationResponse(context.Background(), 1, reply, vacAddr(t, sender), vacAddr(t, owner), original); err != nil {
				t.Fatalf("relay rejected vacation reply: %v", err)
			}
			var received vacationSMTPMessage
			select {
			case received = <-backend.messages:
			case <-time.After(5 * time.Second):
				t.Fatal("relay did not receive the vacation reply")
			}
			if !received.utf8 {
				t.Error("MAIL FROM did not negotiate SMTPUTF8 for the Unicode attribution header")
			}
			if received.from != "" || received.to != sender {
				t.Errorf("reply envelope = %q -> %q, want <> -> %q", received.from, received.to, sender)
			}
			entity, err := message.Read(bytes.NewReader(received.body))
			if err != nil {
				t.Fatal(err)
			}
			if got := entity.Header.Get("From"); got != alias {
				t.Errorf("From = %q, want owned alias %q", got, alias)
			}
			if values := entity.Header.Values(helpers.RedirectedByHeader); len(values) != 1 || values[0] != owner {
				t.Errorf("attribution values = %q, want exactly [%q]", values, owner)
			}
		})
	}
}
