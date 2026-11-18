package db

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
)

func TestBuildEnvelopeObsoleteSourceRoutes(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "from only"
		h := mail.HeaderFromMap(map[string][]string{"From": {"<@route:user@domain>"}})
		if explicit {
			name = "explicit sender and reply-to"
			h.Set("Sender", "Sender <@first,@second:sender@domain>")
			h.Set("Reply-To", "Replies <@route:replies@domain>")
		}
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(helpers.ExtractRecipients(h.Header))
			if err != nil {
				t.Fatal(err)
			}
			env, err := BuildEnvelope(&Message{RecipientsJSON: raw})
			if err != nil {
				t.Fatal(err)
			}
			wantFrom := []imap.Address{{Mailbox: "user", Host: "domain"}}
			if !slices.Equal(env.From, wantFrom) {
				t.Errorf("From = %+v, want %+v", env.From, wantFrom)
			}
			wantSender := wantFrom
			if explicit {
				wantSender = []imap.Address{{Name: "Sender", Mailbox: "sender", Host: "domain"}}
				wantReplyTo := []imap.Address{{Name: "Replies", Mailbox: "replies", Host: "domain"}}
				if !slices.Equal(env.ReplyTo, wantReplyTo) {
					t.Errorf("ReplyTo = %+v, want %+v", env.ReplyTo, wantReplyTo)
				}
			}
			if !slices.Equal(env.Sender, wantSender) {
				t.Errorf("Sender = %+v, want %+v", env.Sender, wantSender)
			}
		})
	}
}
