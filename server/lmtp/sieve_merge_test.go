package lmtp

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/sora/server/sieveengine"
)

// Vacation is independent of the delivery action. A user script that leaves the
// default filing in place must also leave its auto-reply in place, unless the user
// supplies their own reply. Evaluate actual scripts to cover implicit and explicit
// keep as the LMTP delivery path receives them from the Sieve executor.
func TestKeepDefaultActionPreservesDefaultVacation(t *testing.T) {
	for _, action := range []struct {
		name, script string
		want         sieveengine.Action
	}{
		{"fileinto", `fileinto "Archive";`, sieveengine.ActionFileInto},
		{"redirect", `redirect "other@example.net";`, sieveengine.ActionRedirect},
		{"discard", `discard;`, sieveengine.ActionDiscard},
	} {
		for _, user := range []struct {
			name, script string
			ownReply     bool
		}{
			{"implicit keep", `addflag "usertag";`, false},
			{"explicit keep", `addflag "usertag"; keep;`, false},
			{"user vacation", `addflag "usertag"; vacation :subject "User away" "User auto-reply";`, true},
		} {
			t.Run(action.name+"/"+user.name, func(t *testing.T) {
				evaluate := func(script string) sieveengine.Result {
					t.Helper()
					compiled, err := sieveengine.CompileScript(`require ["vacation", "fileinto", "imap4flags", "editheader"]; `+script, append(sieveengine.EffectiveExtensions(nil), "editheader"))
					if err != nil {
						t.Fatal(err)
					}
					result, err := compiled.NewExecutor(1, nil, nil, 0, 0, 0).Evaluate(context.Background(), sieveengine.Context{
						EnvelopeFrom: "sender@example.com",
						EnvelopeTo:   "recipient@example.com",
						Header: map[string][]string{
							"From": {"sender@example.com"}, "To": {"recipient@example.com"},
							"Subject": {"A message"},
						},
						Message: []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: A message\r\n\r\nHello.\r\n"),
					})
					if err != nil {
						t.Fatal(err)
					}
					return result
				}
				defaultResult := evaluate(action.script + ` addflag "defaulttag"; addheader "X-Default" "default"; vacation :subject "System away" "System auto-reply";`)
				userResult := evaluate(user.script + ` addheader "X-User" "user";`)
				if defaultResult.Action != action.want || defaultResult.Vacation == nil {
					t.Fatalf("default script did not produce its action and reply: %+v", defaultResult)
				}
				if userResult.Action != sieveengine.ActionKeep || (userResult.Vacation != nil) != user.ownReply {
					t.Fatalf("user script did not produce the expected keep: %+v", userResult)
				}
				merged := keepDefaultAction(defaultResult, userResult)
				wantReply := defaultResult.Vacation
				if user.ownReply {
					wantReply = userResult.Vacation
				}
				if merged.Vacation != wantReply {
					t.Errorf("vacation = %+v, want %+v", merged.Vacation, wantReply)
				}
				if merged.Action != defaultResult.Action || merged.Mailbox != defaultResult.Mailbox || merged.RedirectTo != defaultResult.RedirectTo {
					t.Errorf("user keep changed the default action: %+v", merged)
				}
				if want := []string{"defaulttag", "usertag"}; !slices.Equal(merged.Flags, want) {
					t.Errorf("flags = %v, want %v", merged.Flags, want)
				}
				if want := slices.Concat(defaultResult.HeaderEdits, userResult.HeaderEdits); !slices.Equal(merged.HeaderEdits, want) {
					t.Errorf("header edits = %v, want default edits followed by user edits: %v", merged.HeaderEdits, want)
				}
			})
		}
	}
}

// TestKeepDefaultActionKeepsTheUserScriptsWork: when the user script ends in the
// implicit keep, the default script's action stands, but the user's flags, header
// edits and vacation reply must survive. Only the reply used to be carried over, so
// an Auto-Submitted header the user added never reached the vacation suppression.
func TestKeepDefaultActionKeepsTheUserScriptsWork(t *testing.T) {
	defaultEdit := sieveengine.HeaderEdit{Action: "add", FieldName: "X-Default", Value: "1"}
	userEdit := sieveengine.HeaderEdit{Action: "add", FieldName: "Auto-Submitted", Value: "auto-generated"}
	defaultResult := sieveengine.Result{
		Action:      sieveengine.ActionFileInto,
		Mailbox:     "Junk",
		Flags:       []string{"\\Seen", "Spam"},
		HeaderEdits: []sieveengine.HeaderEdit{defaultEdit},
	}
	reply := &sieveengine.VacationReply{Subject: "Away"}
	userResult := sieveengine.Result{
		Action:      sieveengine.ActionKeep,
		Flags:       []string{"\\seen", "usertag"},
		HeaderEdits: []sieveengine.HeaderEdit{userEdit},
		Vacation:    reply,
	}

	merged := keepDefaultAction(defaultResult, userResult)

	if merged.Action != sieveengine.ActionFileInto || merged.Mailbox != "Junk" {
		t.Errorf("action %s mailbox %q, want the default's fileinto Junk", merged.Action, merged.Mailbox)
	}
	if want := []string{"\\Seen", "Spam", "usertag"}; !slices.Equal(merged.Flags, want) {
		t.Errorf("flags %v, want %v", merged.Flags, want)
	}
	if want := []sieveengine.HeaderEdit{defaultEdit, userEdit}; !slices.Equal(merged.HeaderEdits, want) {
		t.Errorf("header edits %v, want the default's, then the user's: %v", merged.HeaderEdits, want)
	}
	if merged.Vacation != reply {
		t.Errorf("the user's vacation reply was not carried over")
	}
	if len(defaultResult.HeaderEdits) != 1 || len(defaultResult.Flags) != 2 {
		t.Errorf("the default script's result was modified: %+v", defaultResult)
	}
}
