package lmtp

import (
	"slices"
	"testing"

	"github.com/migadu/sora/server/sieveengine"
)

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
