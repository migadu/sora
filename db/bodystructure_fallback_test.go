package db

import (
	"testing"

	"github.com/emersion/go-imap/v2"
)

// TestDeserializeBodyStructureFallbackLineCount pins the line count on the
// fallback structure served when a stored body_structure blob is unusable.
//
// The fallback calls itself text/plain, and body-fld-lines is mandatory for a
// text part (RFC 9051 body-type-text). Without it the FETCH response carries
// ("text" "plain" NIL NIL NIL "7bit" 1234 NIL NIL NIL NIL), which clients reject
// outright -- one unreadable blob then costs every message in the response, not
// just its own.
func TestDeserializeBodyStructureFallbackLineCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty blob", nil},
		{"corrupt gob", []byte("this is not gob-encoded data")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bs := deserializeBodyStructure(tc.data, 1234, 1, 2, imap.UID(3), "hash")
			if bs == nil {
				t.Fatal("deserializeBodyStructure() = nil")
			}
			sp, ok := (*bs).(*imap.BodyStructureSinglePart)
			if !ok {
				t.Fatalf("deserializeBodyStructure() = %T, want *imap.BodyStructureSinglePart", *bs)
			}
			if sp.Type != "text" || sp.Subtype != "plain" {
				t.Errorf("got %v/%v, want text/plain", sp.Type, sp.Subtype)
			}
			if sp.Size != 1234 {
				t.Errorf("Size = %v, want 1234", sp.Size)
			}
			if sp.Text == nil {
				t.Error("Text = nil, want a line count")
			}
		})
	}
}
