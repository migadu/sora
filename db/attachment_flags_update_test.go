package db

import (
	"slices"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestNormalizeAttachmentKeywordUpdate(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		resulting, requested []imap.Flag
		want                 []imap.Flag
	}{
		{"unrelated flags", []imap.Flag{"Work", "$hasattachment", imap.FlagSeen}, []imap.Flag{imap.FlagSeen}, []imap.Flag{"Work", "$hasattachment", imap.FlagSeen}},
		{"replace negative", []imap.Flag{"Work", "$HasNoAttachment", "$HASATTACHMENT"}, []imap.Flag{"$HASATTACHMENT"}, []imap.Flag{"Work", "$HASATTACHMENT"}},
		{"replace positive", []imap.Flag{"$HasAttachment", "$HASNOATTACHMENT", "Work"}, []imap.Flag{"$HASNOATTACHMENT"}, []imap.Flag{"$HASNOATTACHMENT", "Work"}},
		{"conflicting pair", []imap.Flag{imap.FlagFlagged, "$HASATTACHMENT", "$hasnoattachment", "Work"}, []imap.Flag{"$HASATTACHMENT", "$hasnoattachment"}, []imap.Flag{imap.FlagFlagged, "Work"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original, requested := slices.Clone(tc.resulting), slices.Clone(tc.requested)
			got := NormalizeAttachmentKeywordUpdate(tc.resulting, tc.requested)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if !slices.Equal(tc.resulting, original) || !slices.Equal(tc.requested, requested) {
				t.Fatal("normalization mutated caller flags")
			}
		})
	}
}
