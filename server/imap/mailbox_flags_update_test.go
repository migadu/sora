package imap

import (
	"slices"
	"testing"

	"github.com/migadu/go-imap"
)

func TestMailboxFlagsWithNewKeywords(t *testing.T) {
	announced := buildDisplayFlags([]string{"$Old"})

	t.Run("nothing new", func(t *testing.T) {
		keywords := []string{
			"$old", "$junk", // case-insensitive identity (RFC 9051 §2.3.2)
			"Кириллица", "", // never shown, so never announced
		}
		if got := mailboxFlagsWithNewKeywords(announced, keywords); got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})

	t.Run("new keywords extend the announced list", func(t *testing.T) {
		got := mailboxFlagsWithNewKeywords(announced, []string{"$New", "$Old", "$new", "$Other"})
		for _, f := range announced {
			if !slices.Contains(got, f) {
				t.Errorf("%v dropped %s", got, f)
			}
		}
		for _, f := range []imap.Flag{"$New", "$Other"} {
			if !slices.Contains(got, f) {
				t.Errorf("%v lacks %s", got, f)
			}
		}
		if slices.Contains(got, "$new") {
			t.Errorf("%v lists a second case variant of $New", got)
		}
		if len(got) != len(announced)+2 {
			t.Errorf("got %d flags %v, want %d", len(got), got, len(announced)+2)
		}
	})
}
