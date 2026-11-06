package db

import (
	"fmt"
	"slices"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
)

func TestWithAttachmentKeyword(t *testing.T) {
	withPDF := &imap.BodyStructureMultiPart{
		Subtype: "mixed",
		Children: []imap.BodyStructure{
			&imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"},
			&imap.BodyStructureSinglePart{
				Type: "application", Subtype: "pdf",
				Extended: &imap.BodyStructureSinglePartExt{
					Disposition: &imap.BodyStructureDisposition{Value: "attachment"},
				},
			},
		},
	}
	plain := &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	has, hasNo := helpers.KeywordHasAttachment, helpers.KeywordHasNoAttachment

	tests := []struct {
		name     string
		flags    []imap.Flag
		bs       imap.BodyStructure
		override bool
		want     []imap.Flag
	}{
		{"delivery adds the keyword", []imap.Flag{imap.FlagSeen}, withPDF, true, []imap.Flag{imap.FlagSeen, has}},
		{"delivery replaces a Sieve-set one", []imap.Flag{"$HasAttachment", "Work"}, plain, true, []imap.Flag{"Work", hasNo}},
		{"APPEND fills in when the client set neither", nil, plain, false, []imap.Flag{hasNo}},
		{"APPEND keeps the client's own", []imap.Flag{"$HasNoAttachment"}, withPDF, false, []imap.Flag{"$HasNoAttachment"}},
		{"undecided leaves one keyword alone", []imap.Flag{has}, nil, true, []imap.Flag{has}},
		{"undecided still drops both", []imap.Flag{has, hasNo, "Work"}, nil, false, []imap.Flag{"Work"}},
		{"decided drops both on APPEND too", []imap.Flag{has, hasNo}, plain, false, []imap.Flag{hasNo}},
	}
	for _, tt := range tests {
		in := slices.Clone(tt.flags)
		got := WithAttachmentKeyword(tt.flags, tt.bs, tt.override)
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
		if !slices.Equal(tt.flags, in) {
			t.Errorf("%s: input changed to %v", tt.name, tt.flags)
		}
	}
}

func TestWithAttachmentKeyword_KeywordCap(t *testing.T) {
	plain := &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	full := make([]imap.Flag, 0, MaxCustomKeywordsPerMessage)
	for i := 0; i < MaxCustomKeywordsPerMessage; i++ {
		full = append(full, imap.Flag(fmt.Sprintf("kw%d", i)))
	}
	// A full message gets no keyword: it must not push out one the client set.
	if got := WithAttachmentKeyword(full, plain, true); len(got) != MaxCustomKeywordsPerMessage || slices.Contains(got, helpers.KeywordHasNoAttachment) {
		t.Errorf("full message: got %d flags, want the client's %d unchanged", len(got), MaxCustomKeywordsPerMessage)
	}
	// Replacing a Sieve-set keyword frees its slot.
	full[0] = helpers.KeywordHasAttachment
	if got := WithAttachmentKeyword(full, plain, true); !slices.Contains(got, helpers.KeywordHasNoAttachment) || len(got) != MaxCustomKeywordsPerMessage {
		t.Errorf("full message with a Sieve-set keyword: got %v", got)
	}
}

func TestHasAttachmentsFromKeywords(t *testing.T) {
	tests := []struct {
		kw   []string
		want *bool
	}{
		{[]string{"Work", "$hasattachment"}, ptr(true)},
		{[]string{"$HasNoAttachment"}, ptr(false)},
		{[]string{"Work"}, nil},
		{nil, nil},
		{[]string{"$hasattachment", "$hasnoattachment"}, nil},
	}
	for _, tt := range tests {
		got := hasAttachmentsFromKeywords(tt.kw)
		if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
			t.Errorf("hasAttachmentsFromKeywords(%v) = %v, want %v", tt.kw, deref(got), deref(tt.want))
		}
	}
}

func ptr(b bool) *bool { return &b }

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}
